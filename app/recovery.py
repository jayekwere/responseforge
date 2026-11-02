from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.common import DomainError, Identity, Store, canonical, clock, digest, require, timestamp

TABLES = {
    "objects": ["tenant", "id", "kind", "payload"],
    "audit": ["seq", "tenant", "payload", "previous", "hash"],
    "idempotency": ["tenant", "key", "request", "response"],
}


def file_digest(path: Path) -> str:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise DomainError("Recovery lab backup exceeds 16 MiB", 422)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_snapshot(path: Path, tenant: str) -> dict[str, Any]:
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise DomainError("Snapshot database integrity failed", 422)
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1"
        ).fetchone():
            raise DomainError("Unexpected executable database schema", 422)
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != set(TABLES):
            raise DomainError("Unexpected database schema", 422)
        result: dict[str, Any] = {}
        for table, columns in TABLES.items():
            actual = [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
            if actual != columns:
                raise DomainError("Unexpected recovery table contract", 422)
            rows = db.execute(
                f"SELECT * FROM {table} ORDER BY {','.join(columns)} LIMIT 5001"
            ).fetchall()
            if len(rows) > 5000:
                raise DomainError("Recovery table exceeds local capacity", 422)
            tenant_index = columns.index("tenant")
            if any(row[tenant_index] != tenant for row in rows):
                raise DomainError("Recovery lab requires a tenant-isolated source", 403)
            result[table] = {"count": len(rows), "sha256": digest(rows)}
        return result


class Recovery:
    def __init__(self, store: Store, root: Path, key: bytes):
        if len(key) < 32:
            raise ValueError("Recovery signing key must contain at least 32 bytes")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise ValueError("Recovery root must not be a symlink")
        root.chmod(0o700)
        self.store, self.root, self.key = store, root, key

    def _mac(self, manifest: dict[str, Any]) -> str:
        return hmac.new(
            self.key,
            b"responseforge-recovery-v1\x00" + canonical(manifest).encode(),
            hashlib.sha256,
        ).hexdigest()

    def backup(self, actor: Identity, source: Path, key: str, now: str) -> dict[str, Any]:
        require(actor, "operator")
        if not key.isalnum() or len(key) > 64 or source.is_symlink():
            raise DomainError("Invalid recovery backup reference", 422)
        source = source.resolve(strict=True)
        if source.stat().st_size > 16 * 1024 * 1024:
            raise DomainError("Recovery source exceeds 16 MiB", 422)
        target = self.root / f"{key}.sqlite"
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        try:
            with (
                sqlite3.connect(f"file:{source}?mode=ro", uri=True) as origin,
                sqlite3.connect(target) as destination,
            ):
                origin.backup(destination)
            tables = inspect_snapshot(target, actor.tenant)
            manifest = {
                "format": "responseforge-recovery-v1",
                "tenant": actor.tenant,
                "backup": target.name,
                "sha256": file_digest(target),
                "created_at": now,
                "tables": tables,
                "confidentiality": "not_encrypted_store_in_private_lab_directory",
            }
            envelope = {"manifest": manifest, "hmac_sha256": self._mac(manifest)}
            metadata = self.root / f"{key}.json"
            with os.fdopen(
                os.open(metadata, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w"
            ) as file:
                file.write(canonical(envelope))
            with self.store.tx() as db:
                Store.audit(
                    db,
                    actor,
                    "recovery.backup",
                    {"backup_sha256": manifest["sha256"], "manifest_sha256": digest(manifest)},
                    now,
                )
            return envelope
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def plan(
        self, actor: Identity, envelope: dict[str, Any], destination_id: str, now: str
    ) -> dict[str, Any]:
        require(actor, "analyst")
        self.verify(actor, envelope)
        if not destination_id.isalnum() or len(destination_id) > 64:
            raise DomainError("Invalid isolated restore destination", 422)
        plan: dict[str, Any] = {
            "tenant": actor.tenant,
            "envelope": envelope,
            "destination_id": destination_id,
            "requested_by": actor.subject,
            "expires_at": (timestamp(now) + timedelta(minutes=15)).isoformat(),
            "status": "pending",
        }
        plan["id"] = "recovery-" + digest(plan)[:24]
        plan["plan_sha256"] = digest(plan)
        with self.store.tx() as db:
            if db.execute(
                "SELECT 1 FROM objects WHERE tenant=? AND id=? AND kind='recovery-plan'",
                (actor.tenant, plan["id"]),
            ).fetchone():
                raise DomainError("Recovery plan already exists")
            Store.save(db, actor.tenant, plan["id"], "recovery-plan", plan)
            Store.audit(
                db,
                actor,
                "recovery.plan",
                {"id": plan["id"], "plan_sha256": plan["plan_sha256"]},
                now,
            )
        return plan

    def verify(self, actor: Identity, envelope: dict[str, Any]) -> Path:
        if (
            set(envelope) != {"manifest", "hmac_sha256"}
            or not isinstance(envelope["manifest"], dict)
            or not isinstance(envelope["hmac_sha256"], str)
        ):
            raise DomainError("Invalid backup envelope", 422)
        manifest = envelope["manifest"]
        if (
            set(manifest)
            != {"format", "tenant", "backup", "sha256", "created_at", "tables", "confidentiality"}
            or manifest["format"] != "responseforge-recovery-v1"
            or not hmac.compare_digest(self._mac(manifest), envelope["hmac_sha256"])
        ):
            raise DomainError("Backup authentication failed", 422)
        if manifest["tenant"] != actor.tenant:
            raise DomainError("Backup tenant mismatch", 403)
        name = manifest["backup"]
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".sqlite"):
            raise DomainError("Backup path rejected", 422)
        source = self.root / name
        if (
            source.is_symlink()
            or file_digest(source) != manifest["sha256"]
            or inspect_snapshot(source, actor.tenant) != manifest["tables"]
        ):
            raise DomainError("Backup bytes or logical records changed", 422)
        return source

    def approve(self, actor: Identity, key: str, expected: str, now: str) -> dict[str, Any]:
        require(actor, "approver")
        with self.store.tx() as db:
            plan = Store.get(db, actor.tenant, key, "recovery-plan")
            if actor.subject == plan["requested_by"]:
                raise DomainError("Independent recovery approval required", 403)
            if (
                plan["status"] != "pending"
                or plan["plan_sha256"] != expected
                or timestamp(plan["expires_at"]) <= timestamp(now)
            ):
                raise DomainError("Recovery plan changed, expired or already decided")
            plan.update(status="approved", approved_by=actor.subject)
            Store.save(db, actor.tenant, key, "recovery-plan", plan)
            Store.audit(db, actor, "recovery.approve", {"id": key, "plan_sha256": expected}, now)
            return plan

    def restore(self, actor: Identity, key: str, expected: str, now: str) -> dict[str, Any]:
        require(actor, "operator")
        started = time.monotonic()
        with self.store.tx() as db:
            plan = Store.get(db, actor.tenant, key, "recovery-plan")
            if plan["plan_sha256"] != expected:
                raise DomainError("Recovery digest mismatch")
            if plan["status"] == "succeeded":
                return dict(plan["result"])
            if plan["status"] != "approved" or timestamp(plan["expires_at"]) <= timestamp(now):
                raise DomainError("A current independent approval is required")
            if actor.subject in {plan["requested_by"], plan["approved_by"]}:
                raise DomainError(
                    "Restore executor must be independent of requester and approver", 403
                )
            source = self.verify(actor, plan["envelope"])
            tenant_root = self.root / actor.tenant
            tenant_root.mkdir(mode=0o700, exist_ok=True)
            if tenant_root.is_symlink():
                raise DomainError("Restore namespace rejected", 422)
            target = tenant_root / f"{plan['destination_id']}.sqlite"
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            try:
                with (
                    sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True) as origin,
                    sqlite3.connect(target) as restored,
                ):
                    origin.backup(restored)
                tables = inspect_snapshot(target, actor.tenant)
                if tables != plan["envelope"]["manifest"]["tables"]:
                    raise DomainError(
                        "Restored logical records do not match the approved snapshot", 500
                    )
                checkpoint = Store(target).evidence(actor)["checkpoint"]
                result = {
                    "status": "succeeded",
                    "destination": str(target.name),
                    "logical_records": "verified_exact_snapshot",
                    "tables": tables,
                    "restored_audit_checkpoint": checkpoint,
                    "measured_restore_seconds": round(time.monotonic() - started, 6),
                    "scope": "isolated_synthetic_sqlite_restore_no_production_recovery_claim",
                }
                plan.update(status="succeeded", result=result)
                Store.save(db, actor.tenant, key, "recovery-plan", plan)
                Store.audit(db, actor, "recovery.restore", {"id": key, "result": result}, now)
                return result
            except BaseException:
                target.unlink(missing_ok=True)
                raise


def demo(directory: Path) -> dict[str, Any]:
    from app.common import DEMO_IDENTITIES

    source = Store(directory / "source.sqlite")
    coordinator = Store(directory / "coordinator.sqlite")
    analyst, approver, operator = (
        DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"]
    )
    now = clock()
    with source.tx() as db:
        Store.save(
            db,
            analyst.tenant,
            "synthetic-record",
            "recovery-fixture",
            {"version": 1, "synthetic": True},
        )
        Store.audit(db, analyst, "fixture.write", {"version": 1}, now)
    recovery = Recovery(coordinator, directory / "backups", secrets.token_bytes(32))
    envelope = recovery.backup(operator, source.path, "snapshot001", now)
    with source.tx() as db:
        Store.save(
            db,
            analyst.tenant,
            "synthetic-record",
            "recovery-fixture",
            {"version": 2, "synthetic": True},
        )
        Store.audit(db, analyst, "fixture.write", {"version": 2}, now)
    plan = recovery.plan(analyst, envelope, "restored001", now)
    denied = False
    try:
        recovery.restore(operator, plan["id"], plan["plan_sha256"], now)
    except DomainError:
        denied = True
    assert denied
    recovery.approve(approver, plan["id"], plan["plan_sha256"], now)
    result = recovery.restore(operator, plan["id"], plan["plan_sha256"], now)
    assert result == recovery.restore(operator, plan["id"], plan["plan_sha256"], now)
    restored = Store(directory / "backups" / analyst.tenant / "restored001.sqlite")
    with restored.tx() as db:
        restored_record = Store.get(db, analyst.tenant, "synthetic-record", "recovery-fixture")
    with source.tx() as db:
        source_record = Store.get(db, analyst.tenant, "synthetic-record", "recovery-fixture")
    assert restored_record["version"] == 1 and source_record["version"] == 2
    return {
        "mode": "actual-isolated-sqlite-backup-and-restore",
        "result": result,
        "approval_gate_verified": denied,
        "idempotent_replay_verified": True,
        "source_untouched": True,
        "fixture_recovery_point": {
            "snapshot_version": 1,
            "latest_source_version": 2,
            "lost_fixture_updates": 1,
            "time_based_rpo": "not_measured",
        },
        "evidence": coordinator.evidence(analyst),
    }
