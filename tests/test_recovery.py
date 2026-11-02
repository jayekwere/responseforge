from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from app.common import DEMO_IDENTITIES, DomainError, Identity, Store
from app.recovery import Recovery, demo, inspect_snapshot

NOW = "2026-11-01T12:00:00Z"


def setup(tmp_path: Path) -> tuple[Recovery, Store, dict[str, Any]]:
    source = Store(tmp_path / "source.db")
    with source.tx() as db:
        Store.save(db, "alder", "synthetic", "fixture", {"value": 1})
        Store.audit(db, DEMO_IDENTITIES["demo-analyst"], "fixture", {"value": 1}, NOW)
    recovery = Recovery(Store(tmp_path / "control.db"), tmp_path / "backups", b"k" * 32)
    envelope = recovery.backup(DEMO_IDENTITIES["demo-verifier"], source.path, "snapshot", NOW)
    return recovery, source, envelope


def test_real_recovery_and_point_in_time_data_loss(tmp_path: Path) -> None:
    result = demo(tmp_path)
    assert result["source_untouched"] and result["approval_gate_verified"]
    assert result["result"]["logical_records"] == "verified_exact_snapshot"
    assert result["fixture_recovery_point"]["lost_fixture_updates"] == 1
    assert result["result"]["measured_restore_seconds"] >= 0


def test_tampered_manifest_backup_and_cross_tenant_rejected(tmp_path: Path) -> None:
    recovery, source, envelope = setup(tmp_path)
    actor = DEMO_IDENTITIES["demo-analyst"]
    changed = copy.deepcopy(envelope)
    changed["manifest"]["tables"]["objects"]["count"] = 0
    with pytest.raises(DomainError):
        recovery.plan(actor, changed, "restore", NOW)
    with pytest.raises(DomainError):
        recovery.plan(DEMO_IDENTITIES["demo-other-tenant"], envelope, "restore", NOW)
    with pytest.raises(DomainError):
        recovery.plan(actor, envelope, "../source", NOW)
    backup = recovery.root / envelope["manifest"]["backup"]
    with backup.open("ab") as file:
        file.write(b"tampered")
    with pytest.raises(DomainError):
        recovery.plan(actor, envelope, "restore", NOW)
    assert source.path.exists()


def test_independent_approval_digest_expiry_replay_and_no_overwrite(tmp_path: Path) -> None:
    recovery, source, envelope = setup(tmp_path)
    analyst, approver, operator = (
        DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"]
    )
    plan = recovery.plan(analyst, envelope, "restore", NOW)
    same = Identity(tenant="alder", subject=analyst.subject, roles=["approver"])
    with pytest.raises(DomainError):
        recovery.approve(same, plan["id"], plan["plan_sha256"], NOW)
    with pytest.raises(DomainError):
        recovery.approve(approver, plan["id"], "a" * 64, NOW)
    with pytest.raises(DomainError):
        recovery.approve(approver, plan["id"], plan["plan_sha256"], "2026-11-02T00:00:00Z")
    recovery.approve(approver, plan["id"], plan["plan_sha256"], NOW)
    with pytest.raises(DomainError):
        recovery.restore(operator, plan["id"], "b" * 64, NOW)
    self_operator = approver.model_copy(update={"roles": ["operator"]})
    with pytest.raises(DomainError):
        recovery.restore(self_operator, plan["id"], plan["plan_sha256"], NOW)
    with pytest.raises(DomainError):
        recovery.restore(operator, plan["id"], plan["plan_sha256"], "2026-11-02T00:00:00Z")
    namespace = recovery.root / analyst.tenant
    namespace.mkdir()
    existing = namespace / "restore.sqlite"
    existing.write_bytes(b"existing destination")
    with pytest.raises(FileExistsError):
        recovery.restore(operator, plan["id"], plan["plan_sha256"], NOW)
    assert existing.read_bytes() == b"existing destination"
    existing.unlink()
    result = recovery.restore(operator, plan["id"], plan["plan_sha256"], NOW)
    assert result == recovery.restore(operator, plan["id"], plan["plan_sha256"], NOW)
    assert source.path.exists()


def test_tenant_isolated_database_and_schema_required(tmp_path: Path) -> None:
    recovery, source, _ = setup(tmp_path)
    with source.tx() as db:
        Store.save(db, "birch", "private", "fixture", {"private": True})
    with pytest.raises(DomainError, match="tenant-isolated"):
        recovery.backup(DEMO_IDENTITIES["demo-verifier"], source.path, "other", NOW)
    assert not (recovery.root / "other.sqlite").exists()
    with pytest.raises(ValueError):
        Recovery(recovery.store, tmp_path / "short", b"short")
    with source.tx() as db:
        db.execute("CREATE TABLE unexpected(value TEXT)")
    with pytest.raises(DomainError, match="schema"):
        inspect_snapshot(source.path, "alder")
