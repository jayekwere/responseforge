from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Identity(Contract):
    tenant: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    subject: str = Field(min_length=1, max_length=128)
    roles: list[Literal["analyst", "approver", "verifier", "operator", "viewer"]]


class DomainError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timezone required")
    return parsed


def clock() -> str:
    return datetime.now(UTC).isoformat()


def require(identity: Identity, role: str) -> None:
    if role not in identity.roles:
        raise DomainError("Role not authorized", 403)


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.tx() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS objects (tenant TEXT, id TEXT, kind TEXT, payload TEXT NOT NULL, PRIMARY KEY(tenant,id,kind));
            CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS idempotency (tenant TEXT, key TEXT, request TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(tenant,key));
            """)
        path.chmod(0o600)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def get(db: sqlite3.Connection, tenant: str, key: str, kind: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT payload FROM objects WHERE tenant=? AND id=? AND kind=?", (tenant, key, kind)
        ).fetchone()
        if row is None:
            raise DomainError("Record not found", 404)
        return dict(json.loads(row["payload"]))

    @staticmethod
    def save(
        db: sqlite3.Connection, tenant: str, key: str, kind: str, value: dict[str, Any]
    ) -> None:
        db.execute(
            "INSERT INTO objects VALUES (?,?,?,?) ON CONFLICT(tenant,id,kind) DO UPDATE SET payload=excluded.payload",
            (tenant, key, kind, canonical(value)),
        )

    @staticmethod
    def audit(
        db: sqlite3.Connection, identity: Identity, action: str, record: dict[str, Any], now: str
    ) -> str:
        row = db.execute(
            "SELECT hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1", (identity.tenant,)
        ).fetchone()
        previous = str(row["hash"]) if row else "0" * 64
        payload = {
            "actor": identity.subject,
            "action": action,
            "at": now,
            "record": record,
            "tenant": identity.tenant,
        }
        hashed = digest({"previous": previous, "payload": payload})
        db.execute(
            "INSERT INTO audit(tenant,payload,previous,hash) VALUES (?,?,?,?)",
            (identity.tenant, canonical(payload), previous, hashed),
        )
        return hashed

    def evidence(self, identity: Identity) -> dict[str, Any]:
        with self.tx() as db:
            rows = db.execute(
                "SELECT seq,payload,previous,hash FROM audit WHERE tenant=? ORDER BY seq",
                (identity.tenant,),
            ).fetchall()
        previous = "0" * 64
        result = []
        for row in rows:
            payload = json.loads(row["payload"])
            if row["previous"] != previous or row["hash"] != digest(
                {"previous": previous, "payload": payload}
            ):
                raise DomainError("Audit integrity check failed", 500)
            previous = str(row["hash"])
            result.append(
                {
                    "seq": row["seq"],
                    "payload": payload,
                    "previous": row["previous"],
                    "hash": row["hash"],
                }
            )
        return {
            "tenant": identity.tenant,
            "events": result,
            "checkpoint": previous,
            "integrity": "verified_local_chain",
        }

    def listing(self, identity: Identity, kind: str) -> list[dict[str, Any]]:
        with self.tx() as db:
            rows = db.execute(
                "SELECT payload FROM objects WHERE tenant=? AND kind=? ORDER BY id",
                (identity.tenant, kind),
            ).fetchall()
            return [dict(json.loads(row["payload"])) for row in rows]


DEMO_IDENTITIES = {
    "demo-analyst": Identity(tenant="alder", subject="alex", roles=["analyst", "viewer"]),
    "demo-approver": Identity(tenant="alder", subject="blair", roles=["approver", "viewer"]),
    "demo-verifier": Identity(
        tenant="alder", subject="casey", roles=["verifier", "operator", "viewer"]
    ),
    "demo-other-tenant": Identity(
        tenant="birch",
        subject="drew",
        roles=["analyst", "approver", "operator", "verifier", "viewer"],
    ),
}


def authenticate(header: str, identities: dict[str, Identity]) -> Identity:
    if not header.startswith("Bearer "):
        raise DomainError("Bearer authentication required", 401)
    token = header[7:]
    for candidate, identity in identities.items():
        if secrets.compare_digest(token.encode(), candidate.encode()):
            return identity
    raise DomainError("Invalid credentials", 401)
