from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, field_validator

from app.common import Contract, DomainError, Identity, Store, clock, digest, require, timestamp
from app.connectors import Connector, Registry, Target, connect, physical
from app.playbooks import Execution

POLICY = {
    "version": 1,
    "actions": ["disable", "restore"],
    "approval": "three-independent-subjects",
    "expiry_minutes": 15,
    "external_retry": "read-only-reconciliation",
}


class CloudRequest(Contract):
    target: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    action: Literal["disable", "restore"]
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: str
    restore_of: str | None = Field(default=None, pattern=r"^cloud-[a-f0-9]{32}$")

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value: str) -> str:
        timestamp(value)
        return value


class CloudOrchestrator:
    """Persist intent before dispatch and reconcile ambiguous outcomes without another write."""

    def __init__(
        self,
        store: Store,
        registry: Registry,
        factory: Callable[[Target], Connector] = connect,
        clock_fn: Callable[[], str] = clock,
    ):
        self.store, self.registry, self.factory = store, registry, factory
        self.clock = clock_fn
        with store.tx() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS cloud_dispatch (tenant TEXT, plan TEXT, idem TEXT, request TEXT NOT NULL, operator TEXT NOT NULL, PRIMARY KEY(tenant,plan), UNIQUE(tenant,idem));
            CREATE TABLE IF NOT EXISTS cloud_locks (target TEXT PRIMARY KEY, tenant TEXT NOT NULL, plan TEXT NOT NULL);
            """)

    def plan(self, actor: Identity, request: CloudRequest, now: str) -> dict[str, Any]:
        require(actor, "analyst")
        if (
            not timestamp(now) - timedelta(hours=1)
            <= timestamp(request.observed_at)
            <= timestamp(now)
        ):
            raise DomainError("Cloud event is stale or future", 422)
        if (request.action == "restore") != bool(request.restore_of):
            raise DomainError(
                "Restore requires a previous verified disable; disable accepts no restore reference",
                422,
            )
        target = self.registry.get(actor.tenant, request.target)
        before = self.factory(target).read()
        desired = request.action == "disable"
        if before.get("disabled") is not (not desired):
            raise DomainError("Cloud target is already in the requested state")
        plan: dict[str, Any] = {
            **request.model_dump(),
            "id": f"cloud-{uuid.uuid4().hex}",
            "tenant": actor.tenant,
            "target_sha256": digest(target.model_dump()),
            "physical_target": physical(target),
            "before": before,
            "before_sha256": digest(before),
            "desired_disabled": desired,
            "policy_sha256": digest(POLICY),
            "requested_by": actor.subject,
            "created_at": now,
            "expires_at": (timestamp(now) + timedelta(minutes=15)).isoformat(),
        }
        plan["plan_sha256"] = digest(plan)
        plan["status"] = "awaiting_approval"
        with self.store.tx() as db:
            if request.restore_of:
                previous = self.store.get(db, actor.tenant, request.restore_of, "cloud-plan")
                if (
                    previous.get("status") != "verified"
                    or previous.get("action") != "disable"
                    or previous.get("physical_target") != physical(target)
                    or previous["before"].get("disabled") is not False
                    or previous.get("target_sha256") != plan["target_sha256"]
                    or previous.get("restore_plan")
                ):
                    raise DomainError("Previous disable is not eligible for this restore", 403)
            self.store.save(db, actor.tenant, plan["id"], "cloud-plan", plan)
            self.store.audit(
                db,
                actor,
                "cloud_planned",
                {"id": plan["id"], "plan_sha256": plan["plan_sha256"]},
                now,
            )
        return plan

    def approve(self, actor: Identity, key: str, hashed: str, now: str) -> dict[str, Any]:
        require(actor, "approver")
        with self.store.tx() as db:
            plan = self.store.get(db, actor.tenant, key, "cloud-plan")
            if actor.subject == plan["requested_by"]:
                raise DomainError("Independent approver required", 403)
            self.validate(plan, hashed, now, "awaiting_approval")
            plan.update(status="approved", approved_by=actor.subject, approved_at=now)
            self.store.save(db, actor.tenant, key, "cloud-plan", plan)
            self.store.audit(db, actor, "cloud_approved", {"id": key, "plan_sha256": hashed}, now)
        return plan

    def validate(self, plan: dict[str, Any], hashed: str, now: str, status: str) -> None:
        target = self.registry.get(plan["tenant"], plan["target"])
        if (
            plan["status"] != status
            or plan["plan_sha256"] != hashed
            or timestamp(now) >= timestamp(plan["expires_at"])
            or plan["policy_sha256"] != digest(POLICY)
            or plan["target_sha256"] != digest(target.model_dump())
        ):
            raise DomainError("Cloud plan state, expiry, configuration or digest invalid")

    def execute(self, actor: Identity, key: str, execution: Execution, now: str) -> dict[str, Any]:
        require(actor, "operator")
        request_hash = digest(
            {"plan": key, "digest": execution.plan_sha256, "operator": actor.subject}
        )
        with self.store.tx() as db:
            prior = db.execute(
                "SELECT * FROM cloud_dispatch WHERE tenant=? AND (plan=? OR idem=?)",
                (actor.tenant, key, execution.idempotency_key),
            ).fetchone()
            if prior:
                if prior["request"] != request_hash or prior["idem"] != execution.idempotency_key:
                    raise DomainError("Cloud plan or idempotency key already reserved")
                return self.store.get(db, actor.tenant, key, "cloud-plan")
            plan = self.store.get(db, actor.tenant, key, "cloud-plan")
            if actor.subject in {plan["requested_by"], plan.get("approved_by")}:
                raise DomainError("Independent operator required", 403)
            self.validate(plan, execution.plan_sha256, now, "approved")
            if plan.get("restore_of"):
                previous = self.store.get(db, actor.tenant, plan["restore_of"], "cloud-plan")
                if previous.get("status") != "verified" or previous.get("restore_plan"):
                    raise DomainError("Restore is already reserved or no longer eligible")
                previous["restore_plan"] = key
                self.store.save(db, actor.tenant, previous["id"], "cloud-plan", previous)
            try:
                db.execute(
                    "INSERT INTO cloud_locks VALUES (?,?,?)",
                    (plan["physical_target"], actor.tenant, key),
                )
                db.execute(
                    "INSERT INTO cloud_dispatch VALUES (?,?,?,?,?)",
                    (actor.tenant, key, execution.idempotency_key, request_hash, actor.subject),
                )
            except sqlite3.IntegrityError:
                raise DomainError("Cloud target is locked by an unresolved dispatch") from None
            plan.update(status="reserved", operator=actor.subject, reserved_at=now)
            self.store.save(db, actor.tenant, key, "cloud-plan", plan)
            self.store.audit(
                db,
                actor,
                "cloud_dispatch_reserved",
                {"id": key, "plan_sha256": plan["plan_sha256"]},
                now,
            )
        target = self.registry.get(actor.tenant, plan["target"])
        connector = self.factory(target)
        try:
            before = connector.read()
            if digest(before) != plan["before_sha256"] or timestamp(self.clock()) >= timestamp(
                plan["expires_at"]
            ):
                raise DomainError("Cloud target changed since approval")
        except Exception:
            return self.record(actor, key, "precondition_failed", now, {}, unlock=True)
        with self.store.tx() as db:
            current = self.store.get(db, actor.tenant, key, "cloud-plan")
            if current["status"] != "reserved":
                raise DomainError("Dispatch state changed")
            if timestamp(now) >= timestamp(current["expires_at"]):
                raise DomainError("Cloud plan expired before dispatch")
            current.update(status="write_started", write_started_at=self.clock())
            self.store.save(db, actor.tenant, key, "cloud-plan", current)
            self.store.audit(db, actor, "cloud_write_started", {"id": key}, now)
        try:
            connector.set_disabled(plan["desired_disabled"])
            after = connector.read()
            if after.get("disabled") is not plan["desired_disabled"]:
                raise DomainError("Native readback has not reached the requested state")
        except Exception:
            return self.record(
                actor, key, "uncertain", now, {"verification": "read-only-reconciliation-required"}
            )
        return self.record(
            actor,
            key,
            "verified",
            now,
            {
                "after": after,
                "after_sha256": digest(after),
                "verification": "provider-acknowledged-and-native-readback",
            },
            unlock=True,
        )

    def record(
        self,
        actor: Identity,
        key: str,
        status: str,
        now: str,
        details: dict[str, Any],
        *,
        unlock: bool = False,
    ) -> dict[str, Any]:
        with self.store.tx() as db:
            plan = self.store.get(db, actor.tenant, key, "cloud-plan")
            if plan["status"] in {"verified", "precondition_failed"}:
                return plan
            plan.update(status=status, updated_at=now, **details)
            self.store.save(db, actor.tenant, key, "cloud-plan", plan)
            if unlock:
                db.execute(
                    "DELETE FROM cloud_locks WHERE target=? AND tenant=? AND plan=?",
                    (plan["physical_target"], actor.tenant, key),
                )
            self.store.audit(db, actor, "cloud_" + status, {"id": key, **details}, now)
        return plan

    def reconcile(self, actor: Identity, key: str, now: str) -> dict[str, Any]:
        require(actor, "operator")
        with self.store.tx() as db:
            plan = self.store.get(db, actor.tenant, key, "cloud-plan")
            if actor.subject in {plan["requested_by"], plan.get("approved_by")}:
                raise DomainError("Independent operator required", 403)
            if plan["status"] == "verified":
                return plan
            if plan["status"] == "reserved":
                if timestamp(now) < timestamp(plan["reserved_at"]) + timedelta(minutes=5):
                    raise DomainError("Dispatch reservation is still active")
                plan.update(
                    status="precondition_failed",
                    updated_at=now,
                    verification="expired-reservation-never-dispatched",
                )
                self.store.save(db, actor.tenant, key, "cloud-plan", plan)
                db.execute(
                    "DELETE FROM cloud_locks WHERE target=? AND tenant=? AND plan=?",
                    (plan["physical_target"], actor.tenant, key),
                )
                self.store.audit(db, actor, "cloud_reservation_expired", {"id": key}, now)
                return plan
            if plan["status"] not in {"reserved", "write_started", "uncertain"}:
                raise DomainError("Only dispatched uncertain writes can be reconciled")
        if timestamp(now) < timestamp(plan["write_started_at"]) + timedelta(minutes=5):
            raise DomainError("Dispatch cooldown is active; reconcile after five minutes")
        target = self.registry.get(actor.tenant, plan["target"])
        if digest(target.model_dump()) != plan["target_sha256"]:
            raise DomainError("Target configuration changed; reconciliation rejected")
        after = self.factory(target).read()
        if after.get("disabled") is not plan["desired_disabled"]:
            return self.record(
                actor,
                key,
                "uncertain",
                now,
                {"verification": "native-state-does-not-yet-confirm-outcome"},
            )
        return self.record(
            actor,
            key,
            "verified",
            now,
            {
                "after": after,
                "after_sha256": digest(after),
                "verification": "reconciled-native-state-after-ambiguous-dispatch",
            },
            unlock=True,
        )
