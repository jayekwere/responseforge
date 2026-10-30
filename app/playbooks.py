from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, field_validator

from app.common import Contract, DomainError, Identity, Store, canonical, digest, require, timestamp


class Event(Contract):
    id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    source: Literal["synthetic-edr", "authorized-import"]
    kind: Literal["malware-detected", "credential-anomaly"]
    resource: str = Field(pattern=r"^sim:[a-z0-9-]{1,128}$")
    severity: Literal["high", "critical"]
    observed_at: str
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value: str) -> str:
        timestamp(value)
        return value


class PlanRequest(Contract):
    event_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    playbook: Literal["contain-host", "disable-identity"]


class Execution(Contract):
    idempotency_key: str = Field(pattern=r"^[a-zA-Z0-9-]{8,128}$")
    plan_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


POLICY = {
    "contain-host": {"event": "malware-detected", "outcome": "isolated"},
    "disable-identity": {"event": "credential-anomaly", "outcome": "disabled"},
}


class Sandbox:
    """This connector only changes a tenant-scoped SQLite row in the same transaction."""

    @staticmethod
    def apply(store: Store, db: Any, tenant: str, resource: str, outcome: str) -> dict[str, Any]:
        if not resource.startswith("sim:") or outcome not in {"isolated", "disabled"}:
            raise DomainError("Sandbox policy rejected target", 403)
        current = store.get(db, tenant, resource, "resource")
        current.update(state=outcome, version=current["version"] + 1)
        store.save(db, tenant, resource, "resource", current)
        return store.get(db, tenant, resource, "resource")


class Orchestrator:
    def __init__(self, store: Store):
        self.store = store

    def ingest(self, identity: Identity, event: Event, now: str) -> dict[str, Any]:
        require(identity, "analyst")
        if (
            not timestamp(now) - timedelta(hours=24)
            <= timestamp(event.observed_at)
            <= timestamp(now)
        ):
            raise DomainError("Event is stale or future", 422)
        record = {**event.model_dump(), "event_sha256": digest(event.model_dump())}
        with self.store.tx() as db:
            exists = db.execute(
                "SELECT 1 FROM objects WHERE tenant=? AND id=? AND kind='event'",
                (identity.tenant, event.id),
            ).fetchone()
            if exists:
                old = self.store.get(db, identity.tenant, event.id, "event")
                if old["event_sha256"] != record["event_sha256"]:
                    raise DomainError("Event id conflict")
                return old
            # Provision only a synthetic resource in this explicit local sandbox.
            db.execute(
                "INSERT OR IGNORE INTO objects VALUES (?,?,?,?)",
                (
                    identity.tenant,
                    event.resource,
                    "resource",
                    canonical({"id": event.resource, "state": "active", "version": 0}),
                ),
            )
            self.store.save(db, identity.tenant, event.id, "event", record)
            self.store.audit(
                db,
                identity,
                "event_ingested",
                {"id": event.id, "event_sha256": record["event_sha256"]},
                now,
            )
            return record

    def plan(self, identity: Identity, request: PlanRequest, now: str) -> dict[str, Any]:
        require(identity, "analyst")
        with self.store.tx() as db:
            event = self.store.get(db, identity.tenant, request.event_id, "event")
            policy = POLICY[request.playbook]
            if event["kind"] != policy["event"]:
                raise DomainError("Playbook trigger does not match event", 403)
            resource = self.store.get(db, identity.tenant, event["resource"], "resource")
            if resource["state"] != "active":
                raise DomainError("Resource is already contained")
            plan = {
                "id": f"plan-{request.event_id}",
                "event_id": request.event_id,
                "event_sha256": event["event_sha256"],
                "tenant": identity.tenant,
                "resource": event["resource"],
                "resource_version": resource["version"],
                "playbook": request.playbook,
                "outcome": policy["outcome"],
                "policy_sha256": digest(POLICY),
                "requested_by": identity.subject,
                "created_at": now,
                "expires_at": (timestamp(now) + timedelta(minutes=30)).isoformat(),
            }
            plan["plan_sha256"] = digest(plan)
            key = str(plan["id"])
            if db.execute(
                "SELECT 1 FROM objects WHERE tenant=? AND id=? AND kind='plan'",
                (identity.tenant, key),
            ).fetchone():
                raise DomainError("Plan already exists")
            plan["status"] = "awaiting_approval"
            self.store.save(db, identity.tenant, key, "plan", plan)
            self.store.audit(
                db, identity, "planned", {"id": key, "plan_sha256": plan["plan_sha256"]}, now
            )
            return plan

    def approve(self, identity: Identity, key: str, plan_sha256: str, now: str) -> dict[str, Any]:
        require(identity, "approver")
        with self.store.tx() as db:
            plan = self.store.get(db, identity.tenant, key, "plan")
            if identity.subject == plan["requested_by"]:
                raise DomainError("Requester cannot approve", 403)
            if (
                plan["status"] != "awaiting_approval"
                or plan["plan_sha256"] != plan_sha256
                or timestamp(now) >= timestamp(plan["expires_at"])
            ):
                raise DomainError("Plan state, digest or expiry invalid")
            plan.update(status="approved", approved_by=identity.subject, approved_at=now)
            self.store.save(db, identity.tenant, key, "plan", plan)
            self.store.audit(db, identity, "approved", {"id": key, "plan_sha256": plan_sha256}, now)
            return plan

    def execute(
        self, identity: Identity, key: str, execution: Execution, now: str
    ) -> dict[str, Any]:
        require(identity, "operator")
        request_hash = digest(
            {"plan": key, "digest": execution.plan_sha256, "operator": identity.subject}
        )
        with self.store.tx() as db:
            prior = db.execute(
                "SELECT request,response FROM idempotency WHERE tenant=? AND key=?",
                (identity.tenant, execution.idempotency_key),
            ).fetchone()
            if prior:
                if prior["request"] != request_hash:
                    raise DomainError("Idempotency key reused for a different operation")
                import json

                return dict(json.loads(prior["response"]))
            plan = self.store.get(db, identity.tenant, key, "plan")
            if identity.subject in {plan["requested_by"], plan.get("approved_by")}:
                raise DomainError("Independent operator required", 403)
            if (
                plan["status"] != "approved"
                or plan["plan_sha256"] != execution.plan_sha256
                or timestamp(now) >= timestamp(plan["expires_at"])
            ):
                raise DomainError("Plan state, digest or expiry invalid")
            if (
                plan["policy_sha256"] != digest(POLICY)
                or POLICY[plan["playbook"]]["outcome"] != plan["outcome"]
            ):
                raise DomainError("Policy changed since approval", 403)
            event = self.store.get(db, identity.tenant, plan["event_id"], "event")
            if timestamp(now) - timestamp(event["observed_at"]) > timedelta(hours=24):
                raise DomainError("Event evidence expired", 403)
            resource = self.store.get(db, identity.tenant, plan["resource"], "resource")
            if resource["version"] != plan["resource_version"] or resource["state"] != "active":
                raise DomainError("Target changed after approval")
            Sandbox.apply(self.store, db, identity.tenant, plan["resource"], plan["outcome"])
            observed = self.store.get(db, identity.tenant, plan["resource"], "resource")
            if (
                observed["state"] != plan["outcome"]
                or observed["version"] != plan["resource_version"] + 1
            ):
                raise DomainError("Outcome verification failed; transaction rolled back", 500)
            plan.update(
                status="succeeded",
                executed_by=identity.subject,
                verified_outcome=observed,
                mode="local-simulation",
            )
            self.store.save(db, identity.tenant, key, "plan", plan)
            evidence_hash = self.store.audit(
                db,
                identity,
                "outcome_verified",
                {
                    "id": key,
                    "plan_sha256": execution.plan_sha256,
                    "observed": observed,
                    "mode": "local-simulation",
                },
                now,
            )
            response = {
                "status": "succeeded",
                "plan_id": key,
                "mode": "local-simulation",
                "outcome": observed,
                "evidence_sha256": evidence_hash,
            }
            db.execute(
                "INSERT INTO idempotency VALUES (?,?,?,?)",
                (identity.tenant, execution.idempotency_key, request_hash, canonical(response)),
            )
            return response
