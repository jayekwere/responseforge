import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.cli import demo
from app.common import DEMO_IDENTITIES, DomainError, Identity, Store
from app.playbooks import POLICY, Event, Execution, Orchestrator, PlanRequest, Sandbox

NOW = "2026-10-30T12:00:00Z"
A, B, C = (DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"])


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "state.db")
    service = Orchestrator(store)
    event = Event.model_validate(json.loads(Path("samples/workflow.json").read_text()))
    return store, service, event


def approved(setup):
    _, service, event = setup
    service.ingest(A, event, NOW)
    plan = service.plan(A, PlanRequest(event_id=event.id, playbook="contain-host"), NOW)
    return service.approve(B, plan["id"], plan["plan_sha256"], NOW)


def execute(plan, key="response-key-001"):
    return Execution(idempotency_key=key, plan_sha256=plan["plan_sha256"])


def test_end_to_end_reproducible_and_explicitly_simulated():
    first = demo()
    assert first == demo()
    assert first["result"]["mode"] == "local-simulation"
    assert first["result"]["outcome"]["version"] == 1
    assert len(first["evidence"]["events"]) == 4


def test_concurrent_retries_execute_once_and_survive_restart(setup):
    store, service, _ = setup
    plan = approved(setup)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: service.execute(C, plan["id"], execute(plan), NOW), range(8))
        )
    assert all(r == results[0] for r in results)
    restarted = Orchestrator(Store(store.path))
    assert restarted.execute(C, plan["id"], execute(plan), NOW) == results[0]
    assert len(store.evidence(A)["events"]) == 4


def test_event_id_dedup_and_conflicting_replay(setup):
    store, service, event = setup
    assert service.ingest(A, event, NOW) == service.ingest(A, event, NOW)
    assert len(store.evidence(A)["events"]) == 1
    event.severity = "critical"
    with pytest.raises(DomainError):
        service.ingest(A, event, NOW)


@pytest.mark.parametrize("at", ["2026-01-01T00:00:00Z", "2026-10-31T00:00:00Z"])
def test_event_freshness(setup, at):
    _, service, event = setup
    event.observed_at = at
    with pytest.raises(DomainError):
        service.ingest(A, event, NOW)


def test_trigger_mismatch_unknown_commands_and_tenant_spoof_rejected(setup):
    _, service, event = setup
    service.ingest(A, event, NOW)
    with pytest.raises(DomainError):
        service.plan(A, PlanRequest(event_id=event.id, playbook="disable-identity"), NOW)
    for patch in [
        {"resource": "aws:real-resource"},
        {"tenant": "other"},
        {"kind": "run-shell"},
        {"observed_at": "2026-10-30"},
    ]:
        with pytest.raises(ValidationError):
            Event.model_validate({**event.model_dump(), **patch})


def test_separation_of_duties_even_with_combined_roles(setup):
    _, service, event = setup
    service.ingest(A, event, NOW)
    plan = service.plan(A, PlanRequest(event_id=event.id, playbook="contain-host"), NOW)
    same = Identity(tenant="alder", subject=A.subject, roles=["approver", "operator"])
    with pytest.raises(DomainError):
        service.approve(same, plan["id"], plan["plan_sha256"], NOW)
    service.approve(B, plan["id"], plan["plan_sha256"], NOW)
    for actor in [A, same, Identity(tenant="alder", subject=B.subject, roles=["operator"])]:
        with pytest.raises(DomainError):
            service.execute(actor, plan["id"], execute(plan), NOW)


@pytest.mark.parametrize("at,digest", [("2026-10-30T13:00:00Z", None), (NOW, "0" * 64)])
def test_expired_or_wrong_digest_approval_rejected(setup, at, digest):
    _, service, event = setup
    service.ingest(A, event, NOW)
    plan = service.plan(A, PlanRequest(event_id=event.id, playbook="contain-host"), NOW)
    with pytest.raises(DomainError):
        service.approve(B, plan["id"], digest or plan["plan_sha256"], at)


def test_target_state_and_policy_rechecked_at_execution(setup, monkeypatch):
    store, service, _ = setup
    plan = approved(setup)
    with store.tx() as db:
        resource = store.get(db, A.tenant, plan["resource"], "resource")
        resource["version"] = 5
        store.save(db, A.tenant, plan["resource"], "resource", resource)
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execute(plan), NOW)
    monkeypatch.setitem(
        POLICY, "contain-host", {"event": "malware-detected", "outcome": "disabled"}
    )
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execute(plan), NOW)


def test_failed_outcome_rolls_back_and_leaves_no_success_evidence(setup, monkeypatch):
    store, service, _ = setup
    plan = approved(setup)
    monkeypatch.setattr(Sandbox, "apply", lambda *args: {"state": "active"})
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execute(plan), NOW)
    assert len(store.evidence(A)["events"]) == 3
    with store.tx() as db:
        assert store.get(db, A.tenant, plan["resource"], "resource")["version"] == 0


def test_foreign_tenant_cannot_approve_execute_or_read(setup):
    store, service, _ = setup
    plan = approved(setup)
    foreign = DEMO_IDENTITIES["demo-other-tenant"]
    assert store.listing(foreign, "plan") == []
    with pytest.raises(DomainError):
        service.execute(foreign, plan["id"], execute(plan), NOW)
    with pytest.raises(DomainError):
        service.approve(foreign, plan["id"], plan["plan_sha256"], NOW)


def test_idempotency_key_cannot_bind_a_different_request(setup):
    _, service, _ = setup
    plan = approved(setup)
    service.execute(C, plan["id"], execute(plan), NOW)
    with pytest.raises(DomainError):
        service.execute(
            C, plan["id"], Execution(idempotency_key="response-key-001", plan_sha256="0" * 64), NOW
        )
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execute(plan, "new-response-key"), NOW)


def test_two_playbooks_have_distinct_verified_outcomes(setup):
    _, service, event = setup
    event.kind = "credential-anomaly"
    service.ingest(A, event, NOW)
    plan = service.plan(A, PlanRequest(event_id=event.id, playbook="disable-identity"), NOW)
    service.approve(B, plan["id"], plan["plan_sha256"], NOW)
    assert service.execute(C, plan["id"], execute(plan), NOW)["outcome"]["state"] == "disabled"


def test_audit_corruption_detected(setup):
    store, _, _ = setup
    approved(setup)
    with store.tx() as db:
        db.execute("UPDATE audit SET hash=? WHERE seq=1", ("0" * 64,))
    with pytest.raises(DomainError):
        store.evidence(A)
