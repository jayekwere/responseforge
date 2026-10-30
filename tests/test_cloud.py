import copy
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api import create_app
from app.cloud import CloudOrchestrator, CloudRequest
from app.common import DEMO_IDENTITIES, DomainError, Store
from app.connectors import (
    AwsConnector,
    AwsTarget,
    AzureConnector,
    AzureTarget,
    GcpConnector,
    GcpTarget,
    JsonHTTP,
    Registry,
    connect,
    physical,
)
from app.playbooks import Execution

NOW = "2026-10-30T12:00:00Z"
LATER = "2026-10-30T12:06:00Z"
A, B, C = (DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"])
AWS = AwsTarget(
    provider="aws",
    tenant="alder",
    alias="test-key",
    account="123456789012",
    profile="test",
    username="responseforge-test",
    user_id="AIDA" + "X" * 17,
    access_key_id="AKIA" + "X" * 16,
)
AZURE = AzureTarget(
    provider="azure",
    tenant="alder",
    alias="test-sp",
    directory_tenant="11111111-1111-1111-1111-111111111111",
    subscription="22222222-2222-2222-2222-222222222222",
    object_id="33333333-3333-3333-3333-333333333333",
    app_id="44444444-4444-4444-4444-444444444444",
)
GCP = GcpTarget(
    provider="gcp",
    tenant="alder",
    alias="test-sa",
    project="synthetic-project",
    email="responseforge-test@synthetic-project.iam.gserviceaccount.com",
    unique_id="123456789012345678901",
    operator_account="operator@example.invalid",
)


class Fake:
    def __init__(self):
        self.disabled = False
        self.writes = 0
        self.fail = False
        self.fail_read = False
        self.timeout_before = False
        self.version = 1

    def read(self):
        if self.fail_read:
            raise RuntimeError("secret provider detail must not escape")
        return {"disabled": self.disabled, "native_id": AWS.user_id, "version": self.version}

    def set_disabled(self, disabled):
        self.writes += 1
        if not self.timeout_before:
            self.disabled = disabled
        if self.fail:
            raise TimeoutError("ambiguous provider write")


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "cloud.db")
    fake = Fake()
    registry = Registry([AWS])
    return store, CloudOrchestrator(store, registry, lambda _: fake, lambda: NOW), fake, registry


def request(**changes):
    return CloudRequest.model_validate(
        {
            "target": AWS.alias,
            "action": "disable",
            "evidence_sha256": "a" * 64,
            "observed_at": NOW,
            **changes,
        }
    )


def approved(setup, **changes):
    _, service, _, _ = setup
    plan = service.plan(A, request(**changes), NOW)
    return service.approve(B, plan["id"], plan["plan_sha256"], NOW)


def execution(plan, key="cloud-idem-001"):
    return Execution(idempotency_key=key, plan_sha256=plan["plan_sha256"])


def test_live_lifecycle_has_separate_approved_restore_and_durable_readback(setup):
    store, service, fake, registry = setup
    plan = approved(setup)
    result = service.execute(C, plan["id"], execution(plan), NOW)
    assert result["status"] == "verified" and fake.disabled and fake.writes == 1
    assert service.execute(C, plan["id"], execution(plan), NOW) == result
    assert (
        CloudOrchestrator(Store(store.path), registry, lambda _: fake, lambda: NOW).execute(
            C, plan["id"], execution(plan), NOW
        )
        == result
    )
    restored = approved(setup, action="restore", restore_of=plan["id"])
    assert (
        service.execute(C, restored["id"], execution(restored, "restore-idem-001"), NOW)["status"]
        == "verified"
    )
    assert not fake.disabled and fake.writes == 2
    assert store.evidence(A)["integrity"] == "verified_local_chain"
    with pytest.raises(DomainError):
        service.plan(A, request(action="restore", restore_of=plan["id"]), NOW)


def test_independent_roles_and_tenant_boundaries(setup):
    _, service, _, _ = setup
    plan = service.plan(A, request(), NOW)
    with pytest.raises(DomainError):
        service.approve(
            A.model_copy(update={"roles": ["approver"]}), plan["id"], plan["plan_sha256"], NOW
        )
    service.approve(B, plan["id"], plan["plan_sha256"], NOW)
    for actor in [
        A.model_copy(update={"roles": ["operator"]}),
        B.model_copy(update={"roles": ["operator"]}),
        DEMO_IDENTITIES["demo-other-tenant"],
    ]:
        with pytest.raises(DomainError):
            service.execute(actor, plan["id"], execution(plan), NOW)
    with pytest.raises(DomainError):
        service.plan(DEMO_IDENTITIES["demo-other-tenant"], request(), NOW)


@pytest.mark.parametrize(
    "change",
    [
        {"observed_at": "2020-01-01T00:00:00Z"},
        {"observed_at": "2026-10-31T00:00:00Z"},
        {"action": "restore"},
        {"restore_of": "cloud-" + "a" * 32},
    ],
)
def test_invalid_event_or_restore_provenance_rejected(setup, change):
    with pytest.raises(DomainError):
        setup[1].plan(A, request(**change), NOW)


def test_strict_cloud_schema_rejects_client_target_override():
    for changes in [
        {"account": "999999999999"},
        {"endpoint": "http://evil.invalid"},
        {"observed_at": "2026-10-30"},
        {"evidence_sha256": "false"},
    ]:
        with pytest.raises(ValidationError):
            request(**changes)


def test_precondition_drift_and_provider_read_failure_never_write(setup):
    _, service, fake, _ = setup
    plan = approved(setup)
    fake.version = 2
    assert service.execute(C, plan["id"], execution(plan), NOW)["status"] == "precondition_failed"
    assert fake.writes == 0
    fake.version = 1
    plan = approved(setup)
    fake.fail_read = True
    assert (
        service.execute(C, plan["id"], execution(plan, "second-read-failure"), NOW)["status"]
        == "precondition_failed"
    )
    assert fake.writes == 0


def test_timeout_is_not_retried_and_reconciles_after_cooldown(setup):
    store, service, fake, registry = setup
    plan = approved(setup)
    fake.fail = True
    result = service.execute(C, plan["id"], execution(plan), NOW)
    assert result["status"] == "uncertain" and fake.writes == 1
    assert service.execute(C, plan["id"], execution(plan), NOW) == result
    with pytest.raises(DomainError):
        service.reconcile(C, plan["id"], NOW)
    restarted = CloudOrchestrator(Store(store.path), registry, lambda _: fake, lambda: NOW)
    assert restarted.reconcile(C, plan["id"], LATER)["status"] == "verified"
    assert fake.writes == 1
    assert restarted.reconcile(C, plan["id"], LATER)["status"] == "verified"


def test_timeout_before_provider_write_keeps_target_locked(setup):
    _, service, fake, _ = setup
    plan = approved(setup)
    fake.fail = True
    fake.timeout_before = True
    assert service.execute(C, plan["id"], execution(plan), NOW)["status"] == "uncertain"
    assert service.reconcile(C, plan["id"], LATER)["status"] == "uncertain"
    other = approved(setup)
    with pytest.raises(DomainError):
        service.execute(C, other["id"], execution(other, "different-idem"), NOW)
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execution(plan, "different-idem"), NOW)
    assert fake.writes == 1


def test_concurrent_retries_reserve_only_one_application_dispatch(setup):
    _, service, fake, _ = setup
    plan = approved(setup)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: service.execute(C, plan["id"], execution(plan), NOW), range(8))
        )
    assert fake.writes == 1 and all(
        r["status"] in {"reserved", "write_started", "verified"} for r in results
    )


def test_expiry_digest_and_changed_registry_reject_before_dispatch(setup):
    _, service, fake, registry = setup
    plan = approved(setup)
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execution(plan), "2026-10-30T12:16:00Z")
    with pytest.raises(DomainError):
        service.execute(
            C, plan["id"], Execution(idempotency_key="wrong-digest", plan_sha256="b" * 64), NOW
        )
    registry.targets[("alder", AWS.alias)] = AWS.model_copy(update={"profile": "changed"})
    with pytest.raises(DomainError):
        service.execute(C, plan["id"], execution(plan), NOW)
    assert fake.writes == 0


def test_private_registry_and_physical_alias_dedup(tmp_path):
    with pytest.raises(ValueError):
        Registry([AWS, AWS.model_copy(update={"tenant": "other", "alias": "another"})])
    with pytest.raises(ValueError):
        Registry([GCP.model_copy(update={"project": "another-project"})])
    path = tmp_path / "targets.json"
    path.write_text(json.dumps([AWS.model_dump()]))
    path.chmod(0o600)
    assert Registry.load(path).get("alder", AWS.alias) == AWS
    path.chmod(0o644)
    with pytest.raises(ValueError):
        Registry.load(path)
    assert (
        isinstance(connect(AWS), AwsConnector)
        and isinstance(connect(AZURE), AzureConnector)
        and isinstance(connect(GCP), GcpConnector)
    )


def aws_native():
    return {
        "get-caller-identity": {
            "Account": AWS.account,
            "Arn": f"arn:aws:iam::{AWS.account}:user/operator",
        },
        "get-user": {
            "User": {
                "UserName": AWS.username,
                "UserId": AWS.user_id,
                "Arn": f"arn:aws:iam::{AWS.account}:user/{AWS.username}",
                "Tags": [
                    {"Key": "responseforge-managed", "Value": "true"},
                    {"Key": "responseforge-tenant", "Value": "alder"},
                ],
            }
        },
        "list-access-keys": {
            "IsTruncated": False,
            "AccessKeyMetadata": [
                {
                    "UserName": AWS.username,
                    "AccessKeyId": AWS.access_key_id,
                    "Status": "Active",
                    "CreateDate": "2026-10-30T00:00:00Z",
                }
            ],
        },
        "update-access-key": {},
    }


def test_aws_native_target_pinning_and_exact_write():
    native = aws_native()
    calls = []

    def run(args):
        calls.append(args)
        return copy.deepcopy(native[args[2]])

    connector = AwsConnector(AWS, run)
    assert connector.read()["disabled"] is False
    connector.set_disabled(True)
    assert json.loads(calls[-1][calls[-1].index("--cli-input-json") + 1]) == {
        "UserName": AWS.username,
        "AccessKeyId": AWS.access_key_id,
        "Status": "Inactive",
    }
    assert all(
        "https://iam.amazonaws.com" in c or "https://sts.us-east-1.amazonaws.com" in c
        for c in calls
    )
    with pytest.raises(DomainError):
        connector.call("iam", "delete-user", {})


@pytest.mark.parametrize("mutation", ["account", "self", "root", "uid", "tags", "key", "truncated"])
def test_aws_native_adversarial_preconditions(mutation):
    native = aws_native()
    if mutation == "account":
        native["get-caller-identity"]["Account"] = "999999999999"
    if mutation == "self":
        native["get-caller-identity"]["Arn"] = native["get-user"]["User"]["Arn"]
    if mutation == "root":
        native["get-caller-identity"]["Arn"] = f"arn:aws:iam::{AWS.account}:root"
    if mutation == "uid":
        native["get-user"]["User"]["UserId"] = "recreated"
    if mutation == "tags":
        native["get-user"]["User"]["Tags"] = []
    if mutation == "key":
        native["list-access-keys"]["AccessKeyMetadata"] = []
    if mutation == "truncated":
        native["list-access-keys"]["IsTruncated"] = True
    with pytest.raises(DomainError):
        AwsConnector(AWS, lambda args: native[args[2]]).read()


def test_azure_native_account_enabled_and_tenant_validation():
    context = {
        "id": AZURE.subscription,
        "tenantId": AZURE.directory_tenant,
        "user": {"name": "operator"},
    }
    value = {
        "id": AZURE.object_id,
        "appId": AZURE.app_id,
        "displayName": "responseforge-test",
        "servicePrincipalType": "Application",
        "accountEnabled": True,
        "tags": ["responseforge-managed", "responseforge-tenant:alder"],
    }
    calls = []

    def http(method, url, payload):
        calls.append((method, url, payload))
        return value

    connector = AzureConnector(AZURE, http, lambda _: context)
    assert connector.read()["disabled"] is False
    connector.set_disabled(True)
    assert calls[-1] == ("PATCH", connector.url(), {"accountEnabled": False})
    value["appId"] = "changed"
    with pytest.raises(DomainError):
        connector.read()
    value["appId"] = AZURE.app_id
    context["tenantId"] = "other"
    with pytest.raises(DomainError):
        connector.read()


def test_gcp_native_uid_ownership_and_disable_enable():
    value = {
        "projectId": GCP.project,
        "email": GCP.email,
        "uniqueId": GCP.unique_id,
        "disabled": False,
        "description": "responseforge-managed:alder:test-sa",
    }
    calls = []

    def http(method, url, payload):
        calls.append((method, url, payload))
        return value

    connector = GcpConnector(GCP, http, lambda _: {})
    assert connector.read()["target"] == physical(GCP)
    connector.set_disabled(True)
    connector.set_disabled(False)
    assert calls[-2][1].endswith(":disable") and calls[-1][1].endswith(":enable")
    value["uniqueId"] = "recreated"
    with pytest.raises(DomainError):
        connector.read()
    with pytest.raises(DomainError):
        GcpConnector(
            GCP.model_copy(update={"operator_account": GCP.email}), http, lambda _: {}
        ).read()
    with pytest.raises(DomainError):
        GcpConnector(
            GCP, http, lambda _: {"auth": {"impersonate_service_account": GCP.email}}
        ).read()


def test_http_does_not_redirect_or_expose_credentials_on_errors():
    http = JsonHTTP("private-token", "graph.microsoft.com")
    with pytest.raises(DomainError):
        http("GET", "https://evil.invalid/", None)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"location": "https://evil.invalid"})
        )
    )
    with (
        patch("app.connectors.httpx.Client", return_value=client),
        pytest.raises(DomainError, match="HTTP 302"),
    ):
        http(
            "PATCH",
            "https://graph.microsoft.com/v1.0/servicePrincipals/x",
            {"accountEnabled": False},
        )


def test_configured_api_cannot_enable_live_actions_with_demo_credentials(tmp_path):
    with pytest.raises(ValueError):
        create_app(tmp_path / "bad.db", demo=True, cloud_registry=Registry([AWS]))
    demo = TestClient(create_app(tmp_path / "demo.db", demo=True))
    response = demo.post(
        "/api/cloud/operate",
        headers={"Authorization": "Bearer demo-analyst"},
        json={"operation": "plan", "data": request().model_dump()},
    )
    assert response.status_code == 403
    fake = Fake()
    accounts = {"a" * 32: A, "b" * 32: B, "c" * 32: C}
    client = TestClient(
        create_app(
            tmp_path / "live.db",
            accounts,
            cloud_registry=Registry([AWS]),
            cloud_factory=lambda _: fake,
        )
    )

    def op(token, data):
        return client.post(
            "/api/cloud/operate", headers={"Authorization": "Bearer " + token * 32}, json=data
        )

    assert (
        op(
            "a", {"operation": "plan", "data": {**request().model_dump(), "account": "other"}}
        ).status_code
        == 422
    )
    plan = op(
        "a",
        {
            "operation": "plan",
            "data": {**request().model_dump(), "observed_at": "2026-10-30T12:00:00Z"},
        },
    )
    # Bind wall time at the server boundary; clients cannot choose approval time.
    with patch("app.api.clock", return_value=NOW):
        plan = op("a", {"operation": "plan", "data": request().model_dump()}).json()
        assert (
            op(
                "b",
                {
                    "operation": "approve",
                    "record_id": plan["id"],
                    "data": {"digest": plan["plan_sha256"]},
                },
            ).status_code
            == 200
        )
        assert (
            op(
                "c",
                {
                    "operation": "execute",
                    "record_id": plan["id"],
                    "data": execution(plan).model_dump(),
                },
            ).json()["status"]
            == "verified"
        )
        assert len(op("a", {"operation": "list"}).json()["records"]) == 1
    assert fake.writes == 1
