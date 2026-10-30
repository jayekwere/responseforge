import json
import sys

import pytest
from fastapi.testclient import TestClient

from app import api, cli
from app.api import create_app
from app.common import DEMO_IDENTITIES

NOW = "2026-10-30T12:00:00Z"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "clock", lambda: NOW)
    return TestClient(create_app(tmp_path / "api.db", demo=True))


def request(client, operation, data=None, record_id="", token="demo-analyst"):
    return client.post(
        "/api/operate",
        headers={"Authorization": f"Bearer {token}"},
        json={"operation": operation, "record_id": record_id, "data": {} if data is None else data},
    )


def test_auth_origin_host_size_and_contracts(client):
    assert client.get("/health").status_code == 200
    assert client.get("/api/sample").status_code == 401
    assert client.get("/api/sample", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/health", headers={"Origin": "https://untrusted.invalid"}).status_code == 403
    assert client.get("/health", headers={"Host": "untrusted.invalid"}).status_code == 400
    assert request(client, "list", {"tenant": "birch"}).status_code == 422
    assert (
        client.post(
            "/api/operate",
            headers={"Authorization": "Bearer demo-analyst"},
            json={"operation": "list", "tenant": "birch"},
        ).status_code
        == 422
    )
    assert request(client, "ingest", {"unexpected": "field"}).status_code == 422
    response = client.post(
        "/api/operate",
        content=b"x" * 1_048_577,
        headers={"Authorization": "Bearer demo-analyst", "Content-Type": "application/json"},
    )
    assert response.status_code in {413, 422}
    assert "default-src 'none'" in client.get("/health").headers["content-security-policy"]


def test_complete_http_workflow_and_tenant_boundary(client):
    sample = client.get("/api/sample", headers={"Authorization": "Bearer demo-analyst"}).json()
    first = request(client, "ingest", sample)
    assert first.status_code == 200, first.text
    plan = request(
        client, "plan", {"event_id": first.json()["id"], "playbook": "contain-host"}
    ).json()
    key = plan["id"]
    assert (
        request(
            client, "approve", {"digest": plan["plan_sha256"]}, key, token="demo-other-tenant"
        ).status_code
        == 404
    )
    assert (
        request(
            client, "approve", {"digest": plan["plan_sha256"]}, key, token="demo-approver"
        ).status_code
        == 200
    )
    response = request(
        client,
        "execute",
        {"plan_sha256": plan["plan_sha256"], "idempotency_key": "http-demo-001"},
        key,
        token="demo-verifier",
    )
    assert response.status_code == 200 and response.json()["status"] == "succeeded"
    assert request(client, "list", token="demo-other-tenant").json() == {"records": []}
    assert request(client, "evidence").json()["integrity"] == "verified_local_chain"
    assert len(request(client, "list").json()["records"]) == 1
    assert request(client, "approve", {"digest": "0" * 64}).status_code == 422


def test_explicit_configuration_and_cli_modes(tmp_path, monkeypatch, capsys):
    with pytest.raises(ValueError):
        create_app(tmp_path / "none.db")
    assert create_app(tmp_path / "configured.db", DEMO_IDENTITIES)
    monkeypatch.setattr(sys, "argv", ["cli", "demo"])
    cli.main()
    assert json.loads(capsys.readouterr().out)["mode"] == "synthetic-offline"
    called = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *args, **kwargs: called.append(kwargs))
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "serve.db"))
    monkeypatch.setattr(sys, "argv", ["cli", "serve", "--demo", "--port", "8181"])
    cli.main()
    assert called[-1]["host"] == "127.0.0.1" and called[-1]["port"] == 8181
    identity_file = tmp_path / "identities.json"
    identity_file.write_text(json.dumps({"x" * 40: DEMO_IDENTITIES["demo-analyst"].model_dump()}))
    identity_file.chmod(0o600)
    monkeypatch.setenv("IDENTITY_FILE", str(identity_file))
    pass
    monkeypatch.setattr(sys, "argv", ["cli", "serve"])
    cli.main()
    identity_file.chmod(0o644)
    with pytest.raises(ValueError):
        cli.main()
    identity_file.chmod(0o600)
    identity_file.write_text(json.dumps({"weak": DEMO_IDENTITIES["demo-analyst"].model_dump()}))
    with pytest.raises(ValueError):
        cli.main()
