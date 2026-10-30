from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import uvicorn

from app.api import create_app
from app.common import DEMO_IDENTITIES, Identity, Store
from app.playbooks import Event, Execution, Orchestrator, PlanRequest


def demo() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "demo.db")
        analyst, approver, verifier = (
            DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"]
        )
        data = json.loads(Path("samples/workflow.json").read_text())
        NOW = "2026-10-30T12:00:00Z"
        service = Orchestrator(store)
        event = service.ingest(analyst, Event.model_validate(data), NOW)
        plan = service.plan(
            analyst, PlanRequest(event_id=event["id"], playbook="contain-host"), NOW
        )
        service.approve(approver, plan["id"], plan["plan_sha256"], NOW)
        execution = Execution(idempotency_key="demo-response-001", plan_sha256=plan["plan_sha256"])
        result = service.execute(verifier, plan["id"], execution, NOW)
        assert result == service.execute(verifier, plan["id"], execution, NOW)
        return {"mode": "synthetic-offline", "result": result, "evidence": store.evidence(analyst)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["demo", "serve"])
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "demo":
        print(json.dumps(demo(), indent=2))
        return
    identities = None
    if not args.demo:
        path = Path(os.environ["IDENTITY_FILE"])
        if path.stat().st_mode & 0o077:
            raise ValueError("Identity file must be private to its owner")
        raw = json.loads(path.read_text())
        if not raw or any(len(token) < 32 for token in raw):
            raise ValueError("Credentials must contain at least 32 characters")
        identities = {token: Identity.model_validate(value) for token, value in raw.items()}
    app = create_app(
        Path(os.environ.get("STATE_PATH", "artifacts/state.db")), identities, demo=args.demo
    )
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=args.port, access_log=False)


if __name__ == "__main__":
    main()
