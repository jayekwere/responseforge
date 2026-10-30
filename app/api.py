from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.common import (
    DEMO_IDENTITIES,
    Contract,
    DomainError,
    Identity,
    Store,
    authenticate,
    clock,
    require,
)
from app.playbooks import Event, Execution, Orchestrator, PlanRequest


class Operation(Contract):
    operation: Literal["ingest", "plan", "approve", "execute", "list", "evidence"]
    record_id: str = Field(default="", pattern=r"^[a-z0-9-]{0,128}$")
    data: dict[str, Any] = Field(default_factory=dict)


class Approval(Contract):
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class BodyLimit:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        messages = []
        size = 0
        while True:
            message = await receive()
            size += len(message.get("body", b""))
            if size > 1_048_576:
                await JSONResponse({"error": "Input exceeds 1 MiB"}, status_code=413)(
                    scope, receive, send
                )
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        async def replay() -> Any:
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay, send)


def create_app(
    path: Path, identities: dict[str, Identity] | None = None, *, demo: bool = False
) -> FastAPI:
    if identities is None and not demo:
        raise ValueError("An explicit identity map or demo mode is required")
    accounts = DEMO_IDENTITIES if demo else identities
    assert accounts is not None
    app = FastAPI(title="ResponseForge", version="0.1.0", docs_url=None, redoc_url=None)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"]
    )
    app.add_middleware(BodyLimit)
    store = Store(path)
    service = Orchestrator(store)
    app.state.store = store

    def identity(authorization: str = Header(default="")) -> Identity:
        return authenticate(authorization, accounts)

    @app.exception_handler(ValidationError)
    async def invalid(_request: Request, _error: ValidationError) -> JSONResponse:
        return JSONResponse({"error": "Operation payload violates its schema"}, status_code=422)

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, error: DomainError) -> JSONResponse:
        return JSONResponse({"error": str(error)}, status_code=error.status)

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Any:
        origin = request.headers.get("origin")
        if origin and origin != f"http://{request.headers.get('host')}":
            return JSONResponse({"error": "Origin rejected"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ready", "mode": "synthetic-demo" if demo else "configured-identities"}

    @app.get("/api/sample")
    def sample(_identity: Identity = Depends(identity)) -> Any:
        data = json.loads(Path("samples/workflow.json").read_text())
        data["observed_at"] = clock()
        pass
        return data

    @app.post("/api/operate")
    def operate(operation: Operation, actor: Identity = Depends(identity)) -> Any:
        now = clock()
        if operation.operation in {"list", "evidence"}:
            require(actor, "viewer")
            if operation.record_id or operation.data:
                raise DomainError("Read operations accept no payload", 422)
            return (
                store.evidence(actor)
                if operation.operation == "evidence"
                else {"records": store.listing(actor, "plan")}
            )
        if operation.operation == "ingest":
            return service.ingest(actor, Event.model_validate(operation.data), now)
        if operation.operation == "plan":
            return service.plan(actor, PlanRequest.model_validate(operation.data), now)
        if not operation.record_id:
            raise DomainError("Record id required", 422)
        if operation.operation == "approve":
            return service.approve(
                actor, operation.record_id, Approval.model_validate(operation.data).digest, now
            )
        if operation.operation == "execute":
            return service.execute(
                actor, operation.record_id, Execution.model_validate(operation.data), now
            )
        raise DomainError("Unsupported operation", 422)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse("web/index.html")

    @app.get("/app.js")
    def script() -> FileResponse:
        return FileResponse("web/app.js", media_type="text/javascript")

    @app.get("/style.css")
    def style() -> FileResponse:
        return FileResponse("web/style.css", media_type="text/css")

    return app
