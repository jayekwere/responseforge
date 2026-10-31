import asyncio
import json
import tracemalloc
from pathlib import Path

from app import api
from app.api import BodyLimit
from app.common import DEMO_IDENTITIES


async def exercise(messages, headers=()):
    source = iter(messages)
    observed = {"called": False, "disconnected": False, "body": bytearray()}
    sent = []

    async def receive():
        return next(source, {"type": "http.disconnect"})

    async def send(message):
        sent.append(message)

    async def downstream(scope, read, write):
        observed["called"] = True
        while True:
            message = await read()
            if message["type"] == "http.disconnect":
                observed["disconnected"] = True
                break
            observed["body"].extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await write(
            {
                "type": "http.response.start",
                "status": 400 if observed["disconnected"] else 200,
                "headers": [],
            }
        )
        await write({"type": "http.response.body", "body": b""})

    await BodyLimit(downstream)({"type": "http", "headers": list(headers)}, receive, send)
    return observed, sent


def test_fragmented_body_storage_stays_bounded_and_preserves_bytes():
    count = 100000
    messages = (
        {"type": "http.request", "body": b"x", "more_body": i < count - 1} for i in range(count)
    )
    tracemalloc.start()
    try:
        observed, sent = asyncio.run(exercise(messages))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert observed["body"] == b"x" * count
    assert observed["called"] and not observed["disconnected"]
    assert sent[0]["status"] == 200
    assert peak < 4 * 1048576


def test_raw_byte_limit_is_inclusive_and_ignores_declared_length():
    for size, status in [(1048576, 200), (1048577, 413)]:
        messages = [
            {"type": "http.request", "body": b"x" * (size - 1), "more_body": True},
            {"type": "http.request", "body": b"x"},
        ]
        observed, sent = asyncio.run(exercise(messages, [(b"content-length", b"1")]))
        assert sent[0]["status"] == status
        assert observed["called"] is (status == 200)
    document = '{"message":"\u2603"}'.encode()
    messages = (
        {"type": "http.request", "body": document[i : i + 1], "more_body": i < len(document) - 1}
        for i in range(len(document))
    )
    observed, _ = asyncio.run(exercise(messages))
    assert observed["body"] == document


def test_disconnect_is_not_complete_content_and_non_http_scopes_pass_through():
    for prefix in [[], [{"type": "http.request", "body": b'{"partial":', "more_body": True}]]:
        observed, sent = asyncio.run(exercise([*prefix, {"type": "http.disconnect"}]))
        assert observed["disconnected"]
        assert sent[0]["status"] == 400

    async def other_protocol():
        observed = []

        async def receive():
            return {"type": "lifespan.startup"}

        async def send(message):
            observed.append(message)

        async def downstream(scope, read, write):
            assert scope["type"] == "lifespan"
            await write(await read())

        await BodyLimit(downstream)({"type": "lifespan"}, receive, send)
        assert observed == [{"type": "lifespan.startup"}]

    asyncio.run(other_protocol())


def test_incomplete_transport_body_cannot_authorize_an_operation(tmp_path, monkeypatch):
    now = "2026-10-30T12:00:00Z"
    monkeypatch.setattr(api, "clock", lambda: now)
    app = api.create_app(tmp_path / "disconnect.db", demo=True)
    event = json.loads(Path("samples/workflow.json").read_text())
    payload = json.dumps({"operation": "ingest", "data": event}).encode()

    async def interrupted():
        messages = iter(
            [
                {"type": "http.request", "body": payload, "more_body": True},
                {"type": "http.disconnect"},
            ]
        )
        sent = []

        async def receive():
            return next(messages, {"type": "http.disconnect"})

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/operate",
            "raw_path": b"/api/operate",
            "query_string": b"",
            "server": ("127.0.0.1", 80),
            "client": ("127.0.0.1", 12345),
            "headers": [
                (b"host", b"localhost"),
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer demo-analyst"),
            ],
        }
        await app(scope, receive, send)
        assert not any(m["type"] == "http.response.start" and m["status"] == 200 for m in sent)

    asyncio.run(interrupted())
    assert app.state.store.listing(DEMO_IDENTITIES["demo-analyst"], "event") == []
