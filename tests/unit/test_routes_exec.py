"""
test_routes_exec.py — Unit tests for server/api/routes_exec.py

Uses httpx AsyncClient + FastAPI test transport.
No real NATS — all tests use the direct WS fallback (nats_client=None on app.state).
JWT tokens use role='plugin' to pass require_role("plugin") dependency.
"""

import asyncio
import base64
import json
import os
import sys
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")

from server.db.agent_store import AgentStore
from server.api import routes_exec, routes_register, ws_handler
from server.api.ws_handler import (
    pending_futures,
    stdout_buffers,
    ws_connections,
    _task_hostname,
    register_future,
)

JWT_SECRET = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Token helper
# ---------------------------------------------------------------------------

def _make_plugin_token() -> str:
    now = int(time.time())
    payload = {
        "sub": "ansible-plugin",
        "role": "plugin",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 3600,
    }
    return jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


PLUGIN_HEADERS = {"Authorization": f"Bearer {_make_plugin_token()}"}


# ---------------------------------------------------------------------------
# App factory — minimal FastAPI app with exec + register routers and in-memory store
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def clean_ws_state():
    """Reset ws_handler module-level state before each test."""
    ws_connections.clear()
    pending_futures.clear()
    stdout_buffers.clear()
    _task_hostname.clear()
    routes_exec._completed_results.clear()
    yield
    ws_connections.clear()
    pending_futures.clear()
    stdout_buffers.clear()
    _task_hostname.clear()
    routes_exec._completed_results.clear()


@pytest_asyncio.fixture
async def app_client():
    """FastAPI app with in-memory store, no NATS."""
    store = AgentStore(":memory:")
    await store.init()

    app = FastAPI()
    app.include_router(routes_register.router)
    app.include_router(routes_exec.router)
    app.state.store = store
    app.state.nats_client = None  # direct WS fallback

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, store

    await store.close()


def _mock_ws():
    ws = AsyncMock()
    ws.sent_messages = []

    async def _send_text(data):
        ws.sent_messages.append(json.loads(data))

    ws.send_text = AsyncMock(side_effect=_send_text)
    ws.close = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# TestExecCommand — POST /api/exec/{hostname}
# ---------------------------------------------------------------------------

class TestExecCommand:
    async def test_agent_offline_returns_503(self, app_client):
        c, store = app_client
        resp = await c.post(
            "/api/exec/offline-host",
            json={"cmd": "ls", "timeout": 5},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "agent_offline"

    async def test_exec_success_returns_200(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-exec"] = ws

        async def resolve_future(hostname, message):
            """Simulate agent responding to the task."""
            task_id = message.get("task_id")
            await asyncio.sleep(0)  # yield to let exec_command register the future
            fut = pending_futures.get(task_id)
            if fut and not fut.done():
                fut.set_result({"rc": 0, "stdout": "file1\nfile2", "stderr": "", "task_id": task_id})

        with patch("server.api.ws_handler.send_to_agent", side_effect=resolve_future):
            # We need to also patch send_to_agent in routes_exec's imported scope
            # Actually, since exec_command calls send_to_agent from ws_handler directly,
            # we need to resolve the future after it is registered.
            pass

        # Use a direct approach: register future manually and resolve it
        # The exec endpoint registers the future BEFORE sending, so we can hook in
        original_register = routes_exec.register_future

        resolved_event = asyncio.Event()

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)
            # Schedule resolution after the future is registered
            async def _resolve():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({
                        "rc": 0,
                        "stdout": "hello world",
                        "stderr": "",
                        "task_id": task_id,
                    })
            asyncio.create_task(_resolve())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/exec/host-exec",
                json={"cmd": "echo hello", "timeout": 5},
                headers=PLUGIN_HEADERS,
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["rc"] == 0
        assert body["stdout"] == "hello world"
        assert body["stderr"] == ""
        assert "truncated" in body

    async def test_exec_timeout_returns_504(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-timeout"] = ws

        # Register a future but never resolve it — will timeout
        original_wait = routes_exec._wait_for_result

        async def fast_timeout(task_id, hostname, timeout):
            # Override with a very short timeout
            from fastapi import HTTPException
            raise HTTPException(status_code=504, detail={"error": "timeout"})

        with patch("server.api.routes_exec._wait_for_result", side_effect=fast_timeout):
            resp = await c.post(
                "/api/exec/host-timeout",
                json={"cmd": "sleep 100", "timeout": 1},
                headers=PLUGIN_HEADERS,
            )

        assert resp.status_code == 504
        assert resp.json()["detail"]["error"] == "timeout"

    async def test_exec_agent_busy_returns_429(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-busy"] = ws

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)

            async def _resolve_busy():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({
                        "rc": -1,
                        "running_tasks": 5,
                        "task_id": task_id,
                    })
            asyncio.create_task(_resolve_busy())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/exec/host-busy",
                json={"cmd": "ls", "timeout": 5},
                headers=PLUGIN_HEADERS,
            )

        assert resp.status_code == 429
        assert resp.json()["detail"]["error"] == "agent_busy"

    async def test_exec_agent_disconnected_mid_task_returns_500(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-mid-disc"] = ws

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)

            async def _resolve_disc():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({
                        "error": "agent_disconnected",
                        "task_id": task_id,
                    })
            asyncio.create_task(_resolve_disc())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/exec/host-mid-disc",
                json={"cmd": "ls", "timeout": 5},
                headers=PLUGIN_HEADERS,
            )

        assert resp.status_code == 500
        assert resp.json()["detail"]["error"] == "agent_disconnected"

    async def test_exec_requires_plugin_role(self, app_client):
        """Requests without a valid plugin JWT are rejected."""
        c, store = app_client
        resp = await c.post(
            "/api/exec/some-host",
            json={"cmd": "ls", "timeout": 5},
        )
        assert resp.status_code == 401

    async def test_exec_empty_cmd_returns_422(self, app_client):
        c, store = app_client
        ws_connections["host-empty"] = _mock_ws()
        resp = await c.post(
            "/api/exec/host-empty",
            json={"cmd": "   ", "timeout": 5},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 422

    async def test_exec_negative_timeout_returns_422(self, app_client):
        c, store = app_client
        ws_connections["host-neg"] = _mock_ws()
        resp = await c.post(
            "/api/exec/host-neg",
            json={"cmd": "ls", "timeout": -1},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 422

    async def test_exec_caller_supplied_task_id_is_used(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-taskid"] = ws
        custom_task_id = "my-custom-task-id-123"

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            assert task_id == custom_task_id
            fut = original_register(task_id, hostname)

            async def _resolve():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({"rc": 0, "stdout": "", "stderr": ""})
            asyncio.create_task(_resolve())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/exec/host-taskid",
                json={"cmd": "ls", "timeout": 5, "task_id": custom_task_id},
                headers=PLUGIN_HEADERS,
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TestUploadFile — POST /api/upload/{hostname}
# ---------------------------------------------------------------------------

class TestUploadFile:
    async def test_upload_agent_offline_returns_503(self, app_client):
        c, store = app_client
        data_b64 = base64.b64encode(b"hello").decode()
        resp = await c.post(
            "/api/upload/offline-host",
            json={"dest": "/tmp/test.txt", "data": data_b64},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 503

    async def test_upload_payload_too_large_returns_413(self, app_client):
        """File larger than 500KB returns HTTP 413."""
        c, store = app_client
        ws_connections["host-big"] = _mock_ws()
        big_data = base64.b64encode(b"x" * (500 * 1024 + 1)).decode()
        resp = await c.post(
            "/api/upload/host-big",
            json={"dest": "/tmp/big.bin", "data": big_data},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 413
        assert resp.json()["detail"]["error"] == "payload_too_large"

    async def test_upload_exactly_at_limit_is_allowed(self, app_client):
        """500KB exactly is within the limit."""
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-limit"] = ws
        limit_data = base64.b64encode(b"x" * (500 * 1024)).decode()

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)

            async def _resolve():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({"rc": 0, "task_id": task_id})
            asyncio.create_task(_resolve())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/upload/host-limit",
                json={"dest": "/tmp/limit.bin", "data": limit_data},
                headers=PLUGIN_HEADERS,
            )
        assert resp.status_code == 200

    async def test_upload_invalid_base64_returns_400(self, app_client):
        c, store = app_client
        ws_connections["host-b64"] = _mock_ws()
        resp = await c.post(
            "/api/upload/host-b64",
            json={"dest": "/tmp/test.txt", "data": "not!!valid!!base64!!"},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_base64"

    async def test_upload_success_returns_rc_0(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-upload-ok"] = ws
        data_b64 = base64.b64encode(b"file content here").decode()

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)

            async def _resolve():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({"rc": 0, "task_id": task_id})
            asyncio.create_task(_resolve())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/upload/host-upload-ok",
                json={"dest": "/tmp/content.txt", "data": data_b64},
                headers=PLUGIN_HEADERS,
            )
        assert resp.status_code == 200
        assert resp.json()["rc"] == 0

    async def test_upload_empty_dest_returns_422(self, app_client):
        c, store = app_client
        ws_connections["host-udest"] = _mock_ws()
        data_b64 = base64.b64encode(b"data").decode()
        resp = await c.post(
            "/api/upload/host-udest",
            json={"dest": "   ", "data": data_b64},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# TestFetchFile — POST /api/fetch/{hostname}
# ---------------------------------------------------------------------------

class TestFetchFile:
    async def test_fetch_agent_offline_returns_503(self, app_client):
        c, store = app_client
        resp = await c.post(
            "/api/fetch/offline-host",
            json={"src": "/etc/hostname"},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 503

    async def test_fetch_success_returns_base64_data(self, app_client):
        c, store = app_client
        ws = _mock_ws()
        ws_connections["host-fetch"] = ws
        expected_b64 = base64.b64encode(b"hostname-value\n").decode()

        original_register = routes_exec.register_future

        def mock_register(task_id, hostname):
            fut = original_register(task_id, hostname)

            async def _resolve():
                await asyncio.sleep(0.01)
                if task_id in pending_futures and not pending_futures[task_id].done():
                    pending_futures[task_id].set_result({
                        "rc": 0,
                        "data": expected_b64,
                        "task_id": task_id,
                    })
            asyncio.create_task(_resolve())
            return fut

        with patch("server.api.routes_exec.register_future", side_effect=mock_register):
            resp = await c.post(
                "/api/fetch/host-fetch",
                json={"src": "/etc/hostname"},
                headers=PLUGIN_HEADERS,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["rc"] == 0
        assert body["data"] == expected_b64

    async def test_fetch_empty_src_returns_422(self, app_client):
        c, store = app_client
        ws_connections["host-fsrc"] = _mock_ws()
        resp = await c.post(
            "/api/fetch/host-fsrc",
            json={"src": "   "},
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# TestAsyncStatus — GET /api/async_status/{task_id}
# ---------------------------------------------------------------------------

class TestAsyncStatus:
    async def test_unknown_task_id_returns_404(self, app_client):
        c, store = app_client
        resp = await c.get(
            "/api/async_status/nonexistent-task-id",
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "task_not_found"

    async def test_running_task_returns_status_running(self, app_client):
        c, store = app_client
        task_id = str(uuid.uuid4())
        register_future(task_id, "host-running")
        resp = await c.get(
            f"/api/async_status/{task_id}",
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "running"
        assert body["task_id"] == task_id
        assert body["rc"] is None

    async def test_finished_task_returns_result_from_cache(self, app_client):
        c, store = app_client
        task_id = str(uuid.uuid4())
        routes_exec.store_result(task_id, {"rc": 0, "stdout": "done", "stderr": "", "truncated": False})
        resp = await c.get(
            f"/api/async_status/{task_id}",
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "finished"
        assert body["rc"] == 0
        assert body["stdout"] == "done"

    async def test_done_future_not_in_cache_is_resolved(self, app_client):
        """A completed future not yet in _completed_results is resolved on polling."""
        c, store = app_client
        task_id = str(uuid.uuid4())
        fut = register_future(task_id, "host-done")
        fut.set_result({"rc": 42, "stdout": "computed", "stderr": "", "truncated": False})
        resp = await c.get(
            f"/api/async_status/{task_id}",
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "finished"
        assert body["rc"] == 42

    async def test_cancelled_future_returns_408(self, app_client):
        c, store = app_client
        task_id = str(uuid.uuid4())
        fut = register_future(task_id, "host-cancel")
        fut.cancel()
        # Consume the CancelledError so the future is in cancelled state
        try:
            await asyncio.wait_for(asyncio.shield(fut), timeout=0.01)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        resp = await c.get(
            f"/api/async_status/{task_id}",
            headers=PLUGIN_HEADERS,
        )
        assert resp.status_code == 408

    async def test_async_status_requires_plugin_role(self, app_client):
        c, store = app_client
        resp = await c.get("/api/async_status/some-task-id")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestStoreResult — in-process result cache
# ---------------------------------------------------------------------------

class TestStoreResult:
    def test_store_result_adds_status_finished(self):
        task_id = str(uuid.uuid4())
        routes_exec.store_result(task_id, {"rc": 0, "stdout": "out", "stderr": ""})
        stored = routes_exec._completed_results[task_id]
        assert stored["status"] == "finished"
        assert stored["rc"] == 0

    def test_store_result_overwrites_existing(self):
        task_id = str(uuid.uuid4())
        routes_exec.store_result(task_id, {"rc": 0, "stdout": "first"})
        routes_exec.store_result(task_id, {"rc": 1, "stdout": "second"})
        assert routes_exec._completed_results[task_id]["stdout"] == "second"
