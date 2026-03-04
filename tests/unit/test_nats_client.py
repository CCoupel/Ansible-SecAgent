"""
test_nats_client.py — Unit tests for server/broker/nats_client.py

All NATS I/O is mocked — no real NATS server is required.
Tests cover:
  - connect(): idempotent, stream creation, subscription startup
  - publish_task() / publish_result(): subject routing, JSON encoding
  - _on_task_message(): ACK on success, NAK when agent offline, ACK on bad JSON
  - _on_result_message(): calls result_fn, ACKs always, handles bad JSON
  - subscribe_task(): ACK on callback success, NAK on failure
  - wait_for_result(): resolves when result arrives, asyncio.TimeoutError on timeout
  - close(): drain called, state cleared
  - Reconnect event callbacks: no exception raised
"""

import asyncio
import json
import os
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server.broker.nats_client import NatsClient


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _make_mock_js():
    """Return a mock JetStream object with all relevant methods as AsyncMocks."""
    js = AsyncMock()
    js.publish = AsyncMock(return_value=MagicMock(seq=1))
    js.find_stream = AsyncMock()
    js.add_stream = AsyncMock()
    js.subscribe = AsyncMock()
    js.purge_stream = AsyncMock()
    return js


def _make_mock_nc(js=None):
    """Return a mock NATS connection with a JetStream method."""
    nc = AsyncMock()
    nc.is_closed = False
    nc.drain = AsyncMock()
    nc.jetstream = MagicMock(return_value=js or _make_mock_js())
    return nc


def _make_nats_msg(subject: str, data: bytes) -> MagicMock:
    """Return a mock NATS message."""
    msg = MagicMock()
    msg.subject = subject
    msg.data = data
    msg.ack = AsyncMock()
    msg.nak = AsyncMock()
    return msg


# ---------------------------------------------------------------------------
# Fixture: NatsClient with mocked NATS connection
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client_and_js():
    """
    NatsClient instance where nats.connect() is patched to return a mock.
    Returns (client, mock_js) so tests can inspect what was called.
    """
    js = _make_mock_js()
    nc = _make_mock_nc(js)
    ws_send = AsyncMock()
    result_fn = AsyncMock()

    with patch("server.broker.nats_client.nats.connect", return_value=nc):
        client = NatsClient(
            nats_url="nats://mock:4222",
            ws_send_fn=ws_send,
            result_fn=result_fn,
            node_id="test-node",
        )
        await client.connect()

    yield client, js, ws_send, result_fn


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    async def test_connect_creates_nc_and_js(self):
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc) as mock_connect:
            client = NatsClient(nats_url="nats://mock:4222", node_id="n1")
            await client.connect()
            mock_connect.assert_called_once()
        assert client._nc is nc
        assert client._js is js

    async def test_connect_idempotent(self):
        """Calling connect() twice does not create a second connection."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc) as mock_connect:
            client = NatsClient(nats_url="nats://mock:4222", node_id="n1")
            await client.connect()
            await client.connect()  # second call should be no-op
            mock_connect.assert_called_once()

    async def test_connect_ensures_streams(self):
        """connect() calls _ensure_streams which calls find_stream for each stream."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(nats_url="nats://mock:4222")
            await client.connect()
        # Two streams: RELAY_TASKS + RELAY_RESULTS → two find_stream calls
        assert js.find_stream.await_count == 2

    async def test_connect_creates_stream_when_not_found(self):
        """If find_stream raises NotFoundError, add_stream is called."""
        from nats.js.errors import NotFoundError
        js = _make_mock_js()
        js.find_stream = AsyncMock(side_effect=NotFoundError)
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(nats_url="nats://mock:4222")
            await client.connect()
        assert js.add_stream.await_count == 2  # one per stream

    async def test_connect_subscribes_tasks_when_ws_send_provided(self):
        """With ws_send_fn set, subscribe to tasks.* is called."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(
                nats_url="nats://mock:4222",
                ws_send_fn=AsyncMock(),
            )
            await client.connect()
        # At least one subscribe call for tasks.*
        subjects = [str(c) for c in js.subscribe.call_args_list]
        assert js.subscribe.await_count >= 1

    async def test_connect_skips_task_subscription_without_ws_send(self):
        """Without ws_send_fn, task subscription is skipped."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(
                nats_url="nats://mock:4222",
                ws_send_fn=None,
                result_fn=None,
            )
            await client.connect()
        # No subscriptions at all (no ws_send_fn, no result_fn)
        assert js.subscribe.await_count == 0

    async def test_connect_subscribes_results_when_result_fn_provided(self):
        """With result_fn set, subscribe to results.* is called."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(
                nats_url="nats://mock:4222",
                result_fn=AsyncMock(),
            )
            await client.connect()
        assert js.subscribe.await_count >= 1


# ---------------------------------------------------------------------------
# TestClose
# ---------------------------------------------------------------------------

class TestClose:
    async def test_close_drains_connection(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        nc = client._nc   # capture reference before close() sets it to None
        await client.close()
        nc.drain.assert_awaited_once()

    async def test_close_clears_nc_and_js(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        await client.close()
        assert client._nc is None
        assert client._js is None

    async def test_close_when_already_closed_does_not_raise(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        client._nc.is_closed = True
        await client.close()  # should not raise

    async def test_close_when_nc_is_none_does_not_raise(self):
        client = NatsClient(nats_url="nats://mock:4222")
        await client.close()  # nc is None, should not raise


# ---------------------------------------------------------------------------
# TestPublishTask
# ---------------------------------------------------------------------------

class TestPublishTask:
    async def test_publish_task_uses_correct_subject(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        payload = {"task_id": "t1", "type": "exec", "cmd": "ls"}
        await client.publish_task("host-A", payload)
        js.publish.assert_awaited_once()
        args = js.publish.call_args[0]
        assert args[0] == "tasks.host-A"

    async def test_publish_task_serialises_to_json(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        payload = {"task_id": "t2", "type": "exec", "cmd": "pwd"}
        await client.publish_task("host-B", payload)
        args = js.publish.call_args[0]
        decoded = json.loads(args[1])
        assert decoded["cmd"] == "pwd"
        assert decoded["type"] == "exec"

    async def test_publish_task_returns_ack_seq(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        js.publish.return_value = MagicMock(seq=42)
        # Should not raise — ack is logged, not returned to caller
        await client.publish_task("host-C", {"task_id": "t3", "type": "exec", "cmd": "whoami"})


# ---------------------------------------------------------------------------
# TestPublishResult
# ---------------------------------------------------------------------------

class TestPublishResult:
    async def test_publish_result_uses_correct_subject(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())
        await client.publish_result(task_id, {"rc": 0, "stdout": "ok"})
        args = js.publish.call_args[0]
        assert args[0] == f"results.{task_id}"

    async def test_publish_result_serialises_payload(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())
        await client.publish_result(task_id, {"rc": 1, "stderr": "err"})
        args = js.publish.call_args[0]
        decoded = json.loads(args[1])
        assert decoded["rc"] == 1
        assert decoded["stderr"] == "err"


# ---------------------------------------------------------------------------
# TestOnTaskMessage — _on_task_message callback
# ---------------------------------------------------------------------------

class TestOnTaskMessage:
    async def _make_client_with_js(self, ws_send=None, result_fn=None):
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(
                nats_url="nats://mock:4222",
                ws_send_fn=ws_send or AsyncMock(),
                result_fn=result_fn,
                node_id="test-node",
            )
            await client.connect()
        return client, js

    async def test_on_task_message_acks_and_forwards_when_agent_connected(self):
        ws_send = AsyncMock()
        client, js = await self._make_client_with_js(ws_send=ws_send)
        payload = {"task_id": "t1", "type": "exec", "cmd": "ls"}
        msg = _make_nats_msg("tasks.host-X", json.dumps(payload).encode())
        await client._on_task_message(msg)
        ws_send.assert_awaited_once_with("host-X", payload)
        msg.ack.assert_awaited_once()
        msg.nak.assert_not_awaited()

    async def test_on_task_message_naks_when_agent_offline(self):
        from server.api.ws_handler import AgentOfflineError
        ws_send = AsyncMock(side_effect=AgentOfflineError("host-offline"))
        client, js = await self._make_client_with_js(ws_send=ws_send)
        payload = {"task_id": "t2", "type": "exec", "cmd": "ls"}
        msg = _make_nats_msg("tasks.host-offline", json.dumps(payload).encode())
        await client._on_task_message(msg)
        msg.nak.assert_awaited_once()
        msg.ack.assert_not_awaited()

    async def test_on_task_message_acks_bad_json(self):
        """Malformed JSON is ACKed (not NAKed) to avoid redelivery loop."""
        client, js = await self._make_client_with_js()
        msg = _make_nats_msg("tasks.host-Y", b"not-valid-json{{")
        await client._on_task_message(msg)
        msg.ack.assert_awaited_once()
        msg.nak.assert_not_awaited()

    async def test_on_task_message_acks_malformed_subject(self):
        """Subject without a dot (no hostname) causes ACK + skip."""
        client, js = await self._make_client_with_js()
        msg = _make_nats_msg("notasks", json.dumps({"task_id": "t"}).encode())
        await client._on_task_message(msg)
        msg.ack.assert_awaited_once()

    async def test_on_task_message_naks_without_ws_send_fn(self):
        """When ws_send_fn is None, message is NAKed."""
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(nats_url="nats://mock:4222", ws_send_fn=None, node_id="n")
            await client.connect()
        client._ws_send_fn = None  # explicitly ensure None
        payload = {"task_id": "t3", "type": "exec"}
        msg = _make_nats_msg("tasks.host-Z", json.dumps(payload).encode())
        await client._on_task_message(msg)
        msg.nak.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestOnResultMessage — _on_result_message callback
# ---------------------------------------------------------------------------

class TestOnResultMessage:
    async def test_on_result_message_calls_result_fn(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())
        payload = {"rc": 0, "stdout": "done", "task_id": task_id}
        msg = _make_nats_msg(f"results.{task_id}", json.dumps(payload).encode())
        await client._on_result_message(msg)
        result_fn.assert_awaited_once_with(task_id, payload)
        msg.ack.assert_awaited_once()

    async def test_on_result_message_acks_always(self, client_and_js):
        """Result messages are always ACKed — even if result_fn raises."""
        client, js, ws_send, result_fn = client_and_js
        result_fn.side_effect = RuntimeError("something failed")
        task_id = str(uuid.uuid4())
        msg = _make_nats_msg(
            f"results.{task_id}",
            json.dumps({"rc": 0, "task_id": task_id}).encode(),
        )
        await client._on_result_message(msg)
        msg.ack.assert_awaited_once()

    async def test_on_result_message_acks_bad_json(self, client_and_js):
        """Malformed result JSON is ACKed to avoid redelivery."""
        client, js, ws_send, result_fn = client_and_js
        msg = _make_nats_msg("results.some-task", b"bad{{json")
        await client._on_result_message(msg)
        msg.ack.assert_awaited_once()
        result_fn.assert_not_awaited()

    async def test_on_result_message_skips_result_fn_when_none(self):
        js = _make_mock_js()
        nc = _make_mock_nc(js)
        with patch("server.broker.nats_client.nats.connect", return_value=nc):
            client = NatsClient(nats_url="nats://mock:4222", result_fn=None)
            await client.connect()
        task_id = str(uuid.uuid4())
        msg = _make_nats_msg(
            f"results.{task_id}",
            json.dumps({"rc": 0}).encode(),
        )
        # Should not raise even though result_fn is None
        await client._on_result_message(msg)
        msg.ack.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestSubscribeTask — public subscribe_task() API
# ---------------------------------------------------------------------------

class TestSubscribeTask:
    async def test_subscribe_task_registers_subscription(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        callback = AsyncMock()
        await client.subscribe_task("host-sub", callback)
        # A subscribe call should have been made for tasks.host-sub
        subjects_called = [str(c.args[0]) for c in js.subscribe.call_args_list if c.args]
        assert "tasks.host-sub" in subjects_called

    async def test_subscribe_task_callback_acks_on_success(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        received = []
        callback = AsyncMock(side_effect=lambda p: received.append(p))

        # Capture the internal _cb that gets registered with js.subscribe
        captured_cb = None

        async def mock_subscribe(subject, config=None, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return AsyncMock()

        js.subscribe = AsyncMock(side_effect=mock_subscribe)
        await client.subscribe_task("host-cb", callback)

        payload = {"task_id": "t10", "type": "exec"}
        msg = _make_nats_msg("tasks.host-cb", json.dumps(payload).encode())
        await captured_cb(msg)

        assert received[0] == payload
        msg.ack.assert_awaited_once()
        msg.nak.assert_not_awaited()

    async def test_subscribe_task_callback_naks_on_failure(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        callback = AsyncMock(side_effect=RuntimeError("agent gone"))

        captured_cb = None

        async def mock_subscribe(subject, config=None, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return AsyncMock()

        js.subscribe = AsyncMock(side_effect=mock_subscribe)
        await client.subscribe_task("host-fail", callback)

        payload = {"task_id": "t11", "type": "exec"}
        msg = _make_nats_msg("tasks.host-fail", json.dumps(payload).encode())
        await captured_cb(msg)

        msg.nak.assert_awaited_once()
        msg.ack.assert_not_awaited()

    async def test_subscribe_task_acks_bad_json(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        callback = AsyncMock()

        captured_cb = None

        async def mock_subscribe(subject, config=None, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return AsyncMock()

        js.subscribe = AsyncMock(side_effect=mock_subscribe)
        await client.subscribe_task("host-json", callback)

        msg = _make_nats_msg("tasks.host-json", b"{{invalid")
        await captured_cb(msg)

        msg.ack.assert_awaited_once()
        callback.assert_not_awaited()


# ---------------------------------------------------------------------------
# TestWaitForResult
# ---------------------------------------------------------------------------

class TestWaitForResult:
    async def test_wait_for_result_resolves_when_message_arrives(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())
        expected = {"rc": 0, "stdout": "result", "task_id": task_id}

        # Capture the callback registered for the ephemeral subscription
        captured_cb = None
        mock_sub = AsyncMock()
        mock_sub.unsubscribe = AsyncMock()

        async def mock_subscribe(subject, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return mock_sub

        js.subscribe = AsyncMock(side_effect=mock_subscribe)

        # Start wait_for_result, then feed it a message via the callback
        wait_task = asyncio.create_task(client.wait_for_result(task_id, timeout=5.0))
        await asyncio.sleep(0)   # yield so wait_for_result registers the subscription

        # Simulate message arrival
        msg = _make_nats_msg(f"results.{task_id}", json.dumps(expected).encode())
        await captured_cb(msg)

        result = await wait_task
        assert result["rc"] == 0
        assert result["stdout"] == "result"

    async def test_wait_for_result_unsubscribes_after_result(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())

        captured_cb = None
        mock_sub = AsyncMock()
        mock_sub.unsubscribe = AsyncMock()

        async def mock_subscribe(subject, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return mock_sub

        js.subscribe = AsyncMock(side_effect=mock_subscribe)

        wait_task = asyncio.create_task(client.wait_for_result(task_id, timeout=5.0))
        await asyncio.sleep(0)

        msg = _make_nats_msg(f"results.{task_id}", json.dumps({"rc": 0}).encode())
        await captured_cb(msg)
        await wait_task

        mock_sub.unsubscribe.assert_awaited_once()

    async def test_wait_for_result_raises_timeout_error(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())

        mock_sub = AsyncMock()
        mock_sub.unsubscribe = AsyncMock()
        js.subscribe = AsyncMock(return_value=mock_sub)

        with pytest.raises(asyncio.TimeoutError):
            await client.wait_for_result(task_id, timeout=0.01)

        # Even on timeout, the subscription should be cleaned up
        mock_sub.unsubscribe.assert_awaited_once()

    async def test_wait_for_result_second_message_ignored(self, client_and_js):
        """Once the future is resolved, additional messages are ignored."""
        client, js, ws_send, result_fn = client_and_js
        task_id = str(uuid.uuid4())

        captured_cb = None
        mock_sub = AsyncMock()
        mock_sub.unsubscribe = AsyncMock()

        async def mock_subscribe(subject, cb=None, manual_ack=False):
            nonlocal captured_cb
            captured_cb = cb
            return mock_sub

        js.subscribe = AsyncMock(side_effect=mock_subscribe)

        wait_task = asyncio.create_task(client.wait_for_result(task_id, timeout=5.0))
        await asyncio.sleep(0)

        # First message resolves the future
        msg1 = _make_nats_msg(f"results.{task_id}", json.dumps({"rc": 0}).encode())
        await captured_cb(msg1)
        result = await wait_task
        assert result["rc"] == 0

        # Second message should not raise (fut.done() guard)
        msg2 = _make_nats_msg(f"results.{task_id}", json.dumps({"rc": 99}).encode())
        await captured_cb(msg2)  # should not raise


# ---------------------------------------------------------------------------
# TestPurgeStream
# ---------------------------------------------------------------------------

class TestPurgeStream:
    async def test_purge_stream_calls_js_purge(self, client_and_js):
        client, js, ws_send, result_fn = client_and_js
        await client.purge_stream("RELAY_TASKS")
        js.purge_stream.assert_awaited_once_with("RELAY_TASKS")


# ---------------------------------------------------------------------------
# TestReconnectCallbacks — _on_error, _on_disconnected, _on_reconnected
# ---------------------------------------------------------------------------

class TestReconnectCallbacks:
    async def test_on_error_does_not_raise(self):
        client = NatsClient(nats_url="nats://mock:4222")
        await client._on_error(RuntimeError("network error"))

    async def test_on_disconnected_does_not_raise(self):
        client = NatsClient(nats_url="nats://mock:4222")
        await client._on_disconnected()

    async def test_on_reconnected_does_not_raise(self):
        client = NatsClient(nats_url="nats://mock:4222")
        await client._on_reconnected()
