"""
ws_handler.py — WebSocket handler for persistent relay-agent connections.

Endpoint:
    WebSocket /ws/agent

Responsibilities:
  - Authenticate agent JWT on connection (role=agent, JTI not blacklisted)
  - Maintain ws_connections registry (hostname -> WebSocket, 1 per hostname)
  - Dispatch incoming messages (ack / stdout / result) to pending asyncio Futures
  - Accumulate stdout buffers per task_id
  - Resolve pending futures with error on agent disconnection
  - Expose send_to_agent() for other modules (routes_exec) to push tasks

Thread-safety: all state is managed within a single asyncio event loop.
No threading is used — asyncio dicts are safe for concurrent coroutine access.

Protocol reference: ARCHITECTURE.md §4, §9, §13 — HLD §3.2, §3.4
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import ExpiredSignatureError, JWTError

from server.api.routes_register import _extract_bearer, _get_jwt_secret, verify_jwt
from server.db.agent_store import AgentStore

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Shared in-process state
# All access is from the asyncio event loop — no locking required.
# ---------------------------------------------------------------------------

# hostname -> active WebSocket connection
ws_connections: dict[str, WebSocket] = {}

# task_id -> asyncio.Future[dict]  (result or error payload)
pending_futures: dict[str, asyncio.Future] = {}

# task_id -> accumulated stdout string
stdout_buffers: dict[str, str] = {}

# Maximum accumulated stdout per task before truncation (5 MB — ARCHITECTURE.md §2)
_STDOUT_MAX_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class AgentOfflineError(Exception):
    """Raised when attempting to send to an agent that has no active WebSocket."""


# ---------------------------------------------------------------------------
# WebSocket close codes (ARCHITECTURE.md §4)
# ---------------------------------------------------------------------------

_WS_CLOSE_REVOKED = 4001     # Token revoked — agent must not reconnect
_WS_CLOSE_EXPIRED = 4002     # Token expired — agent should refresh then reconnect
_WS_CLOSE_NORMAL  = 4000     # Normal close


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _authenticate(websocket: WebSocket, store: AgentStore) -> Optional[str]:
    """
    Extract and validate the JWT from the WebSocket upgrade headers.

    Closes the WebSocket with the appropriate code on failure.

    Args:
        websocket: Incoming WebSocket connection (not yet accepted).
        store:     AgentStore for JTI blacklist lookup.

    Returns:
        The agent hostname (JWT sub claim) on success, or None on failure.
        The websocket is closed before returning None.
    """
    # FastAPI delivers upgrade headers via websocket.headers
    authorization = websocket.headers.get("authorization")
    if not authorization:
        await websocket.close(code=_WS_CLOSE_REVOKED)
        logger.warning("WS auth failed: missing Authorization header")
        return None

    try:
        token = _extract_bearer(authorization)
    except Exception:
        await websocket.close(code=_WS_CLOSE_REVOKED)
        logger.warning("WS auth failed: malformed Authorization header")
        return None

    # Verify JWT — raises HTTPException on failure, which we catch here
    try:
        payload = await verify_jwt(token, store)
    except Exception as exc:
        detail = getattr(exc, "detail", {})
        error = detail.get("error", "") if isinstance(detail, dict) else str(detail)
        if error == "token_expired":
            await websocket.close(code=_WS_CLOSE_EXPIRED)
        else:
            await websocket.close(code=_WS_CLOSE_REVOKED)
        logger.warning("WS auth failed: %s", error)
        return None

    # Enforce agent role
    if payload.get("role") != "agent":
        await websocket.close(code=_WS_CLOSE_REVOKED)
        logger.warning("WS auth failed: role is not agent (got %s)", payload.get("role"))
        return None

    return payload["sub"]  # hostname


def _resolve_futures_for_hostname(hostname: str, error: str) -> None:
    """
    Resolve all pending futures for tasks that were assigned to a given hostname.

    Called when the agent disconnects unexpectedly so that blocking
    POST /api/exec callers receive an error response immediately.

    The mapping of task_id to hostname is not stored explicitly — we instead
    keep a side-table ``_task_hostname`` populated by send_to_agent().

    Args:
        hostname: Agent hostname that just disconnected.
        error:    Error code to resolve futures with.
    """
    task_ids = [tid for tid, h in _task_hostname.items() if h == hostname]
    for task_id in task_ids:
        fut = pending_futures.get(task_id)
        if fut and not fut.done():
            fut.set_result({"error": error, "task_id": task_id})
            logger.info(
                "Future resolved with error on disconnect",
                extra={"task_id": task_id, "error": error, "hostname": hostname},
            )
        # Cleanup
        pending_futures.pop(task_id, None)
        stdout_buffers.pop(task_id, None)
        _task_hostname.pop(task_id, None)


# task_id -> hostname mapping so we can resolve futures on disconnection
_task_hostname: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Message dispatching
# ---------------------------------------------------------------------------

async def _handle_message(msg: dict, hostname: str, store: AgentStore) -> None:
    """
    Dispatch a single message received from an agent.

    Supported message types (ARCHITECTURE.md §4 Agent→Server):
      - ack    : task acknowledged, subprocess started
      - stdout : streaming output chunk
      - result : final result (rc, stdout, stderr, truncated)

    Args:
        msg:      Parsed JSON message dict.
        hostname: Sending agent's hostname.
        store:    AgentStore for last_seen updates.
    """
    task_id = msg.get("task_id")
    msg_type = msg.get("type")

    # Update heartbeat on every message (ARCHITECTURE.md §4)
    await store.update_last_seen(hostname)

    if not task_id or not msg_type:
        logger.warning(
            "WS message missing task_id or type",
            extra={"hostname": hostname, "msg": msg},
        )
        return

    if msg_type == "ack":
        # Subprocess started — nothing to resolve yet, just log
        logger.debug(
            "Task ack received",
            extra={"task_id": task_id, "hostname": hostname},
        )

    elif msg_type == "stdout":
        # Accumulate stdout, enforce 5 MB cap
        data = msg.get("data", "")
        buf = stdout_buffers.get(task_id, "")
        combined = buf + data
        if len(combined.encode()) > _STDOUT_MAX_BYTES:
            combined = combined.encode()[:_STDOUT_MAX_BYTES].decode(errors="replace")
            logger.warning(
                "Stdout buffer truncated",
                extra={"task_id": task_id, "hostname": hostname},
            )
        stdout_buffers[task_id] = combined

    elif msg_type == "result":
        # Final result — merge accumulated stdout if not already present
        if "stdout" not in msg or not msg["stdout"]:
            msg = {**msg, "stdout": stdout_buffers.pop(task_id, "")}
        else:
            stdout_buffers.pop(task_id, None)

        fut = pending_futures.get(task_id)
        if fut and not fut.done():
            fut.set_result(msg)
            logger.info(
                "Task result received",
                extra={"task_id": task_id, "rc": msg.get("rc"), "hostname": hostname},
            )
        else:
            logger.warning(
                "Result received but no pending future",
                extra={"task_id": task_id, "hostname": hostname},
            )
        # Cleanup
        pending_futures.pop(task_id, None)
        _task_hostname.pop(task_id, None)

    else:
        logger.warning(
            "Unknown WS message type",
            extra={"type": msg_type, "task_id": task_id, "hostname": hostname},
        )


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@router.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket) -> None:
    """
    Persistent WebSocket endpoint for relay-agent connections.

    Flow:
    1. Verify JWT from Authorization header BEFORE accepting the connection.
    2. Accept the connection (only if JWT is valid).
    3. Register in ws_connections (replacing stale connection if any).
    4. Receive messages in a loop until disconnect.
    5. On disconnect: update status, clean up, resolve pending futures.

    One WebSocket per hostname — reconnection replaces the previous entry.

    Security (ARCHITECTURE.md §4, §7):
      JWT is verified from the WebSocket upgrade request headers before
      accept() is called.  Invalid tokens cause the connection to be
      rejected at the HTTP upgrade level (403) — no WebSocket session is
      established for unauthenticated clients.
    """
    store: AgentStore = websocket.app.state.store

    # --- Step 1: verify JWT BEFORE accept() ---
    # Read token directly from upgrade headers (available before accept).
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("WS auth failed: missing or malformed Authorization header")
        await websocket.close(code=_WS_CLOSE_REVOKED)
        return

    token = auth_header[len("Bearer "):]
    try:
        jwt_payload = await verify_jwt(token, store)
    except Exception as exc:
        detail = getattr(exc, "detail", {})
        error = detail.get("error", "") if isinstance(detail, dict) else str(detail)
        close_code = _WS_CLOSE_EXPIRED if error == "token_expired" else _WS_CLOSE_REVOKED
        logger.warning("WS auth failed: %s", error)
        await websocket.close(code=close_code)
        return

    if jwt_payload.get("role") != "agent":
        logger.warning(
            "WS auth failed: role is not agent (got %s)", jwt_payload.get("role")
        )
        await websocket.close(code=_WS_CLOSE_REVOKED)
        return

    hostname: str = jwt_payload["sub"]

    # --- Step 2: accept connection only after successful auth ---
    await websocket.accept()

    # Close and replace any existing connection for this hostname (reconnect case)
    old_ws = ws_connections.get(hostname)
    if old_ws is not None:
        logger.info("Replacing stale WS for hostname", extra={"hostname": hostname})
        try:
            await old_ws.close(code=_WS_CLOSE_NORMAL)
        except Exception:
            pass  # already closed

    ws_connections[hostname] = websocket
    await store.update_agent_status(hostname, "connected", _now_iso())
    logger.info("Agent connected", extra={"hostname": hostname})

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(
                    "Invalid JSON from agent",
                    extra={"hostname": hostname, "raw": raw[:200]},
                )
                continue

            await _handle_message(msg, hostname, store)

    finally:
        # Cleanup on disconnect (normal or abnormal)
        ws_connections.pop(hostname, None)
        await store.update_agent_status(hostname, "disconnected", _now_iso())
        _resolve_futures_for_hostname(hostname, "agent_disconnected")
        logger.info("Agent disconnected", extra={"hostname": hostname})


# ---------------------------------------------------------------------------
# Public API for other modules (routes_exec)
# ---------------------------------------------------------------------------

async def send_to_agent(hostname: str, message: dict) -> None:
    """
    Send a JSON message to a connected agent over its WebSocket.

    Also registers the task_id → hostname mapping so that futures can be
    resolved on disconnection.

    Args:
        hostname: Target agent hostname.
        message:  Dict to serialise as JSON and send.

    Raises:
        AgentOfflineError: If no active WebSocket exists for the hostname.
    """
    ws = ws_connections.get(hostname)
    if ws is None:
        raise AgentOfflineError(hostname)

    task_id = message.get("task_id")
    if task_id:
        _task_hostname[task_id] = hostname

    await ws.send_text(json.dumps(message))


def register_future(task_id: str, hostname: str) -> asyncio.Future:
    """
    Create and register an asyncio Future for a task result.

    The Future is resolved by _handle_message() when the agent sends a
    ``result`` message, or by _resolve_futures_for_hostname() on disconnect.

    Args:
        task_id:  Unique task identifier.
        hostname: Agent hostname — used to resolve on disconnect.

    Returns:
        asyncio.Future that will be resolved with the result payload dict.
    """
    loop = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()
    pending_futures[task_id] = fut
    _task_hostname[task_id] = hostname
    return fut


def cancel_future(task_id: str) -> None:
    """
    Cancel and remove a pending future without resolving it.

    Used when the server sends a ``cancel`` message after a timeout and the
    agent result arrives — the future is already handled by the timeout path.

    Args:
        task_id: Task identifier.
    """
    fut = pending_futures.pop(task_id, None)
    if fut and not fut.done():
        fut.cancel()
    stdout_buffers.pop(task_id, None)
    _task_hostname.pop(task_id, None)


# ---------------------------------------------------------------------------
# ConnectionManager — typed facade (referenced by other route modules)
# ---------------------------------------------------------------------------

class ConnectionManager:
    """
    Typed facade over the module-level ws_connections registry.

    Provides the connect / disconnect / send_message / broadcast interface
    expected by routes_exec and other consumers.

    All methods delegate to the module-level dicts and functions so there is
    a single source of truth for connection state.
    """

    @property
    def active_connections(self) -> dict[str, WebSocket]:
        """Dict of hostname -> active WebSocket (live view, not a copy)."""
        return ws_connections

    async def connect(self, hostname: str, websocket: WebSocket) -> None:
        """
        Register a WebSocket for a hostname, closing any existing one.

        Args:
            hostname:  Agent hostname.
            websocket: Accepted WebSocket connection.
        """
        old = ws_connections.get(hostname)
        if old is not None:
            try:
                await old.close(code=_WS_CLOSE_NORMAL)
            except Exception:
                pass
        ws_connections[hostname] = websocket

    def disconnect(self, hostname: str) -> None:
        """
        Remove a hostname from the active connections registry.

        Does not close the socket — caller is responsible for the close frame.

        Args:
            hostname: Agent hostname to remove.
        """
        ws_connections.pop(hostname, None)
        _resolve_futures_for_hostname(hostname, "agent_disconnected")

    async def send_message(self, hostname: str, message: dict) -> None:
        """
        Send a JSON message to a specific agent.

        Args:
            hostname: Target agent hostname.
            message:  Dict to serialise as JSON.

        Raises:
            AgentOfflineError: If no active WebSocket for the hostname.
        """
        await send_to_agent(hostname, message)

    async def broadcast(self, message: dict) -> None:
        """
        Send a JSON message to every connected agent.

        Errors on individual connections are logged and skipped so that a
        single dead socket does not prevent delivery to others.

        Args:
            message: Dict to serialise as JSON and broadcast.
        """
        text = json.dumps(message)
        dead: list[str] = []
        for hostname, ws in list(ws_connections.items()):
            try:
                await ws.send_text(text)
            except Exception as exc:
                logger.warning(
                    "Broadcast failed for agent",
                    extra={"hostname": hostname, "error": str(exc)},
                )
                dead.append(hostname)
        for hostname in dead:
            ws_connections.pop(hostname, None)


# Module-level singleton — import and use directly:  from ws_handler import connection_manager
connection_manager = ConnectionManager()
