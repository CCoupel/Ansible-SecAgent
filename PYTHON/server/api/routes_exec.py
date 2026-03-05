"""
routes_exec.py — Task execution endpoints for the relay server.

Endpoints:
    POST /api/exec/{hostname}          — Execute a command on a remote agent (blocking)
    POST /api/upload/{hostname}        — Transfer a file to a remote agent
    POST /api/fetch/{hostname}         — Retrieve a file from a remote agent
    GET  /api/async_status/{task_id}   — Poll result of an in-flight or completed task

Auth: Bearer JWT with role "plugin" on all endpoints (require_role dependency).

Flow (ARCHITECTURE.md §8):
    1. Verify agent is connected in ws_connections → 503 if not
    2. Register an asyncio.Future for the task result
    3. Publish task to NATS tasks.{hostname} (HA: any relay node can receive it)
    4. Block on asyncio.wait_for(future, timeout + margin)
    5. Resolve result → HTTP 200, or error → 504 / 500 / 429

Security:
    - stdin is NOT logged when become=True (ARCHITECTURE.md §7, §12)
    - All payloads validated by Pydantic before processing
"""

import asyncio
import base64
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from server.api.routes_register import require_role
from server.api.ws_handler import (
    AgentOfflineError,
    cancel_future,
    register_future,
    send_to_agent,
    ws_connections,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# 500 KB decoded limit for file transfers (ARCHITECTURE.md §11)
_FILE_MAX_BYTES = 500 * 1024

# Extra seconds added on top of the task timeout before the server gives up
_TIMEOUT_MARGIN_S = 5


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ExecRequest(BaseModel):
    task_id: Optional[str] = None       # caller may supply; generated if absent
    cmd: str
    stdin: Optional[str] = None         # base64 encoded, or null
    timeout: int = 30
    become: bool = False
    become_method: str = "sudo"

    @field_validator("cmd")
    @classmethod
    def cmd_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("cmd must not be empty")
        return v

    @field_validator("timeout")
    @classmethod
    def timeout_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("timeout must be positive")
        return v


class UploadRequest(BaseModel):
    task_id: Optional[str] = None
    dest: str
    data: str       # base64-encoded file content
    mode: str = "0644"

    @field_validator("dest")
    @classmethod
    def dest_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("dest must not be empty")
        return v


class FetchRequest(BaseModel):
    task_id: Optional[str] = None
    src: str

    @field_validator("src")
    @classmethod
    def src_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("src must not be empty")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_task_id() -> str:
    return str(uuid.uuid4())


def _now_ts() -> int:
    return int(time.time())


def _check_agent_online(hostname: str) -> None:
    """
    Raise HTTP 503 immediately if the agent has no active WebSocket.

    Args:
        hostname: Target agent hostname.
    """
    if hostname not in ws_connections:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "agent_offline"},
        )


def _decode_result(result: dict, hostname: str, task_id: str) -> dict:
    """
    Interpret a result dict returned by an agent and raise the appropriate
    HTTP error if needed.

    Args:
        result:   Result payload from the agent or disconnection error.
        hostname: Agent hostname (for logging).
        task_id:  Task identifier (for logging).

    Returns:
        Clean result dict on success.

    Raises:
        HTTPException 500 — agent disconnected mid-task.
        HTTPException 429 — agent busy (rc == -1).
    """
    error = result.get("error")
    if error == "agent_disconnected":
        logger.warning(
            "Agent disconnected during task",
            extra={"hostname": hostname, "task_id": task_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "agent_disconnected"},
        )

    rc = result.get("rc")
    if rc == -1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "agent_busy", "running_tasks": result.get("running_tasks")},
        )

    return result


async def _wait_for_result(
    task_id: str,
    hostname: str,
    timeout: float,
) -> dict:
    """
    Wait for an asyncio Future to be resolved by the WebSocket handler.

    Raises HTTP 504 on timeout (after sending a WS cancel to the agent).

    Args:
        task_id:  Task identifier.
        hostname: Target agent hostname.
        timeout:  Total seconds to wait (task timeout + margin already applied).

    Returns:
        Result payload dict.
    """
    fut = pending_futures_ref(task_id)
    try:
        result = await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
    except asyncio.TimeoutError:
        # Cancel the future locally and send cancel to agent
        cancel_future(task_id)
        try:
            await send_to_agent(hostname, {"task_id": task_id, "type": "cancel"})
        except AgentOfflineError:
            pass  # Agent already gone — cancel is best-effort
        logger.warning(
            "Task timed out",
            extra={"task_id": task_id, "hostname": hostname, "timeout": timeout},
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={"error": "timeout"},
        )

    return result


def pending_futures_ref(task_id: str):
    """Return the Future registered for task_id, or raise 500 if missing."""
    from server.api.ws_handler import pending_futures
    fut = pending_futures.get(task_id)
    if fut is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        )
    return fut


def _log_exec_safe(hostname: str, task_id: str, body: ExecRequest) -> None:
    """Log exec request — mask stdin when become=True (ARCHITECTURE.md §7)."""
    stdin_log = "***REDACTED***" if body.become and body.stdin else body.stdin
    logger.info(
        "Exec request",
        extra={
            "hostname": hostname,
            "task_id": task_id,
            "cmd": body.cmd,
            "become": body.become,
            "stdin": stdin_log,
            "timeout": body.timeout,
        },
    )


# ---------------------------------------------------------------------------
# POST /api/exec/{hostname}
# ---------------------------------------------------------------------------

@router.post(
    "/api/exec/{hostname}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("plugin"))],
    summary="Execute a command on a remote agent (blocking)",
)
async def exec_command(
    hostname: str,
    body: ExecRequest,
    request: Request,
) -> dict:
    """
    Send a command to a connected agent and wait for the result.

    The call blocks until the agent returns a result or the timeout expires.

    HTTP 503 — agent not connected.
    HTTP 504 — agent did not respond within timeout.
    HTTP 500 — agent disconnected mid-task.
    HTTP 429 — agent too busy (max_concurrent_tasks reached).
    HTTP 200 — { rc, stdout, stderr, truncated }.
    """
    _check_agent_online(hostname)

    task_id = body.task_id or _new_task_id()
    now = _now_ts()

    _log_exec_safe(hostname, task_id, body)

    # Register Future BEFORE publishing to NATS (avoid race condition)
    register_future(task_id, hostname)

    message = {
        "task_id": task_id,
        "type": "exec",
        "cmd": body.cmd,
        "stdin": body.stdin,
        "timeout": body.timeout,
        "become": body.become,
        "become_method": body.become_method,
        "expires_at": now + body.timeout,
    }

    # Publish via NATS (HA: another relay node may hold the agent WS)
    nats_client = getattr(request.app.state, "nats_client", None)
    if nats_client is not None:
        # SECURITY (H-1): strip stdin from the NATS payload when become=True.
        # stdin may contain become_pass (base64) which must not transit NATS
        # in plaintext.  The agent will treat absent stdin as None (no password).
        # mTLS on NATS is required in production — see nats_client.py SECURITY NOTE.
        nats_message = {**message}
        if body.become:
            nats_message.pop("stdin", None)
        await nats_client.publish_task(hostname, nats_message)
    else:
        # Fallback: direct WS send (single-node / tests without NATS)
        # stdin is kept here — no network transit, same process memory.
        try:
            await send_to_agent(hostname, message)
        except AgentOfflineError:
            cancel_future(task_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "agent_offline"},
            )

    # Block until result or timeout (task timeout + margin)
    result = await _wait_for_result(task_id, hostname, body.timeout + _TIMEOUT_MARGIN_S)
    result = _decode_result(result, hostname, task_id)

    return {
        "rc": result.get("rc"),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "truncated": result.get("truncated", False),
    }


# ---------------------------------------------------------------------------
# POST /api/upload/{hostname}
# ---------------------------------------------------------------------------

@router.post(
    "/api/upload/{hostname}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("plugin"))],
    summary="Transfer a file to a remote agent",
)
async def upload_file(
    hostname: str,
    body: UploadRequest,
    request: Request,
) -> dict:
    """
    Upload a base64-encoded file to the agent's filesystem.

    HTTP 413 — decoded file exceeds 500 KB.
    HTTP 503 — agent not connected.
    HTTP 500 — agent disconnected mid-transfer.
    HTTP 200 — { rc: 0 }.
    """
    _check_agent_online(hostname)

    # Validate decoded size before sending
    try:
        decoded = base64.b64decode(body.data)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_base64"},
        )
    if len(decoded) > _FILE_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"error": "payload_too_large", "max_bytes": _FILE_MAX_BYTES},
        )

    task_id = body.task_id or _new_task_id()
    logger.info(
        "Upload request",
        extra={"hostname": hostname, "task_id": task_id, "dest": body.dest, "size": len(decoded)},
    )

    register_future(task_id, hostname)

    message = {
        "task_id": task_id,
        "type": "put_file",
        "dest": body.dest,
        "data": body.data,
        "mode": body.mode,
    }

    nats_client = getattr(request.app.state, "nats_client", None)
    if nats_client is not None:
        await nats_client.publish_task(hostname, message)
    else:
        try:
            await send_to_agent(hostname, message)
        except AgentOfflineError:
            cancel_future(task_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "agent_offline"},
            )

    # Use a generous timeout for file transfers (same margin)
    result = await _wait_for_result(task_id, hostname, 60 + _TIMEOUT_MARGIN_S)
    result = _decode_result(result, hostname, task_id)

    return {"rc": result.get("rc", 0)}


# ---------------------------------------------------------------------------
# POST /api/fetch/{hostname}
# ---------------------------------------------------------------------------

@router.post(
    "/api/fetch/{hostname}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("plugin"))],
    summary="Retrieve a file from a remote agent",
)
async def fetch_file(
    hostname: str,
    body: FetchRequest,
    request: Request,
) -> dict:
    """
    Fetch a file from the agent's filesystem as base64-encoded content.

    HTTP 503 — agent not connected.
    HTTP 500 — agent disconnected mid-fetch.
    HTTP 200 — { rc: 0, data: "<base64>" }.
    """
    _check_agent_online(hostname)

    task_id = body.task_id or _new_task_id()
    logger.info(
        "Fetch request",
        extra={"hostname": hostname, "task_id": task_id, "src": body.src},
    )

    register_future(task_id, hostname)

    message = {
        "task_id": task_id,
        "type": "fetch_file",
        "src": body.src,
    }

    nats_client = getattr(request.app.state, "nats_client", None)
    if nats_client is not None:
        await nats_client.publish_task(hostname, message)
    else:
        try:
            await send_to_agent(hostname, message)
        except AgentOfflineError:
            cancel_future(task_id)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "agent_offline"},
            )

    result = await _wait_for_result(task_id, hostname, 60 + _TIMEOUT_MARGIN_S)
    result = _decode_result(result, hostname, task_id)

    return {
        "rc": result.get("rc", 0),
        "data": result.get("data", ""),
    }


# ---------------------------------------------------------------------------
# In-memory result cache — stores completed task results for async_status
# Keyed by task_id; entries are set by exec_command / result handlers.
# ---------------------------------------------------------------------------

# task_id -> result dict (rc, stdout, stderr, truncated, status)
_completed_results: dict[str, dict] = {}


def store_result(task_id: str, result: dict) -> None:
    """
    Store a completed task result for later retrieval via async_status.

    Args:
        task_id: Task identifier.
        result:  Result payload from the agent.
    """
    _completed_results[task_id] = {**result, "status": "finished"}


# ---------------------------------------------------------------------------
# GET /api/async_status/{task_id}
# ---------------------------------------------------------------------------

@router.get(
    "/api/async_status/{task_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("plugin"))],
    summary="Poll the status of an async task",
)
async def async_status(task_id: str) -> dict:
    """
    Return the current status of a task by task_id.

    If the task result has been stored (finished), returns it immediately.
    If the task future is still pending, returns status='running'.
    If the task is unknown (never started or expired), returns HTTP 404.

    Response:
        { task_id, status: "running"|"finished", rc, stdout, stderr, truncated }

    HTTP 404 — task_id not found.
    """
    from server.api.ws_handler import pending_futures

    # Check completed cache first
    if task_id in _completed_results:
        r = _completed_results[task_id]
        return {
            "task_id": task_id,
            "status": "finished",
            "rc": r.get("rc"),
            "stdout": r.get("stdout", ""),
            "stderr": r.get("stderr", ""),
            "truncated": r.get("truncated", False),
        }

    # Check if still running (future registered but not resolved)
    if task_id in pending_futures:
        fut = pending_futures[task_id]
        if not fut.done():
            return {
                "task_id": task_id,
                "status": "running",
                "rc": None,
                "stdout": "",
                "stderr": "",
                "truncated": False,
            }
        # Future done but not in cache → resolve now
        try:
            result = fut.result()
            store_result(task_id, result)
            return {
                "task_id": task_id,
                "status": "finished",
                "rc": result.get("rc"),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "truncated": result.get("truncated", False),
            }
        except asyncio.CancelledError:
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail={"error": "task_cancelled"},
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": "task_not_found"},
    )
