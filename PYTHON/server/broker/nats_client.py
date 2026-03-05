"""
nats_client.py — NATS JetStream client for AnsibleRelay relay server.

Responsibilities:
  - Connect to a NATS server and ensure JetStream streams are created
  - Publish task messages to RELAY_TASKS (subject: tasks.{hostname})
  - Subscribe to RELAY_TASKS to deliver tasks to agents via WebSocket
  - Publish task results to RELAY_RESULTS (subject: results.{task_id})
  - Subscribe to RELAY_RESULTS to resolve pending futures in routes_exec

Streams (ARCHITECTURE.md §5):
  RELAY_TASKS   subjects: tasks.{hostname}   WorkQueue  TTL 5min  MaxMsg 1MB
  RELAY_RESULTS subjects: results.{task_id}  Limits     TTL 60s   MaxMsg 5MB

HA routing: this node subscribes to ALL tasks.* subjects and forwards only
those whose hostname has an active WebSocket on THIS node.  Tasks for agents
on other nodes are NAcked immediately so NATS delivers to the correct node.

SECURITY NOTE (H-1):
  NATS messages may contain the `stdin` field with a base64-encoded become_pass.
  In the current implementation NATS transport is plaintext within the Docker
  Compose network.  This is acceptable for the qualification environment where
  the internal network is isolated.

  PRODUCTION REQUIREMENT: mTLS MUST be enabled on all NATS connections before
  deploying to a multi-tenant or untrusted network.  Configure via:
    - NATS server: --tls --tlscert --tlskey --tlscacert --tlsverify
    - NatsClient: pass tls=ssl.SSLContext to nats.connect()
  Failure to enable mTLS exposes become_pass in transit over NATS.
  See ARCHITECTURE.md §7 (Sécurité) for the full security requirements.

Usage (from main.py lifespan):
    client = NatsClient(nats_url, ws_handler_module)
    await client.connect()
    ...
    await client.close()
"""

import asyncio
import json
import logging
import os
from typing import Any, Callable, Coroutine, Optional

import nats
from nats.aio.client import Client as NatsConnection
from nats.js.api import (
    AckPolicy,
    ConsumerConfig,
    RetentionPolicy,
    StorageType,
    StreamConfig,
)
from nats.js.errors import NotFoundError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stream configuration constants — ARCHITECTURE.md §5
# ---------------------------------------------------------------------------

_STREAM_TASKS = "RELAY_TASKS"
_STREAM_RESULTS = "RELAY_RESULTS"
_SUBJECT_TASKS = "tasks.*"           # wildcard — subscribe to all hostnames
_SUBJECT_RESULTS = "results.*"       # wildcard — subscribe to all task results

_TASKS_TTL_S    = 300      # 5 minutes in seconds (NATS max_age uses seconds)
_RESULTS_TTL_S  = 60       # 60 seconds (NATS max_age uses seconds)
_TASKS_MAX_BYTES   = 1 * 1024 * 1024    # 1 MB per message
_RESULTS_MAX_BYTES = 5 * 1024 * 1024    # 5 MB per message


def _get_nats_url() -> str:
    return os.environ.get("NATS_URL", "nats://localhost:4222")


# ---------------------------------------------------------------------------
# NatsClient
# ---------------------------------------------------------------------------

class NatsClient:
    """
    Async NATS JetStream client for the relay server.

    Args:
        nats_url:      NATS server URL (e.g. "nats://nats:4222").
        ws_send_fn:    Async callable send_to_agent(hostname, message) from ws_handler.
        result_fn:     Async callable invoked when a result message arrives for
                       a task_id that has a pending future.  Signature:
                       result_fn(task_id, payload) -> None.
        node_id:       Optional node identifier for logging (hostname of this server).
    """

    def __init__(
        self,
        nats_url: Optional[str] = None,
        ws_send_fn: Optional[Callable] = None,
        result_fn: Optional[Callable] = None,
        node_id: str = "relay-server",
    ) -> None:
        self._nats_url = nats_url or _get_nats_url()
        self._ws_send_fn = ws_send_fn
        self._result_fn = result_fn
        self._node_id = node_id
        self._nc: Optional[NatsConnection] = None
        self._js: Any = None
        self._subscriptions: list = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Connect to NATS, ensure streams exist, and start subscriptions.

        Safe to call once per process — idempotent if already connected.
        """
        if self._nc is not None:
            return

        logger.info("Connecting to NATS", extra={"url": self._nats_url})
        self._nc = await nats.connect(
            self._nats_url,
            name=self._node_id,
            reconnect_time_wait=2,
            max_reconnect_attempts=-1,   # reconnect forever
            error_cb=self._on_error,
            disconnected_cb=self._on_disconnected,
            reconnected_cb=self._on_reconnected,
        )
        self._js = self._nc.jetstream()

        await self._ensure_streams()

        if self._ws_send_fn is not None:
            try:
                await self._subscribe_tasks()
            except Exception as e:
                # If consumer already exists (from another instance), that's OK
                if "consumer name already in use" not in str(e):
                    raise
                logger.debug("Tasks consumer already exists (shared lifespan)", extra={"error": str(e)})

        if self._result_fn is not None:
            try:
                await self._subscribe_results()
            except Exception as e:
                # If consumer already exists (from another instance), that's OK
                if "consumer name already in use" not in str(e):
                    raise
                logger.debug("Results consumer already exists (shared lifespan)", extra={"error": str(e)})

        logger.info("NATS client ready", extra={"node": self._node_id})

    async def close(self) -> None:
        """Drain and close the NATS connection gracefully."""
        if self._nc and not self._nc.is_closed:
            await self._nc.drain()
            logger.info("NATS connection closed", extra={"node": self._node_id})
        self._nc = None
        self._js = None

    # ------------------------------------------------------------------
    # Stream management
    # ------------------------------------------------------------------

    async def _ensure_streams(self) -> None:
        """Create RELAY_TASKS and RELAY_RESULTS streams if they do not exist."""
        await self._ensure_stream(
            name=_STREAM_TASKS,
            subjects=["tasks.*"],
            retention=RetentionPolicy.WORK_QUEUE,
            max_age=_TASKS_TTL_S,
            max_msg_size=_TASKS_MAX_BYTES,
        )
        await self._ensure_stream(
            name=_STREAM_RESULTS,
            subjects=["results.*"],
            retention=RetentionPolicy.LIMITS,
            max_age=_RESULTS_TTL_S,
            max_msg_size=_RESULTS_MAX_BYTES,
        )

    async def _ensure_stream(
        self,
        name: str,
        subjects: list[str],
        retention: RetentionPolicy,
        max_age: int,
        max_msg_size: int,
    ) -> None:
        """Create a JetStream stream if it does not already exist."""
        try:
            await self._js.stream_info(name)
            logger.debug("NATS stream already exists", extra={"stream": name})
        except NotFoundError:
            cfg = StreamConfig(
                name=name,
                subjects=subjects,
                retention=retention,
                max_age=max_age,
                max_msg_size=max_msg_size,
                storage=StorageType.FILE,
                num_replicas=1,   # 1 for MVP/qualif; 3 for production K8s
            )
            await self._js.add_stream(cfg)
            logger.info("NATS stream created", extra={"stream": name})

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish_task(self, hostname: str, payload: dict) -> None:
        """
        Publish a task to RELAY_TASKS for a specific agent hostname.

        Subject: tasks.{hostname}
        The message is a JSON-serialised task payload.

        Args:
            hostname: Target agent hostname.
            payload:  Task dict — must contain at minimum task_id and type.
        """
        subject = f"tasks.{hostname}"
        data = json.dumps(payload).encode()
        ack = await self._js.publish(subject, data)
        logger.debug(
            "Task published to NATS",
            extra={"subject": subject, "seq": ack.seq, "task_id": payload.get("task_id")},
        )

    async def publish_result(self, task_id: str, payload: dict) -> None:
        """
        Publish a task result to RELAY_RESULTS.

        Subject: results.{task_id}
        Called by ws_handler after receiving a ``result`` message from an agent.

        Args:
            task_id: Task identifier.
            payload: Result dict (rc, stdout, stderr, truncated, error...).
        """
        subject = f"results.{task_id}"
        data = json.dumps(payload).encode()
        ack = await self._js.publish(subject, data)
        logger.debug(
            "Result published to NATS",
            extra={"subject": subject, "seq": ack.seq, "task_id": task_id},
        )

    # ------------------------------------------------------------------
    # Subscribe — tasks (server → agent via WebSocket)
    # ------------------------------------------------------------------

    async def _subscribe_tasks(self) -> None:
        """
        Subscribe to tasks.* — deliver matching tasks to local agent WebSockets.

        WorkQueue policy: each message is delivered to exactly one subscriber
        across the NATS cluster.  If THIS node has the target agent's WS, it
        ACKs and forwards.  If not, it NAKs immediately so another node can
        handle it.

        MaxDeliver: 1 — no silent retry (ARCHITECTURE.md §5).
        """
        consumer_name = f"relay-server-{self._node_id}-tasks"
        cfg = ConsumerConfig(
            durable_name=consumer_name,
            ack_policy=AckPolicy.EXPLICIT,
            max_deliver=1,
            filter_subject=_SUBJECT_TASKS,
        )
        sub = await self._js.subscribe(
            _SUBJECT_TASKS,
            config=cfg,
            cb=self._on_task_message,
            manual_ack=True,
        )
        self._subscriptions.append(sub)
        logger.info("Subscribed to NATS tasks.*", extra={"consumer": consumer_name})

    async def _on_task_message(self, msg) -> None:
        """
        Callback for incoming task messages from NATS.

        Attempts to forward the task to the agent via ws_handler.send_to_agent().
        ACKs if the agent is connected on this node; NAKs otherwise so the
        message can be delivered by another relay node.
        """
        try:
            payload = json.loads(msg.data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("Failed to decode NATS task message: %s", exc)
            await msg.ack()  # bad message — discard to avoid redelivery loop
            return

        # Extract hostname from subject: tasks.{hostname}
        hostname = msg.subject.split(".", 1)[1] if "." in msg.subject else ""

        if not hostname:
            logger.error("Malformed task subject", extra={"subject": msg.subject})
            await msg.ack()
            return

        if self._ws_send_fn is None:
            await msg.nak()
            return

        try:
            await self._ws_send_fn(hostname, payload)
            await msg.ack()
            logger.debug(
                "Task delivered to agent",
                extra={"hostname": hostname, "task_id": payload.get("task_id")},
            )
        except Exception as exc:
            # Agent not connected on this node — NAK so another node can handle
            logger.debug(
                "Agent not on this node, NAK task",
                extra={"hostname": hostname, "error": str(exc)},
            )
            await msg.nak()

    # ------------------------------------------------------------------
    # Subscribe — results (agent → waiting route handler)
    # ------------------------------------------------------------------

    async def _subscribe_results(self) -> None:
        """
        Subscribe to results.* — deliver results to pending asyncio Futures.

        Used in the HA routing case where the result is published by another
        relay node (the one holding the agent WS) and consumed by this node
        (the one that received the original POST /api/exec request).
        """
        consumer_name = f"relay-server-{self._node_id}-results"
        cfg = ConsumerConfig(
            durable_name=consumer_name,
            ack_policy=AckPolicy.EXPLICIT,
            max_deliver=1,
            filter_subject=_SUBJECT_RESULTS,
        )
        sub = await self._js.subscribe(
            _SUBJECT_RESULTS,
            config=cfg,
            cb=self._on_result_message,
            manual_ack=True,
        )
        self._subscriptions.append(sub)
        logger.info("Subscribed to NATS results.*", extra={"consumer": consumer_name})

    async def _on_result_message(self, msg) -> None:
        """
        Callback for incoming result messages from NATS.

        Invokes the result_fn callback (which resolves the pending asyncio Future
        in routes_exec) if this node has a pending future for the task_id.
        ACKs always — results are single-delivery.
        """
        try:
            payload = json.loads(msg.data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("Failed to decode NATS result message: %s", exc)
            await msg.ack()
            return

        # Extract task_id from subject: results.{task_id}
        task_id = msg.subject.split(".", 1)[1] if "." in msg.subject else ""

        await msg.ack()

        if self._result_fn and task_id:
            try:
                await self._result_fn(task_id, payload)
            except Exception as exc:
                logger.warning(
                    "result_fn raised for task",
                    extra={"task_id": task_id, "error": str(exc)},
                )

    # ------------------------------------------------------------------
    # Public subscribe / wait API (used by routes_exec and HA routing)
    # ------------------------------------------------------------------

    async def subscribe_task(
        self,
        hostname: str,
        callback: Callable[..., Coroutine],
    ) -> None:
        """
        Subscribe to task messages for a specific hostname.

        Intended for server-side HA routing: a relay node subscribes to
        tasks.{hostname} so it can forward tasks to agents connected locally.
        The callback receives the decoded payload dict.

        Args:
            hostname: Agent hostname to subscribe for.
            callback: Async callable invoked with (payload: dict) per message.
        """
        subject = f"tasks.{hostname}"
        consumer_name = f"relay-{self._node_id}-{hostname}"

        async def _cb(msg) -> None:
            try:
                payload = json.loads(msg.data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.error("Bad JSON in task message: %s", exc)
                await msg.ack()
                return
            try:
                await callback(payload)
                await msg.ack()
            except Exception as exc:
                logger.debug("subscribe_task callback failed, NAK: %s", exc)
                await msg.nak()

        cfg = ConsumerConfig(
            durable_name=consumer_name,
            ack_policy=AckPolicy.EXPLICIT,
            max_deliver=1,
            filter_subject=subject,
        )
        sub = await self._js.subscribe(subject, config=cfg, cb=_cb, manual_ack=True)
        self._subscriptions.append(sub)
        logger.info(
            "Subscribed to tasks for hostname",
            extra={"subject": subject, "consumer": consumer_name},
        )

    async def wait_for_result(self, task_id: str, timeout: float) -> dict:
        """
        Subscribe to results.{task_id} and wait for the first message.

        This method subscribes BEFORE the task is published so that the result
        is never missed — even in the HA case where the agent is on another node.

        Args:
            task_id: Task identifier — must match the task published via publish_task.
            timeout: Maximum seconds to wait. Raises asyncio.TimeoutError on expiry.

        Returns:
            Decoded result payload dict.

        Raises:
            asyncio.TimeoutError: If no result arrives within the timeout period.
        """
        subject = f"results.{task_id}"
        fut: asyncio.Future = asyncio.get_event_loop().create_future()

        async def _cb(msg) -> None:
            try:
                payload = json.loads(msg.data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.error("Bad JSON in result message: %s", exc)
                await msg.ack()
                return
            await msg.ack()
            if not fut.done():
                fut.set_result(payload)

        # Use an ephemeral (non-durable) push consumer for single-use wait
        sub = await self._js.subscribe(subject, cb=_cb, manual_ack=True)
        try:
            result = await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        finally:
            try:
                await sub.unsubscribe()
            except Exception:
                pass
        return result

    async def purge_stream(self, stream_name: str) -> None:
        """
        Purge all messages from a JetStream stream.

        Intended for development and testing only — clears all pending
        messages without deleting the stream configuration.

        Args:
            stream_name: Name of the stream to purge (e.g. "RELAY_TASKS").
        """
        await self._js.purge_stream(stream_name)
        logger.info("Stream purged", extra={"stream": stream_name})

    # ------------------------------------------------------------------
    # NATS connection event callbacks
    # ------------------------------------------------------------------

    async def _on_error(self, exc: Exception) -> None:
        logger.error("NATS error: %s", exc)

    async def _on_disconnected(self) -> None:
        logger.warning("NATS disconnected — reconnecting...")

    async def _on_reconnected(self) -> None:
        logger.info("NATS reconnected")
