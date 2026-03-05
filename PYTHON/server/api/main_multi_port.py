"""
main_multi_port.py — Multi-port FastAPI launcher for AnsibleRelay.

Launches 3 independent FastAPI instances on separate ports:
  - Port 7770 : Client (enrollment + WSS)
  - Port 7771 : Plugin connection (exec/upload/fetch)
  - Port 7772 : Inventory plugin

Each instance shares:
  - Shared database (AgentStore)
  - Shared NATS client
  - Shared state (WebSocket connections, pending futures, etc.)

Usage:
    python -m hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 &
    python -m hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 &
    python -m hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response
from pydantic_settings import BaseSettings, SettingsConfigDict

from server.api import routes_exec, routes_inventory, routes_register, ws_handler
from server.broker.nats_client import NatsClient
from server.db.agent_store import AgentStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    nats_url: str = "nats://localhost:4222"
    database_url: str = "sqlite:////data/relay.db"
    jwt_secret_key: str  # required
    admin_token: str  # required
    log_level: str = "INFO"
    jwt_ttl_seconds: int = 3600


def _db_path_from_url(database_url: str) -> str:
    if database_url.startswith("sqlite:////"):
        return database_url[len("sqlite:///"):]
    if database_url.startswith("sqlite:///"):
        return database_url[len("sqlite:///"):]
    raise ValueError(f"Unsupported DATABASE_URL scheme: {database_url!r}")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


# ---------------------------------------------------------------------------
# Shared lifespan (startup/shutdown) — runs only once
# ---------------------------------------------------------------------------

_db_initialized = False
_nats_initialized = False
_shutdown_called = False


@asynccontextmanager
async def shared_lifespan(app: FastAPI):
    """
    Shared lifespan for all 3 app instances.

    Only initializes DB and NATS once (first app startup).
    Shutdown happens when all apps are stopped.
    """
    global _db_initialized, _nats_initialized, _shutdown_called

    settings: Settings = app.state.settings

    # ---- Startup (first app only) ----
    if not _db_initialized:
        _configure_logging(settings.log_level)

        # Database
        db_path = _db_path_from_url(settings.database_url)
        store = AgentStore(db_path)
        await store.init()
        await store.purge_expired_blacklist()
        app.state.store = store
        logger.info("Database ready", extra={"path": db_path})
        _db_initialized = True

        # NATS
        nats_client = NatsClient(
            nats_url=settings.nats_url,
            ws_send_fn=ws_handler.send_to_agent,
            result_fn=_on_nats_result,
            node_id="relay-server",
        )
        try:
            await nats_client.connect()
            app.state.nats_client = nats_client
            logger.info("NATS connected", extra={"url": settings.nats_url})
            _nats_initialized = True
        except Exception as exc:
            logger.warning("NATS unavailable at startup: %s", exc)
            app.state.nats_client = None

        logger.info("AnsibleRelay multi-port server started")

    yield  # application runs here

    # ---- Shutdown ----
    if not _shutdown_called:
        _shutdown_called = True
        logger.info("Shutting down AnsibleRelay server...")

        # Close all active WebSocket connections gracefully
        hostnames = list(ws_handler.ws_connections.keys())
        close_tasks = []
        for hostname in hostnames:
            ws = ws_handler.ws_connections.get(hostname)
            if ws is not None:
                close_tasks.append(_close_ws(hostname, ws))
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)
        logger.info("WebSocket connections closed", extra={"count": len(hostnames)})

        # Disconnect NATS
        nats_client = getattr(app.state, "nats_client", None)
        if nats_client is not None:
            try:
                await nats_client.close()
            except Exception as exc:
                logger.warning("NATS close error: %s", exc)

        # Close DB
        store = getattr(app.state, "store", None)
        if store is not None:
            await store.close()

        logger.info("Shutdown complete")


async def _close_ws(hostname: str, ws) -> None:
    try:
        await ws.close(code=4000)
    except Exception:
        pass
    ws_handler.ws_connections.pop(hostname, None)


async def _on_nats_result(task_id: str, payload: dict) -> None:
    from server.api.ws_handler import pending_futures
    fut = pending_futures.get(task_id)
    if fut and not fut.done():
        fut.set_result(payload)
        logger.debug("Future resolved via NATS result", extra={"task_id": task_id})
    routes_exec.store_result(task_id, payload)


# ---------------------------------------------------------------------------
# Health check endpoint
# ---------------------------------------------------------------------------

def _add_health_endpoint(app: FastAPI) -> None:
    @app.get("/health", tags=["ops"], summary="Health check")
    async def health(request: Request) -> dict:
        db_status = "ok"
        nats_status = "ok"

        store: Optional[AgentStore] = getattr(request.app.state, "store", None)
        if store is None or store._conn is None:
            db_status = "unavailable"
        else:
            try:
                await store._conn.execute("SELECT 1")
            except Exception:
                db_status = "error"

        nats_client = getattr(request.app.state, "nats_client", None)
        if nats_client is None:
            nats_status = "unavailable"
        elif nats_client._nc is None or nats_client._nc.is_closed:
            nats_status = "disconnected"

        overall = "ok" if db_status == "ok" and nats_status in ("ok", "unavailable") else "degraded"

        return {
            "status": overall,
            "db": db_status,
            "nats": nats_status,
        }

    return app


# ---------------------------------------------------------------------------
# Logging middleware
# ---------------------------------------------------------------------------

def _add_logging_middleware(app: FastAPI) -> None:
    import time

    @app.middleware("http")
    async def log_requests(request: Request, call_next) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "HTTP %s %s %s %dms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response


# ---------------------------------------------------------------------------
# App factory with role-based router inclusion
# ---------------------------------------------------------------------------

def create_app_client(settings: Optional[Settings] = None) -> FastAPI:
    """
    Create FastAPI app for Port 7770 (Client enrollment + WSS).

    Routes:
      - POST /api/register       (enrollment)
      - GET  /ws/agent           (WebSocket)
      - GET  /health             (health check)
    """
    if settings is None:
        settings = Settings()

    app = FastAPI(
        title="AnsibleRelay — Client (Port 7770)",
        description="Agent enrollment and WebSocket",
        version="1.0.0",
        lifespan=shared_lifespan,
    )

    app.state.settings = settings
    app.state.store = None
    app.state.nats_client = None

    # Include only client routes
    app.include_router(routes_register.router)
    app.include_router(ws_handler.router)

    _add_logging_middleware(app)
    _add_health_endpoint(app)

    return app


def create_app_plugin(settings: Optional[Settings] = None) -> FastAPI:
    """
    Create FastAPI app for Port 7771 (Plugin connection).

    Routes:
      - POST /api/exec/{host}    (execute command)
      - POST /api/upload/{host}  (put file)
      - POST /api/fetch/{host}   (get file)
      - GET  /health             (health check)
    """
    if settings is None:
        settings = Settings()

    app = FastAPI(
        title="AnsibleRelay — Plugin Connection (Port 7771)",
        description="Plugin exec/upload/fetch endpoints",
        version="1.0.0",
        lifespan=shared_lifespan,
    )

    app.state.settings = settings
    app.state.store = None
    app.state.nats_client = None

    # Include only plugin routes
    app.include_router(routes_exec.router)

    _add_logging_middleware(app)
    _add_health_endpoint(app)

    return app


def create_app_inventory(settings: Optional[Settings] = None) -> FastAPI:
    """
    Create FastAPI app for Port 7772 (Inventory plugin).

    Routes:
      - GET /api/inventory       (inventory JSON)
      - GET /health              (health check)
    """
    if settings is None:
        settings = Settings()

    app = FastAPI(
        title="AnsibleRelay — Inventory (Port 7772)",
        description="Dynamic inventory endpoint",
        version="1.0.0",
        lifespan=shared_lifespan,
    )

    app.state.settings = settings
    app.state.store = None
    app.state.nats_client = None

    # Include only inventory routes
    app.include_router(routes_inventory.router)

    _add_logging_middleware(app)
    _add_health_endpoint(app)

    return app


# ---------------------------------------------------------------------------
# Module-level app instances (used by hypercorn)
# ---------------------------------------------------------------------------

try:
    app_client = create_app_client()
    app_plugin = create_app_plugin()
    app_inventory = create_app_inventory()
except Exception as exc:
    import sys
    print(
        f"ERROR: Failed to create FastAPI apps: {exc}\n"
        "Required env vars: JWT_SECRET_KEY, ADMIN_TOKEN",
        file=sys.stderr,
    )
    raise
