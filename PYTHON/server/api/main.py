"""
main.py — FastAPI application entry point for the AnsibleRelay relay server.

Assembles all components:
  - FastAPI app with lifespan (startup / shutdown)
  - Routers: routes_register, routes_exec, routes_inventory, ws_handler
  - SQLite DB initialisation via AgentStore
  - NATS JetStream client connect/disconnect
  - Request logging middleware (tokens redacted)
  - Health check endpoint

Launch:
    uvicorn server.api.main:app --host 0.0.0.0 --port 8443

Configuration via environment variables (see Settings class below).
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings, SettingsConfigDict

from server.api import routes_exec, routes_inventory, routes_register, ws_handler
from server.broker.nats_client import NatsClient
from server.db.agent_store import AgentStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings — read from environment variables
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    """
    Relay server configuration.

    All values are read from environment variables.
    A .env file is loaded if present (useful for local dev).
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    nats_url: str = "nats://localhost:4222"
    database_url: str = "sqlite:////data/relay.db"
    jwt_secret_key: str                          # required — no default
    admin_token: str                             # required — no default

    # TLS terminated by Caddy in Docker Compose — optional for direct TLS
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None

    # Logging
    log_level: str = "INFO"

    # JWT TTL (seconds)
    jwt_ttl_seconds: int = 3600


def _db_path_from_url(database_url: str) -> str:
    """
    Extract the filesystem path from a SQLite URL.

    Handles both:
      sqlite:////absolute/path/relay.db  (4 slashes — absolute UNIX path)
      sqlite:///relative/path/relay.db   (3 slashes — relative path)
    """
    if database_url.startswith("sqlite:////"):
        return database_url[len("sqlite:///"):]    # keep leading /
    if database_url.startswith("sqlite:///"):
        return database_url[len("sqlite:///"):]
    raise ValueError(f"Unsupported DATABASE_URL scheme: {database_url!r}")


# ---------------------------------------------------------------------------
# Lifespan — startup and shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async context manager for application startup and graceful shutdown.

    Startup:
      1. Configure logging.
      2. Initialise SQLite database (create tables if absent).
      3. Connect to NATS JetStream (ensure streams exist, start subscribers).
      4. Store references on app.state for use by route handlers.

    Shutdown:
      1. Close all active agent WebSocket connections cleanly.
      2. Disconnect from NATS.
      3. Close the database connection.
    """
    settings: Settings = app.state.settings
    _configure_logging(settings.log_level)

    # ---- 1. Database ----
    db_path = _db_path_from_url(settings.database_url)
    store = AgentStore(db_path)
    await store.init()
    await store.purge_expired_blacklist()
    app.state.store = store
    logger.info("Database ready", extra={"path": db_path})

    # ---- 2. NATS ----
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
    except Exception as exc:
        logger.warning(
            "NATS unavailable at startup — running without NATS (single-node mode): %s",
            exc,
        )
        app.state.nats_client = None

    logger.info("AnsibleRelay server started")

    yield  # application runs here

    # ---- Shutdown ----
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
    if app.state.nats_client is not None:
        try:
            await app.state.nats_client.close()
        except Exception as exc:
            logger.warning("NATS close error: %s", exc)

    # Close DB
    await store.close()
    logger.info("Shutdown complete")


async def _close_ws(hostname: str, ws) -> None:
    """Close a single WebSocket connection with code 4000 (normal)."""
    try:
        await ws.close(code=4000)
    except Exception:
        pass
    ws_handler.ws_connections.pop(hostname, None)


async def _on_nats_result(task_id: str, payload: dict) -> None:
    """
    Called by NatsClient when a result message arrives from NATS.

    Resolves the pending asyncio.Future in ws_handler so that the blocking
    POST /api/exec handler can return to the plugin caller.
    Also caches the result for GET /api/async_status.
    """
    from server.api.ws_handler import pending_futures

    fut = pending_futures.get(task_id)
    if fut and not fut.done():
        fut.set_result(payload)
        logger.debug("Future resolved via NATS result", extra={"task_id": task_id})

    routes_exec.store_result(task_id, payload)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        settings: Optional Settings instance (useful for testing).
                  If None, Settings() is constructed from environment.

    Returns:
        Configured FastAPI application.
    """
    if settings is None:
        settings = Settings()

    app = FastAPI(
        title="AnsibleRelay Server",
        description="Relay server for executing Ansible playbooks via reverse WebSocket connections",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Store settings on app.state for access in lifespan and routes
    app.state.settings = settings
    app.state.store = None       # set during lifespan startup
    app.state.nats_client = None

    # ---- Routers ----
    app.include_router(routes_register.router)
    app.include_router(routes_exec.router)
    app.include_router(routes_inventory.router)
    app.include_router(ws_handler.router)

    # ---- Middleware ----
    _add_logging_middleware(app)

    # ---- Health check ----
    _add_health_endpoint(app)

    return app


# ---------------------------------------------------------------------------
# Logging middleware — redacts Authorization headers
# ---------------------------------------------------------------------------

def _add_logging_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def log_requests(request: Request, call_next) -> Response:
        start = time.monotonic()
        # Never log Authorization header value — may contain JWT or admin token
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
# Health check endpoint
# ---------------------------------------------------------------------------

def _add_health_endpoint(app: FastAPI) -> None:
    @app.get("/health", tags=["ops"], summary="Health check")
    async def health(request: Request) -> dict:
        """
        Return server health status.

        Checks:
          - DB: verifies the SQLite connection is alive.
          - NATS: verifies the client is connected.

        Returns:
            { status, db, nats }

        HTTP 200 always — callers should inspect the individual component fields.
        """
        db_status = "ok"
        nats_status = "ok"

        # DB check — simple query
        store: Optional[AgentStore] = getattr(request.app.state, "store", None)
        if store is None or store._conn is None:
            db_status = "unavailable"
        else:
            try:
                await store._conn.execute("SELECT 1")
            except Exception:
                db_status = "error"

        # NATS check
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


# ---------------------------------------------------------------------------
# Module-level app instance (used by uvicorn)
# ---------------------------------------------------------------------------

try:
    app = create_app()
except Exception as exc:
    # Provide a helpful message if required env vars are missing
    import sys
    print(
        f"ERROR: Failed to create FastAPI app: {exc}\n"
        "Required env vars: JWT_SECRET_KEY, ADMIN_TOKEN",
        file=sys.stderr,
    )
    raise
