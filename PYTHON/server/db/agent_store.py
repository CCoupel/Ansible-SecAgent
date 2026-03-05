"""
agent_store.py — SQLite persistence layer for AnsibleRelay server.

Tables:
  - agents          : enrolled agents (hostname PK, public_key, token_jti, timestamps, status)
  - authorized_keys : pre-authorized public keys (set by CI/CD before agent boot)
  - blacklist       : revoked JWT identifiers

All writes use explicit transactions for ACID guarantees.
Schema matches ARCHITECTURE.md §20 exactly.
"""

import aiosqlite
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# SQL DDL — matches ARCHITECTURE.md §20 schema exactly
_DDL = """
CREATE TABLE IF NOT EXISTS agents (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    token_jti       TEXT,
    enrolled_at     TIMESTAMP,
    last_seen       TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'disconnected'
);

CREATE TABLE IF NOT EXISTS authorized_keys (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    approved_at     TIMESTAMP NOT NULL,
    approved_by     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    jti             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    revoked_at      TIMESTAMP NOT NULL,
    reason          TEXT,
    expires_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist (expires_at);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (status);
"""


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


class AgentStore:
    """
    Async SQLite store for relay server agent state.

    Usage:
        store = AgentStore("/data/relay.db")
        await store.init()
        ...
        await store.close()

    All public methods are async and safe for concurrent use within a single
    asyncio event loop (aiosqlite serialises writes internally).
    """

    def __init__(self, db_path: str = "/data/relay.db") -> None:
        self._db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def init(self) -> None:
        """
        Open the SQLite connection and create tables if they do not exist.

        Creates parent directories if needed (useful for Docker volume mounts).
        """
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        # Enable WAL for better concurrency under read-heavy workloads
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.executescript(_DDL)
        await self._conn.commit()
        logger.info("AgentStore initialised", extra={"db": self._db_path})

    async def close(self) -> None:
        """Close the database connection cleanly."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # authorized_keys — pre-enrollment (called by CI/CD pipeline)
    # ------------------------------------------------------------------

    async def authorize_key(self, hostname: str, public_key_pem: str, approved_by: str) -> bool:
        """
        Pre-authorize a public key for a hostname before the agent boots.

        Called via POST /api/admin/authorize (pipeline CI/CD).
        Inserts or replaces the authorized key entry.

        Args:
            hostname:       Target hostname (e.g. "host-A").
            public_key_pem: RSA public key in PEM format.
            approved_by:    Identifier of the authorizing entity (e.g. "terraform-pipeline").

        Returns:
            True on success.
        """
        now = _now_iso()
        async with self._conn.execute(
            """
            INSERT INTO authorized_keys (hostname, public_key_pem, approved_at, approved_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                public_key_pem = excluded.public_key_pem,
                approved_at    = excluded.approved_at,
                approved_by    = excluded.approved_by
            """,
            (hostname, public_key_pem, now, approved_by),
        ):
            pass
        await self._conn.commit()
        logger.info("Key authorized", extra={"hostname": hostname, "approved_by": approved_by})
        return True

    async def get_authorized_key(self, hostname: str) -> Optional[dict]:
        """
        Fetch the authorized key entry for a hostname.

        Used during enrollment to verify the agent's public key.

        Args:
            hostname: Target hostname.

        Returns:
            Dict with fields {hostname, public_key_pem, approved_at, approved_by}
            or None if not found.
        """
        async with self._conn.execute(
            "SELECT hostname, public_key_pem, approved_at, approved_by "
            "FROM authorized_keys WHERE hostname = ?",
            (hostname,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def revoke_key(self, hostname: str) -> bool:
        """
        Remove the authorized key for a hostname (prevents future enrollment).

        Args:
            hostname: Target hostname.

        Returns:
            True if a row was deleted, False if the hostname was not found.
        """
        async with self._conn.execute(
            "DELETE FROM authorized_keys WHERE hostname = ?",
            (hostname,),
        ) as cursor:
            deleted = cursor.rowcount > 0
        await self._conn.commit()
        if deleted:
            logger.info("Authorized key revoked", extra={"hostname": hostname})
        return deleted

    # ------------------------------------------------------------------
    # agents — enrolled agent registry
    # ------------------------------------------------------------------

    async def register_agent(
        self,
        hostname: str,
        public_key_pem: str,
        token_jti: str,
    ) -> str:
        """
        Register or re-enroll an agent after successful key verification.

        Inserts the agent row on first enrollment; updates public_key, token_jti
        and enrolled_at on re-enrollment (same hostname, new key).

        Args:
            hostname:       Agent hostname (becomes the primary key).
            public_key_pem: RSA public key presented at enrollment.
            token_jti:      JTI of the JWT issued for this enrollment.

        Returns:
            The hostname (acts as agent identifier in this schema).
        """
        now = _now_iso()
        await self._conn.execute(
            """
            INSERT INTO agents (hostname, public_key_pem, token_jti, enrolled_at, last_seen, status)
            VALUES (?, ?, ?, ?, ?, 'disconnected')
            ON CONFLICT(hostname) DO UPDATE SET
                public_key_pem = excluded.public_key_pem,
                token_jti      = excluded.token_jti,
                enrolled_at    = excluded.enrolled_at,
                last_seen      = excluded.last_seen
            """,
            (hostname, public_key_pem, token_jti, now, now),
        )
        await self._conn.commit()
        logger.info("Agent registered", extra={"hostname": hostname, "jti": token_jti})
        return hostname

    async def get_agent(self, hostname: str) -> Optional[dict]:
        """
        Retrieve a registered agent by hostname.

        Args:
            hostname: Agent hostname.

        Returns:
            Dict with fields {hostname, public_key_pem, token_jti, enrolled_at,
            last_seen, status} or None if not found.
        """
        async with self._conn.execute(
            "SELECT hostname, public_key_pem, token_jti, enrolled_at, last_seen, status "
            "FROM agents WHERE hostname = ?",
            (hostname,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def list_agents(self, only_connected: bool = False) -> list[dict]:
        """
        Return all agents, optionally filtered to connected ones.

        Args:
            only_connected: If True, returns only agents with status='connected'.

        Returns:
            List of agent dicts.
        """
        if only_connected:
            query = (
                "SELECT hostname, public_key_pem, token_jti, enrolled_at, last_seen, status "
                "FROM agents WHERE status = 'connected'"
            )
            params: tuple = ()
        else:
            query = (
                "SELECT hostname, public_key_pem, token_jti, enrolled_at, last_seen, status "
                "FROM agents"
            )
            params = ()

        async with self._conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def update_last_seen(self, hostname: str) -> bool:
        """
        Update the last_seen timestamp and set status to 'connected'.

        Called when the agent opens its WebSocket connection.

        Args:
            hostname: Agent hostname.

        Returns:
            True if the agent was found and updated, False otherwise.
        """
        now = _now_iso()
        async with self._conn.execute(
            "UPDATE agents SET last_seen = ?, status = 'connected' WHERE hostname = ?",
            (now, hostname),
        ) as cursor:
            updated = cursor.rowcount > 0
        await self._conn.commit()
        return updated

    async def set_agent_status(self, hostname: str, status: str) -> bool:
        """
        Set the connection status of an agent.

        Valid status values: 'connected', 'disconnected'.

        Args:
            hostname: Agent hostname.
            status:   New status string.

        Returns:
            True if the agent was found and updated, False otherwise.
        """
        async with self._conn.execute(
            "UPDATE agents SET status = ? WHERE hostname = ?",
            (status, hostname),
        ) as cursor:
            updated = cursor.rowcount > 0
        await self._conn.commit()
        return updated

    async def update_token_jti(self, hostname: str, token_jti: str) -> bool:
        """
        Update the active token JTI for an agent (token refresh).

        Args:
            hostname:   Agent hostname.
            token_jti:  New JWT JTI.

        Returns:
            True if the agent was found and updated, False otherwise.
        """
        async with self._conn.execute(
            "UPDATE agents SET token_jti = ? WHERE hostname = ?",
            (token_jti, hostname),
        ) as cursor:
            updated = cursor.rowcount > 0
        await self._conn.commit()
        return updated

    # ------------------------------------------------------------------
    # blacklist — revoked JWT identifiers
    # ------------------------------------------------------------------

    async def add_to_blacklist(
        self,
        jti: str,
        hostname: str,
        expires_at: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Add a JWT identifier to the revocation blacklist.

        Called during agent revocation. The entry is cleaned up automatically
        once expires_at has passed (via purge_expired_blacklist).

        Args:
            jti:        JWT identifier to blacklist.
            hostname:   Hostname of the agent whose token is revoked.
            expires_at: ISO 8601 timestamp — when the entry can be purged.
            reason:     Optional human-readable reason for revocation.

        Returns:
            True on success.
        """
        now = _now_iso()
        await self._conn.execute(
            """
            INSERT INTO blacklist (jti, hostname, revoked_at, reason, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO NOTHING
            """,
            (jti, hostname, now, reason, expires_at),
        )
        await self._conn.commit()
        logger.info(
            "JTI blacklisted",
            extra={"jti": jti, "hostname": hostname, "reason": reason},
        )
        return True

    async def is_jti_blacklisted(self, jti: str) -> bool:
        """
        Check whether a JWT identifier is in the revocation blacklist.

        Args:
            jti: JWT identifier to check.

        Returns:
            True if the JTI is blacklisted, False otherwise.
        """
        async with self._conn.execute(
            "SELECT 1 FROM blacklist WHERE jti = ?",
            (jti,),
        ) as cursor:
            row = await cursor.fetchone()
            return row is not None

    async def purge_expired_blacklist(self) -> int:
        """
        Remove blacklist entries whose expires_at is in the past.

        Should be called periodically (e.g. on startup or by a background task)
        to keep the blacklist table small.

        Returns:
            Number of rows deleted.
        """
        now = _now_iso()
        async with self._conn.execute(
            "DELETE FROM blacklist WHERE expires_at <= ?",
            (now,),
        ) as cursor:
            deleted = cursor.rowcount
        await self._conn.commit()
        if deleted:
            logger.info("Blacklist entries purged", extra={"count": deleted})
        return deleted

    # ------------------------------------------------------------------
    # Aliases — alternate method names used by routes / test-writer
    # ------------------------------------------------------------------

    async def add_authorized_key(
        self, hostname: str, public_key_pem: str, approved_by: str
    ) -> None:
        """Alias for authorize_key() — adds or updates an authorized key."""
        await self.authorize_key(hostname, public_key_pem, approved_by)

    async def upsert_agent(
        self, hostname: str, public_key_pem: str, jti: str
    ) -> None:
        """Alias for register_agent() — insert or update an agent row."""
        await self.register_agent(hostname, public_key_pem, jti)

    async def update_agent_status(
        self, hostname: str, status: str, last_seen: Optional[str] = None
    ) -> None:
        """
        Update agent status and optionally last_seen timestamp.

        Args:
            hostname:  Agent hostname.
            status:    'connected' or 'disconnected'.
            last_seen: ISO 8601 timestamp; defaults to now if not provided.
        """
        ts = last_seen if last_seen is not None else _now_iso()
        await self._conn.execute(
            "UPDATE agents SET status = ?, last_seen = ? WHERE hostname = ?",
            (status, ts, hostname),
        )
        await self._conn.commit()

    async def cleanup_expired_blacklist(self) -> int:
        """Alias for purge_expired_blacklist()."""
        return await self.purge_expired_blacklist()


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

async def init_db(db_path: str) -> "AgentStore":
    """
    Create and initialise an AgentStore at the given path.

    Idempotent — safe to call multiple times; tables are created only if absent.

    Args:
        db_path: Filesystem path for the SQLite database file.

    Returns:
        An initialised AgentStore instance ready for use.
    """
    store = AgentStore(db_path)
    await store.init()
    return store
