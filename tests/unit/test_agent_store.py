"""
test_agent_store.py — Unit tests for server/db/agent_store.py

Uses an in-memory SQLite database (:memory:) so tests run fast and in isolation.
No disk I/O, no external dependencies.
"""

import sys
import os
import pytest
import pytest_asyncio

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server.db.agent_store import AgentStore, init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def store():
    """Fresh in-memory AgentStore for each test."""
    s = AgentStore(":memory:")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# TestInit — initialisation and idempotency
# ---------------------------------------------------------------------------

class TestInit:
    async def test_init_creates_tables(self, store):
        """After init(), all required tables exist."""
        async with store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) as cur:
            rows = await cur.fetchall()
        names = {r[0] for r in rows}
        assert "agents" in names
        assert "authorized_keys" in names
        assert "blacklist" in names

    async def test_init_idempotent(self):
        """Calling init() twice on the same path does not raise."""
        s = AgentStore(":memory:")
        await s.init()
        await s.init()   # second call — tables already exist, should be no-op
        await s.close()

    async def test_init_db_convenience(self):
        """Module-level init_db() returns an initialised store."""
        s = await init_db(":memory:")
        assert s._conn is not None
        await s.close()


# ---------------------------------------------------------------------------
# TestAuthorizedKeys — pre-enrollment key management
# ---------------------------------------------------------------------------

class TestAuthorizedKeys:
    async def test_get_authorized_key_returns_none_when_absent(self, store):
        result = await store.get_authorized_key("nonexistent-host")
        assert result is None

    async def test_authorize_key_then_get_round_trip(self, store):
        await store.authorize_key("host-A", "pem-content-A", "terraform-pipeline")
        rec = await store.get_authorized_key("host-A")
        assert rec is not None
        assert rec["hostname"] == "host-A"
        assert rec["public_key_pem"] == "pem-content-A"
        assert rec["approved_by"] == "terraform-pipeline"
        assert rec["approved_at"] is not None

    async def test_add_authorized_key_alias(self, store):
        """add_authorized_key() is an alias for authorize_key()."""
        await store.add_authorized_key("host-B", "pem-B", "ci-bot")
        rec = await store.get_authorized_key("host-B")
        assert rec is not None
        assert rec["hostname"] == "host-B"

    async def test_authorize_key_upsert_updates_existing(self, store):
        """Re-authorizing the same hostname updates the entry."""
        await store.authorize_key("host-C", "pem-original", "admin")
        await store.authorize_key("host-C", "pem-updated", "new-admin")
        rec = await store.get_authorized_key("host-C")
        assert rec["public_key_pem"] == "pem-updated"
        assert rec["approved_by"] == "new-admin"

    async def test_revoke_key_removes_entry(self, store):
        await store.authorize_key("host-D", "pem-D", "admin")
        deleted = await store.revoke_key("host-D")
        assert deleted is True
        assert await store.get_authorized_key("host-D") is None

    async def test_revoke_key_returns_false_when_absent(self, store):
        result = await store.revoke_key("ghost-host")
        assert result is False


# ---------------------------------------------------------------------------
# TestAgents — enrolled agent registry
# ---------------------------------------------------------------------------

class TestAgents:
    async def test_get_agent_returns_none_when_absent(self, store):
        assert await store.get_agent("unknown-host") is None

    async def test_register_agent_then_get_round_trip(self, store):
        await store.register_agent("host-1", "pem-1", "jti-abc")
        agent = await store.get_agent("host-1")
        assert agent is not None
        assert agent["hostname"] == "host-1"
        assert agent["public_key_pem"] == "pem-1"
        assert agent["token_jti"] == "jti-abc"
        assert agent["status"] == "disconnected"

    async def test_upsert_agent_alias(self, store):
        """upsert_agent() is an alias for register_agent()."""
        await store.upsert_agent("host-2", "pem-2", "jti-2")
        agent = await store.get_agent("host-2")
        assert agent is not None
        assert agent["token_jti"] == "jti-2"

    async def test_register_agent_upserts_on_conflict(self, store):
        """Re-registering same hostname updates the row."""
        await store.register_agent("host-3", "pem-3", "jti-3a")
        await store.register_agent("host-3", "pem-3-new", "jti-3b")
        agent = await store.get_agent("host-3")
        assert agent["public_key_pem"] == "pem-3-new"
        assert agent["token_jti"] == "jti-3b"

    async def test_list_agents_empty(self, store):
        result = await store.list_agents()
        assert result == []

    async def test_list_agents_returns_all(self, store):
        await store.register_agent("host-A", "pem-A", "jti-A")
        await store.register_agent("host-B", "pem-B", "jti-B")
        result = await store.list_agents()
        assert len(result) == 2
        hostnames = {r["hostname"] for r in result}
        assert hostnames == {"host-A", "host-B"}

    async def test_list_agents_only_connected_filters(self, store):
        """list_agents(only_connected=True) returns only status='connected'."""
        await store.register_agent("host-online", "pem-x", "jti-x")
        await store.register_agent("host-offline", "pem-y", "jti-y")
        # Mark host-online as connected
        await store.set_agent_status("host-online", "connected")
        result = await store.list_agents(only_connected=True)
        assert len(result) == 1
        assert result[0]["hostname"] == "host-online"

    async def test_list_agents_all_returns_both_statuses(self, store):
        await store.register_agent("host-on", "pem-on", "jti-on")
        await store.register_agent("host-off", "pem-off", "jti-off")
        await store.set_agent_status("host-on", "connected")
        result = await store.list_agents(only_connected=False)
        assert len(result) == 2

    async def test_update_last_seen_sets_status_connected(self, store):
        await store.register_agent("host-seen", "pem-s", "jti-s")
        updated = await store.update_last_seen("host-seen")
        assert updated is True
        agent = await store.get_agent("host-seen")
        assert agent["status"] == "connected"
        assert agent["last_seen"] is not None

    async def test_update_last_seen_returns_false_for_unknown(self, store):
        result = await store.update_last_seen("ghost-host")
        assert result is False

    async def test_set_agent_status_disconnected(self, store):
        await store.register_agent("host-stat", "pem-st", "jti-st")
        await store.set_agent_status("host-stat", "connected")
        await store.set_agent_status("host-stat", "disconnected")
        agent = await store.get_agent("host-stat")
        assert agent["status"] == "disconnected"

    async def test_update_agent_status_alias(self, store):
        """update_agent_status() updates status and optionally last_seen."""
        await store.register_agent("host-upd", "pem-upd", "jti-upd")
        await store.update_agent_status("host-upd", "connected", "2024-01-01T00:00:00+00:00")
        agent = await store.get_agent("host-upd")
        assert agent["status"] == "connected"
        assert "2024-01-01" in agent["last_seen"]

    async def test_update_token_jti(self, store):
        await store.register_agent("host-tok", "pem-tok", "jti-old")
        updated = await store.update_token_jti("host-tok", "jti-new")
        assert updated is True
        agent = await store.get_agent("host-tok")
        assert agent["token_jti"] == "jti-new"

    async def test_update_token_jti_returns_false_for_unknown(self, store):
        result = await store.update_token_jti("ghost", "jti-x")
        assert result is False


# ---------------------------------------------------------------------------
# TestBlacklist — JWT revocation
# ---------------------------------------------------------------------------

class TestBlacklist:
    async def test_is_jti_blacklisted_returns_false_initially(self, store):
        result = await store.is_jti_blacklisted("fresh-jti")
        assert result is False

    async def test_add_to_blacklist_then_check(self, store):
        """After adding a JTI to blacklist, is_jti_blacklisted returns True."""
        await store.add_to_blacklist(
            jti="revoked-jti",
            hostname="host-Z",
            expires_at="2099-01-01T00:00:00+00:00",
            reason="test",
        )
        assert await store.is_jti_blacklisted("revoked-jti") is True

    async def test_blacklist_other_jti_unaffected(self, store):
        await store.add_to_blacklist(
            jti="jti-1",
            hostname="host-1",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        assert await store.is_jti_blacklisted("jti-2") is False

    async def test_add_to_blacklist_idempotent(self, store):
        """Adding the same JTI twice does not raise (ON CONFLICT DO NOTHING)."""
        await store.add_to_blacklist("dup-jti", "host-dup", "2099-01-01T00:00:00+00:00")
        await store.add_to_blacklist("dup-jti", "host-dup", "2099-01-01T00:00:00+00:00")
        assert await store.is_jti_blacklisted("dup-jti") is True

    async def test_purge_expired_blacklist_removes_old_entries(self, store):
        """Entries with expires_at in the past are removed by purge."""
        await store.add_to_blacklist(
            jti="expired-jti",
            hostname="host-exp",
            expires_at="2000-01-01T00:00:00+00:00",   # past
        )
        await store.add_to_blacklist(
            jti="valid-jti",
            hostname="host-valid",
            expires_at="2099-01-01T00:00:00+00:00",   # future
        )
        deleted = await store.purge_expired_blacklist()
        assert deleted == 1
        assert await store.is_jti_blacklisted("expired-jti") is False
        assert await store.is_jti_blacklisted("valid-jti") is True

    async def test_cleanup_expired_blacklist_alias(self, store):
        """cleanup_expired_blacklist() is an alias for purge_expired_blacklist()."""
        await store.add_to_blacklist("old-jti", "h", "2000-01-01T00:00:00+00:00")
        deleted = await store.cleanup_expired_blacklist()
        assert deleted == 1

    async def test_purge_with_no_expired_entries_returns_zero(self, store):
        deleted = await store.purge_expired_blacklist()
        assert deleted == 0

    async def test_add_to_blacklist_without_reason(self, store):
        """reason parameter is optional — None is accepted."""
        await store.add_to_blacklist(
            jti="no-reason-jti",
            hostname="host-nr",
            expires_at="2099-01-01T00:00:00+00:00",
            reason=None,
        )
        assert await store.is_jti_blacklisted("no-reason-jti") is True
