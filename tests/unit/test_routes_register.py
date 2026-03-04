"""
test_routes_register.py — Unit tests for server/api/routes_register.py

Uses httpx AsyncClient + FastAPI's test transport so no real HTTP server is started.
All database calls use an in-memory SQLite store.
JWT_SECRET_KEY and ADMIN_TOKEN are injected via environment variables.
"""

import asyncio
import base64
import os
import sys
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from server.db.agent_store import AgentStore
from server.api import routes_register

# ---------------------------------------------------------------------------
# Env vars required by routes_register at import time
# ---------------------------------------------------------------------------
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token-for-unit-tests-only")

JWT_SECRET = os.environ["JWT_SECRET_KEY"]
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]
JWT_ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# RSA key pair helpers (generate once per module for speed)
# ---------------------------------------------------------------------------

def _gen_rsa_keypair():
    """Generate a 4096-bit RSA key pair for testing.

    Must match production key size — RSA-OAEP/SHA-256 with 2048-bit keys cannot
    encrypt JWTs longer than 190 bytes (typical JWT is ~230+ bytes).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_key, public_pem


_AGENT_PRIVATE_KEY, _AGENT_PUBLIC_PEM = _gen_rsa_keypair()


def _decrypt_jwt(token_encrypted_b64: str) -> dict:
    """Decrypt a base64+RSA-OAEP encrypted JWT with the test agent private key."""
    ciphertext = base64.b64decode(token_encrypted_b64)
    raw_jwt = _AGENT_PRIVATE_KEY.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ).decode()
    return jose_jwt.decode(raw_jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ---------------------------------------------------------------------------
# App fixture — minimal FastAPI app with the register router and an in-memory store
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def app_with_store():
    """FastAPI app with in-memory store, no lifespan (we set state manually)."""
    store = AgentStore(":memory:")
    await store.init()

    app = FastAPI()
    app.include_router(routes_register.router)
    app.state.store = store
    app.state.nats_client = None

    yield app, store

    await store.close()


@pytest_asyncio.fixture
async def client(app_with_store):
    app, store = app_with_store
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, store


# ---------------------------------------------------------------------------
# TestAdminAuthorize — POST /api/admin/authorize
# ---------------------------------------------------------------------------

class TestAdminAuthorize:
    async def test_authorize_success_returns_201(self, client):
        c, store = client
        resp = await c.post(
            "/api/admin/authorize",
            json={
                "hostname": "host-new",
                "public_key_pem": _AGENT_PUBLIC_PEM,
                "approved_by": "terraform",
            },
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["hostname"] == "host-new"
        assert body["status"] == "authorized"

    async def test_authorize_persists_key_in_store(self, client):
        c, store = client
        await c.post(
            "/api/admin/authorize",
            json={
                "hostname": "host-persist",
                "public_key_pem": _AGENT_PUBLIC_PEM,
                "approved_by": "ci",
            },
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        rec = await store.get_authorized_key("host-persist")
        assert rec is not None
        assert rec["approved_by"] == "ci"

    async def test_authorize_wrong_token_returns_401(self, client):
        c, store = client
        resp = await c.post(
            "/api/admin/authorize",
            json={
                "hostname": "host-X",
                "public_key_pem": "pem",
                "approved_by": "admin",
            },
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "invalid_admin_token"

    async def test_authorize_missing_token_returns_401(self, client):
        c, store = client
        resp = await c.post(
            "/api/admin/authorize",
            json={
                "hostname": "host-Y",
                "public_key_pem": "pem",
                "approved_by": "admin",
            },
        )
        assert resp.status_code == 401

    async def test_authorize_idempotent(self, client):
        """Authorizing the same hostname twice updates the entry — no 409."""
        c, store = client
        payload = {
            "hostname": "host-idem",
            "public_key_pem": _AGENT_PUBLIC_PEM,
            "approved_by": "admin",
        }
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        r1 = await c.post("/api/admin/authorize", json=payload, headers=headers)
        r2 = await c.post("/api/admin/authorize", json=payload, headers=headers)
        assert r1.status_code == 201
        assert r2.status_code == 201


# ---------------------------------------------------------------------------
# TestRegister — POST /api/register
# ---------------------------------------------------------------------------

class TestRegister:
    async def _authorize_host(self, store, hostname, pem=None):
        pem = pem or _AGENT_PUBLIC_PEM
        await store.add_authorized_key(hostname, pem, "test-setup")

    async def test_register_success_returns_200(self, client):
        c, store = client
        await self._authorize_host(store, "host-reg1")
        resp = await c.post(
            "/api/register",
            json={"hostname": "host-reg1", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "token_encrypted" in body
        assert "server_public_key_pem" in body

    async def test_register_token_is_decryptable_and_valid(self, client):
        """The returned encrypted token decrypts to a valid JWT for the hostname."""
        c, store = client
        await self._authorize_host(store, "host-dec")
        resp = await c.post(
            "/api/register",
            json={"hostname": "host-dec", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert resp.status_code == 200
        payload = _decrypt_jwt(resp.json()["token_encrypted"])
        assert payload["sub"] == "host-dec"
        assert payload["role"] == "agent"
        assert "jti" in payload

    async def test_register_hostname_not_authorized_returns_403(self, client):
        c, store = client
        resp = await c.post(
            "/api/register",
            json={"hostname": "unauthorized-host", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "hostname_not_authorized"

    async def test_register_public_key_mismatch_returns_403(self, client):
        """Submitting a different key than the authorized one returns 403."""
        c, store = client
        _, other_pem = _gen_rsa_keypair()
        await self._authorize_host(store, "host-mismatch", pem=_AGENT_PUBLIC_PEM)
        resp = await c.post(
            "/api/register",
            json={"hostname": "host-mismatch", "public_key_pem": other_pem},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "public_key_mismatch"

    async def test_register_idempotent_same_key_returns_200(self, client):
        """Re-enrollment with the same key is allowed — returns 200 again."""
        c, store = client
        await self._authorize_host(store, "host-reidm")
        payload = {"hostname": "host-reidm", "public_key_pem": _AGENT_PUBLIC_PEM}
        r1 = await c.post("/api/register", json=payload)
        r2 = await c.post("/api/register", json=payload)
        assert r1.status_code == 200
        assert r2.status_code == 200

    async def test_register_conflict_different_key_returns_409(self, client):
        """Re-enrollment with a DIFFERENT key after enrollment returns 409."""
        c, store = client
        _, other_pem = _gen_rsa_keypair()
        # Authorize and enroll with original key
        await self._authorize_host(store, "host-conflict", pem=_AGENT_PUBLIC_PEM)
        r1 = await c.post(
            "/api/register",
            json={"hostname": "host-conflict", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert r1.status_code == 200

        # Now change the authorized key to the other one and try to re-enroll
        await store.add_authorized_key("host-conflict", other_pem, "admin")
        # But the enrolled record still has the old key — different key → 409
        # Manually insert a different key into agents table to simulate the conflict
        await store._conn.execute(
            "UPDATE agents SET public_key_pem = ? WHERE hostname = ?",
            ("different-pem-value", "host-conflict"),
        )
        await store._conn.commit()

        # Re-authorize with original key but enrolled record has different key
        await store.add_authorized_key("host-conflict", _AGENT_PUBLIC_PEM, "admin")
        r2 = await c.post(
            "/api/register",
            json={"hostname": "host-conflict", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "hostname_conflict"

    async def test_register_empty_hostname_returns_422(self, client):
        c, store = client
        resp = await c.post(
            "/api/register",
            json={"hostname": "   ", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert resp.status_code == 422

    async def test_register_empty_pem_returns_422(self, client):
        c, store = client
        resp = await c.post(
            "/api/register",
            json={"hostname": "host-epem", "public_key_pem": "   "},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# TestTokenRefresh — POST /api/token/refresh
# ---------------------------------------------------------------------------

class TestTokenRefresh:
    async def _enroll_host(self, c, store, hostname):
        """Helper: authorize + register a host, return the decrypted JWT payload."""
        await store.add_authorized_key(hostname, _AGENT_PUBLIC_PEM, "test")
        resp = await c.post(
            "/api/register",
            json={"hostname": hostname, "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        assert resp.status_code == 200
        return _decrypt_jwt(resp.json()["token_encrypted"])

    def _make_challenge(self, server_public_pem: str) -> str:
        """Create a valid challenge: random bytes encrypted with server public key."""
        server_pub = serialization.load_pem_public_key(server_public_pem.encode())
        challenge_bytes = os.urandom(32)
        ciphertext = server_pub.encrypt(
            challenge_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ciphertext).decode()

    async def test_token_refresh_success(self, client):
        """Valid challenge returns a new encrypted JWT."""
        c, store = client
        # Enroll host first
        await store.add_authorized_key("host-refresh", _AGENT_PUBLIC_PEM, "test")
        reg_resp = await c.post(
            "/api/register",
            json={"hostname": "host-refresh", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        server_pub_pem = reg_resp.json()["server_public_key_pem"]

        challenge = self._make_challenge(server_pub_pem)
        resp = await c.post(
            "/api/token/refresh",
            json={"hostname": "host-refresh", "challenge_encrypted": challenge},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "token_encrypted" in body
        # New token should decrypt and be valid
        new_payload = _decrypt_jwt(body["token_encrypted"])
        assert new_payload["sub"] == "host-refresh"
        assert new_payload["role"] == "agent"

    async def test_token_refresh_blacklists_old_jti(self, client):
        """After refresh, the old JTI should be in the blacklist."""
        c, store = client
        await store.add_authorized_key("host-bl", _AGENT_PUBLIC_PEM, "test")
        reg_resp = await c.post(
            "/api/register",
            json={"hostname": "host-bl", "public_key_pem": _AGENT_PUBLIC_PEM},
        )
        old_payload = _decrypt_jwt(reg_resp.json()["token_encrypted"])
        old_jti = old_payload["jti"]
        server_pub_pem = reg_resp.json()["server_public_key_pem"]

        challenge = self._make_challenge(server_pub_pem)
        await c.post(
            "/api/token/refresh",
            json={"hostname": "host-bl", "challenge_encrypted": challenge},
        )
        assert await store.is_jti_blacklisted(old_jti) is True

    async def test_token_refresh_unknown_host_returns_403(self, client):
        c, store = client
        resp = await c.post(
            "/api/token/refresh",
            json={
                "hostname": "ghost-host",
                "challenge_encrypted": base64.b64encode(b"garbage").decode(),
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "agent_not_found"

    async def test_token_refresh_bad_challenge_returns_403(self, client):
        """Providing garbage ciphertext fails decryption → 403."""
        c, store = client
        # Insert the agent directly — bypasses RSA encryption of the register endpoint
        await store.upsert_agent("host-bad-ch", _AGENT_PUBLIC_PEM, "jti-bad-ch")
        resp = await c.post(
            "/api/token/refresh",
            json={
                "hostname": "host-bad-ch",
                "challenge_encrypted": base64.b64encode(b"not-valid-ciphertext").decode(),
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "challenge_decryption_failed"


# ---------------------------------------------------------------------------
# TestVerifyJwt — JWT validation helper
# ---------------------------------------------------------------------------

class TestVerifyJwt:
    def _make_token(self, role="agent", expired=False, jti=None):
        now = int(time.time())
        jti = jti or str(uuid.uuid4())
        exp = now - 10 if expired else now + 3600
        payload = {"sub": "host-test", "role": role, "jti": jti, "iat": now, "exp": exp}
        return jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), jti

    async def test_verify_jwt_valid_token(self):
        """A valid token returns the decoded payload."""
        store = AgentStore(":memory:")
        await store.init()
        token, _ = self._make_token(role="agent")
        payload = await routes_register.verify_jwt(token, store)
        assert payload["sub"] == "host-test"
        assert payload["role"] == "agent"
        await store.close()

    async def test_verify_jwt_expired_raises_401(self):
        from fastapi import HTTPException
        store = AgentStore(":memory:")
        await store.init()
        token, _ = self._make_token(expired=True)
        with pytest.raises(HTTPException) as exc_info:
            await routes_register.verify_jwt(token, store)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["error"] == "token_expired"
        await store.close()

    async def test_verify_jwt_invalid_signature_raises_401(self):
        from fastapi import HTTPException
        store = AgentStore(":memory:")
        await store.init()
        token, _ = self._make_token()
        bad_token = token + "tampered"
        with pytest.raises(HTTPException) as exc_info:
            await routes_register.verify_jwt(bad_token, store)
        assert exc_info.value.status_code == 401
        await store.close()

    async def test_verify_jwt_blacklisted_jti_raises_401(self):
        from fastapi import HTTPException
        store = AgentStore(":memory:")
        await store.init()
        token, jti = self._make_token()
        await store.add_to_blacklist(jti, "host-test", "2099-01-01T00:00:00+00:00", "revoked")
        with pytest.raises(HTTPException) as exc_info:
            await routes_register.verify_jwt(token, store)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail["error"] == "token_revoked"
        await store.close()


# ---------------------------------------------------------------------------
# TestRequireRole — FastAPI dependency
# ---------------------------------------------------------------------------

class TestRequireRole:
    @pytest_asyncio.fixture
    async def app_with_exec(self):
        """Minimal app with a role-protected endpoint for testing."""
        store = AgentStore(":memory:")
        await store.init()
        app = FastAPI()
        app.state.store = store

        from fastapi import Depends
        from server.api.routes_register import require_role

        @app.get("/protected-plugin")
        async def protected(payload=Depends(require_role("plugin"))):
            return {"role": payload["role"]}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c, store

        await store.close()

    def _make_plugin_token(self):
        now = int(time.time())
        payload = {
            "sub": "plugin-caller",
            "role": "plugin",
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 3600,
        }
        return jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def _make_agent_token(self):
        now = int(time.time())
        payload = {
            "sub": "some-agent",
            "role": "agent",
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 3600,
        }
        return jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    async def test_require_role_plugin_accepted(self, app_with_exec):
        c, store = app_with_exec
        token = self._make_plugin_token()
        resp = await c.get("/protected-plugin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "plugin"

    async def test_require_role_wrong_role_returns_403(self, app_with_exec):
        c, store = app_with_exec
        token = self._make_agent_token()
        resp = await c.get("/protected-plugin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "insufficient_role"

    async def test_require_role_missing_header_returns_401(self, app_with_exec):
        c, store = app_with_exec
        resp = await c.get("/protected-plugin")
        assert resp.status_code == 401
