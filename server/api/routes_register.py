"""
routes_register.py — Enrollment, admin authorization, and token refresh endpoints.

Endpoints:
    POST /api/register           — Agent enrollment (no JWT required)
    POST /api/admin/authorize    — Pre-authorize a public key (admin token required)
    POST /api/token/refresh      — Refresh an expiring agent JWT

Auth middleware helpers exported for use by other route modules:
    verify_jwt(token)            — Validate signature, expiry, JTI blacklist
    require_role(role)           — FastAPI dependency factory
    get_current_agent(request)   — FastAPI dependency — agent role only

Security:
    - JWT signed HMAC-SHA256 (python-jose)
    - JWT encrypted for agent with RSA-OAEP (cryptography)
    - Admin endpoint protected by static ADMIN_TOKEN (Bearer)
    - become_pass / stdin masking: not applicable here (server side)
"""

import base64
import hmac
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from jose import ExpiredSignatureError, JWTError, jwt as jose_jwt
from pydantic import BaseModel, field_validator

from server.db.agent_store import AgentStore

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Configuration helpers — values read from environment at import time.
# Overridable in tests by patching these module-level names.
# ---------------------------------------------------------------------------

def _get_jwt_secret() -> str:
    val = os.environ.get("JWT_SECRET_KEY", "")
    if not val:
        raise RuntimeError("JWT_SECRET_KEY environment variable is not set")
    return val


def _get_admin_token() -> str:
    val = os.environ.get("ADMIN_TOKEN", "")
    if not val:
        raise RuntimeError("ADMIN_TOKEN environment variable is not set")
    return val


JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "3600"))

# ---------------------------------------------------------------------------
# Server RSA key pair — generated once at process startup, reused across
# requests.  The server public key is returned during enrollment so the agent
# can verify future challenges.
# ---------------------------------------------------------------------------

def _generate_server_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Generate a 4096-bit RSA key pair and return (private_key, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_key, public_pem


_SERVER_PRIVATE_KEY: rsa.RSAPrivateKey
_SERVER_PUBLIC_KEY_PEM: str

try:
    _SERVER_PRIVATE_KEY, _SERVER_PUBLIC_KEY_PEM = _generate_server_keypair()
    logger.info("Server RSA key pair generated")
except Exception as exc:  # pragma: no cover
    logger.error("Failed to generate server RSA key pair: %s", exc)
    raise


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    hostname: str
    public_key_pem: str

    @field_validator("hostname")
    @classmethod
    def hostname_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("hostname must not be empty")
        return v.strip()

    @field_validator("public_key_pem")
    @classmethod
    def pem_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("public_key_pem must not be empty")
        return v.strip()


class RegisterResponse(BaseModel):
    token_encrypted: str          # base64(RSA-OAEP(JWT))
    server_public_key_pem: str


class AdminAuthorizeRequest(BaseModel):
    hostname: str
    public_key_pem: str
    approved_by: str

    @field_validator("hostname", "public_key_pem", "approved_by")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("field must not be empty")
        return v.strip()


class TokenRefreshRequest(BaseModel):
    hostname: str
    challenge_encrypted: str   # base64(RSA-OAEP(random_bytes, encrypted with server pubkey))


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _issue_jwt(hostname: str) -> tuple[str, str]:
    """
    Issue a signed JWT for an agent.

    Returns:
        (raw_jwt_string, jti)
    """
    jti = str(uuid.uuid4())
    now = _now_ts()
    payload = {
        "sub": hostname,
        "role": "agent",
        "jti": jti,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
    }
    token = jose_jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)
    return token, jti


def _encrypt_jwt_for_agent(raw_jwt: str, agent_public_key_pem: str) -> str:
    """
    Encrypt a JWT string with the agent's RSA public key (RSAES-OAEP / SHA-256).

    The agent decrypts it with its private key to obtain the bearer token.

    Args:
        raw_jwt:              Plain JWT string.
        agent_public_key_pem: Agent RSA-4096 public key in PEM format.

    Returns:
        base64-encoded ciphertext.
    """
    public_key = serialization.load_pem_public_key(agent_public_key_pem.encode())
    ciphertext = public_key.encrypt(
        raw_jwt.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()


async def verify_jwt(token: str, store: AgentStore) -> dict:
    """
    Validate a JWT bearer token.

    Checks:
    - HMAC-SHA256 signature
    - Expiration (exp claim)
    - JTI not in blacklist

    Args:
        token: Raw JWT string (without "Bearer " prefix).
        store: AgentStore instance for blacklist lookup.

    Returns:
        Decoded JWT payload dict.

    Raises:
        HTTPException 401 on any validation failure.
    """
    try:
        payload = jose_jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token_expired"},
        )
    except JWTError as exc:
        logger.debug("JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token"},
        )

    jti = payload.get("jti")
    if jti and await store.is_jti_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token_revoked"},
        )

    return payload


def _extract_bearer(authorization: Optional[str]) -> str:
    """Extract the token from an 'Authorization: Bearer <token>' header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "missing_authorization"},
        )
    return authorization[len("Bearer "):]


def require_role(required_role: str):
    """
    FastAPI dependency factory that enforces a JWT role claim.

    Usage:
        @router.get("/protected", dependencies=[Depends(require_role("plugin"))])

    Args:
        required_role: Role string to require ("agent", "plugin", "admin").

    Returns:
        A FastAPI dependency coroutine.
    """
    async def _dependency(
        request: Request,
        authorization: Annotated[Optional[str], Header()] = None,
    ) -> dict:
        store: AgentStore = request.app.state.store
        token = _extract_bearer(authorization)
        payload = await verify_jwt(token, store)
        if payload.get("role") != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "insufficient_role"},
            )
        return payload

    return _dependency


async def get_current_agent(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    """
    FastAPI dependency — validates JWT and requires role 'agent'.

    Returns:
        Decoded JWT payload.
    """
    store: AgentStore = request.app.state.store
    token = _extract_bearer(authorization)
    payload = await verify_jwt(token, store)
    if payload.get("role") != "agent":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "agent_role_required"},
        )
    return payload


# ---------------------------------------------------------------------------
# POST /api/register — Agent enrollment
# ---------------------------------------------------------------------------

@router.post(
    "/api/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Agent enrollment — exchange public key for encrypted JWT",
)
async def register_agent(body: RegisterRequest, request: Request) -> RegisterResponse:
    """
    Enroll a relay-agent.

    Flow (ARCHITECTURE.md §7, HLD §3.1):
    1. Look up hostname in authorized_keys table.
    2. Verify the submitted public key matches the pre-authorized one.
    3. Issue a signed JWT and encrypt it with the agent's public key (RSAES-OAEP).
    4. Upsert the agent row with the new JTI.
    5. Return {token_encrypted, server_public_key_pem}.

    HTTP 403 — hostname not in authorized_keys, or public key mismatch.
    HTTP 409 — hostname already enrolled with a *different* public key
               (re-enrollment with same key is idempotent → HTTP 200).
    """
    store: AgentStore = request.app.state.store

    # Step 1 — lookup authorized key
    auth_rec = await store.get_authorized_key(body.hostname)
    if auth_rec is None:
        logger.warning(
            "Enrollment rejected — hostname not authorized",
            extra={"hostname": body.hostname},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "hostname_not_authorized"},
        )

    # Step 2 — verify submitted key matches pre-authorized key
    # Normalize PEM strings before comparison (strip trailing whitespace)
    authorized_pem = auth_rec["public_key_pem"].strip()
    submitted_pem = body.public_key_pem.strip()

    existing_agent = await store.get_agent(body.hostname)

    if authorized_pem != submitted_pem:
        # Key mismatch — always 403 (not the expected key for this hostname)
        logger.warning(
            "Enrollment rejected — public key mismatch",
            extra={"hostname": body.hostname},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "public_key_mismatch"},
        )

    # Step 3 — check for 409: already enrolled with a *different* key
    # (same key → idempotent re-enrollment is allowed → HTTP 200)
    if existing_agent is not None:
        if existing_agent["public_key_pem"].strip() != submitted_pem:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "hostname_conflict"},
            )
        # Same key: fall through to re-issue JWT (idempotent)

    # Step 4 — issue JWT and encrypt with agent's public key
    try:
        raw_jwt, jti = _issue_jwt(body.hostname)
        token_encrypted = _encrypt_jwt_for_agent(raw_jwt, submitted_pem)
    except (ValueError, TypeError) as exc:
        logger.error(
            "Failed to encrypt JWT for agent",
            extra={"hostname": body.hostname, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_public_key"},
        )

    # Step 5 — persist agent row
    await store.upsert_agent(body.hostname, submitted_pem, jti)

    logger.info("Agent enrolled", extra={"hostname": body.hostname, "jti": jti})

    return RegisterResponse(
        token_encrypted=token_encrypted,
        server_public_key_pem=_SERVER_PUBLIC_KEY_PEM,
    )


# ---------------------------------------------------------------------------
# POST /api/admin/authorize — Pre-authorize a public key (CI/CD pipeline)
# ---------------------------------------------------------------------------

@router.post(
    "/api/admin/authorize",
    status_code=status.HTTP_201_CREATED,
    summary="Pre-authorize an agent public key before first boot",
)
async def admin_authorize(
    body: AdminAuthorizeRequest,
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    """
    Store a public key in authorized_keys so the agent can enroll on boot.

    Auth: Bearer <ADMIN_TOKEN> (static token from environment).

    HTTP 401 — missing or incorrect admin token.
    HTTP 201 — key stored (idempotent: updates existing entry if hostname exists).
    """
    # Validate admin token — constant-time comparison prevents timing attacks
    token = _extract_bearer(authorization)
    if not hmac.compare_digest(token, _get_admin_token()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_admin_token"},
        )

    store: AgentStore = request.app.state.store
    await store.add_authorized_key(body.hostname, body.public_key_pem, body.approved_by)

    logger.info(
        "Key authorized via admin endpoint",
        extra={"hostname": body.hostname, "approved_by": body.approved_by},
    )
    return {"hostname": body.hostname, "status": "authorized"}


# ---------------------------------------------------------------------------
# POST /api/token/refresh — Refresh an expiring agent JWT
# ---------------------------------------------------------------------------

@router.post(
    "/api/token/refresh",
    status_code=status.HTTP_200_OK,
    summary="Refresh an agent JWT using an encrypted challenge",
)
async def token_refresh(body: TokenRefreshRequest, request: Request) -> dict:
    """
    Issue a new JWT for an agent that presents a valid encrypted challenge.

    Protocol:
    1. Look up the agent's registered public key.
    2. Decrypt the challenge with the SERVER private key (agent encrypted it
       with the server public key received at enrollment).
    3. If decryption succeeds → agent possesses the correct private key.
    4. Blacklist the agent's current JTI.
    5. Issue and return a new encrypted JWT.

    HTTP 403 — agent not found or challenge decryption failed.
    """
    store: AgentStore = request.app.state.store

    agent = await store.get_agent(body.hostname)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "agent_not_found"},
        )

    # Decrypt challenge — proves the agent holds the private key matching
    # the server public key it received at enrollment
    try:
        ciphertext = base64.b64decode(body.challenge_encrypted)
        _SERVER_PRIVATE_KEY.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "challenge_decryption_failed"},
        )

    # Blacklist current JTI before issuing new one
    old_jti = agent.get("token_jti")
    if old_jti:
        now = _now_ts()
        expires_iso = datetime.fromtimestamp(now + JWT_TTL_SECONDS, tz=timezone.utc).isoformat()
        await store.add_to_blacklist(
            jti=old_jti,
            hostname=body.hostname,
            expires_at=expires_iso,
            reason="token_refresh",
        )

    # Issue new JWT
    raw_jwt, new_jti = _issue_jwt(body.hostname)
    token_encrypted = _encrypt_jwt_for_agent(raw_jwt, agent["public_key_pem"])
    await store.update_token_jti(body.hostname, new_jti)

    logger.info(
        "Token refreshed",
        extra={"hostname": body.hostname, "old_jti": old_jti, "new_jti": new_jti},
    )
    return {
        "token_encrypted": token_encrypted,
        "server_public_key_pem": _SERVER_PUBLIC_KEY_PEM,
    }
