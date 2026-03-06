# Phase 7 — Migration Verification — Python → GO

**Date** : 2026-03-05
**Author** : dev-relay
**Status** : INCOMPLETE — gaps identified (see conclusion)

---

## 1. API Endpoints Checklist

| Endpoint | GO file | HTTP status match | Notes |
|----------|---------|------------------|-------|
| POST /api/register | handlers/register.go:99 | PARTIAL | 200 OK ✓ — 400 ✓ — 403 ✓ — **409 MISSING** (no conflict check) |
| POST /api/admin/authorize | handlers/register.go:183 | PARTIAL | 201 ✓ — 401 ✓ — 400 ✓ — auth not constant-time |
| POST /api/token/refresh | handlers/register.go:236 | PARTIAL | 200 ✓ — 403 ✓ — agentPublicKey empty → fails in prod |
| POST /api/exec/{hostname} | handlers/exec.go:162 | PARTIAL | 200 ✓ — 503 ✓ — **504/500/429 MISSING** (stub) |
| POST /api/upload/{hostname} | handlers/exec.go:244 | PARTIAL | 200 ✓ — 400 ✓ — 413 ✓ — **504/500 MISSING** (stub) |
| POST /api/fetch/{hostname} | handlers/exec.go:336 | PARTIAL | 200 ✓ — 400 ✓ — **504/500 MISSING** (stub) |
| GET /api/inventory | handlers/inventory.go:53 | PARTIAL | 200 ✓ — **hardcoded mock data** |
| GET /api/async_status/{task_id} | handlers/exec.go:407 | PARTIAL | 200 ✓ — 404 ✓ — **status="running" MISSING** |
| GET /health | cmd/server/main.go:179 | ✓ COMPATIBLE | 200 OK, adds timestamp field (non-breaking) |
| WebSocket /ws/agent | ws/handler.go:293 | PARTIAL | upgrade ✓ — **JWT auth MISSING** |

**Summary** : 9/10 endpoints present — all missing JWT auth middleware on exec/upload/fetch/inventory/async_status/ws

---

## 2. Request/Response Formats

### POST /api/register
- [x] RegisterRequest : `{"hostname": string, "public_key_pem": string}` — IDENTICAL
- [x] RegisterResponse : `{"token_encrypted": string, "server_public_key_pem": string}` — IDENTICAL
- [x] Error format : `{"error": "..."}` — IDENTICAL

### POST /api/exec/{hostname}
- [x] ExecRequest fields : `task_id (opt), cmd, stdin (opt), timeout (default 30), become (default false), become_method (default "sudo")` — IDENTICAL
- [x] ExecResponse : `{"rc": int, "stdout": string, "stderr": string, "truncated": bool}` — IDENTICAL
- [x] stdin redaction log : `***REDACTED***` when become=true — IDENTICAL (exec.go:148)

### POST /api/upload/{hostname}
- [x] UploadRequest : `task_id (opt), dest, data (base64), mode (default "0644")` — IDENTICAL
- [x] UploadResponse : `{"rc": int}` — IDENTICAL
- [x] File size limit : 500 KB (500*1024) — IDENTICAL (exec.go:61, Python routes_exec.py:49)

### POST /api/fetch/{hostname}
- [x] FetchRequest : `task_id (opt), src` — IDENTICAL
- [x] FetchResponse : `{"rc": int, "data": string}` — IDENTICAL

### GET /api/inventory
- [x] Response format : `{"all": {"hosts": [...]}, "_meta": {"hostvars": {...}}}` — IDENTICAL
- [x] Hostvars : `ansible_connection, ansible_host, relay_status, relay_last_seen` — IDENTICAL
- [ ] Data source : hardcoded mock — **NOT from SQLite DB** (TODO pending)

### POST /api/admin/authorize
- [x] AdminAuthorizeRequest : `hostname, public_key_pem, approved_by` — IDENTICAL
- [x] Response : `{"hostname": string, "status": "authorized"}` — IDENTICAL
- [x] HTTP 201 — IDENTICAL

### GET /api/async_status/{task_id}
- [x] Response fields : `task_id, status, rc, stdout, stderr, truncated` — IDENTICAL
- [ ] `status="running"` state : **MISSING in GO** (Python returns running when Future pending)

---

## 3. JWT & Crypto

### JWT Claims
- [x] `sub` : hostname string — IDENTICAL (register.go:146, Python routes_register.py:157)
- [x] `role` : "agent" string — IDENTICAL
- [x] `jti` : UUID v4 string — IDENTICAL
- [x] `iat` : Unix timestamp int — IDENTICAL
- [x] `exp` : Unix timestamp int (TTL 3600s default) — IDENTICAL
- [x] Algorithm : HS256 (symmetric) — IDENTICAL
- [x] Secret : JWT_SECRET_KEY env var — IDENTICAL

### RSA Encryption
- [x] Key size : RSA-4096 — IDENTICAL (register.go:70, Python routes_register.py:72)
- [x] Padding : OAEP / SHA256 — IDENTICAL (register.go:338, Python routes_register.py:182)
- [x] JWT encrypted with **agent** public key on enrollment — IDENTICAL
- [x] Challenge encrypted with **server** public key on refresh — IDENTICAL
- [x] Return value : base64-encoded ciphertext — IDENTICAL

### JTI Blacklist
- [x] `blacklist` table queried on JWT verify — **MISSING in GO** (ws/handler.go TODO comment line 294)
- [ ] Old JTI blacklisted on token_refresh — **MISSING in GO** (register.go TODO comment line 307)
- [x] JTI blacklist entry : jti, hostname, revoked_at, expires_at, reason — schema IDENTICAL

---

## 4. WebSocket Protocol

### Connection
- [x] Upgrade : gorilla/websocket — functionally identical to Python websockets lib
- [x] Close code 4001 (WSCloseRevoked) — IDENTICAL (ws/handler.go:21)
- [x] Close code 4002 (WSCloseExpired) — IDENTICAL (ws/handler.go:22)
- [ ] JWT auth before upgrade — **MISSING** (ws/handler.go:294 TODO comment)
- [ ] Hostname from JWT `sub` claim — **MISSING** (reads from `?hostname=` query param)

### Message Types (server → agent)
- [x] `exec` : task_id, type, cmd, stdin, timeout, become, become_method, expires_at — IDENTICAL
- [x] `put_file` : task_id, type, dest, data, mode — IDENTICAL
- [x] `fetch_file` : task_id, type, src — IDENTICAL
- [x] `cancel` : task_id, type — referenced in Python routes_exec.py but not sent in GO (stubs)

### Response Types (agent → server)
- [x] `ack` : task_id, type — handled (ws/handler.go:222)
- [x] `stdout` : task_id, type, chunk — accumulated (ws/handler.go:226)
- [x] `result` : task_id, type, rc, stdout, stderr, truncated — resolved to channel (ws/handler.go:243)

### Stdout Buffer
- [x] Max 5 MB (5*1024*1024 bytes) — IDENTICAL (ws/handler.go:74)
- [x] Truncation on overflow — IDENTICAL (ws/handler.go:231-239)
- [x] `truncated` flag in result — IDENTICAL

### Task Multiplexing
- [x] Keyed by `task_id` — IDENTICAL
- [x] Per-task result channel (Go) / asyncio.Future (Python) — equivalent semantics
- [x] Cleanup on disconnect : ResolveFuturesForHostname — IDENTICAL to Python behavior

---

## 5. NATS Streams

| Property | Python | GO | Compatible |
|----------|--------|----|------------|
| Stream RELAY_TASKS | nats_client.py | broker/nats.go:17 | ✓ IDENTICAL |
| Stream RELAY_RESULTS | nats_client.py | broker/nats.go:18 | ✓ IDENTICAL |
| RELAY_TASKS policy | WorkQueuePolicy | jetstream.WorkQueuePolicy | ✓ IDENTICAL |
| RELAY_RESULTS policy | LimitsPolicy | jetstream.LimitsPolicy | ✓ IDENTICAL |
| RELAY_TASKS TTL | 300s (5 min) | TasksTTLSec=300 (nats.go:21) | ✓ IDENTICAL |
| RELAY_RESULTS TTL | 60s | ResultsTTLSec=60 (nats.go:22) | ✓ IDENTICAL |
| Subject tasks | `tasks.{hostname}` | `tasks.{hostname}` (nats.go:169) | ✓ IDENTICAL |
| Subject results | `results.{task_id}` | `results.{task_id}` (nats.go:187) | ✓ IDENTICAL |
| Storage | FileStorage | jetstream.FileStorage (nats.go:154) | ✓ IDENTICAL |
| Replicas | 1 | 1 (nats.go:155) | ✓ IDENTICAL |
| MaxDeliver | 1 (no silent retry) | 1 (nats.go:218) | ✓ IDENTICAL |
| NAK on agent offline | YES | YES (nats.go:264) | ✓ IDENTICAL |

**NATS configuration : 100% compatible.**

Note: GO NATS client (`broker.NewClient`) is initialized in `main.go` but handlers do **not yet** call `natsClient.PublishTask()` (exec/upload/fetch are stubs).

---

## 6. Database Schema

### agents table
```sql
-- Python (agent_store.py)                   -- GO (storage/store.go:51)
hostname        TEXT PRIMARY KEY              hostname        TEXT PRIMARY KEY        ✓
public_key_pem  TEXT NOT NULL                 public_key_pem  TEXT NOT NULL           ✓
token_jti       TEXT                          token_jti       TEXT                    ✓
enrolled_at     TIMESTAMP                     enrolled_at     TIMESTAMP               ✓
last_seen       TIMESTAMP                     last_seen       TIMESTAMP               ✓
status          TEXT DEFAULT 'disconnected'   status          TEXT DEFAULT 'disconnected' ✓
```

### authorized_keys table
```sql
-- Python                                     -- GO (storage/store.go:60)
hostname        TEXT PRIMARY KEY              hostname        TEXT PRIMARY KEY        ✓
public_key_pem  TEXT NOT NULL                 public_key_pem  TEXT NOT NULL           ✓
approved_at     TIMESTAMP NOT NULL            approved_at     TIMESTAMP NOT NULL      ✓
approved_by     TEXT NOT NULL                 approved_by     TEXT NOT NULL           ✓
```

Note: Python uses `created_at` column name in some code paths — GO uses `approved_at`. Minor naming difference, no functional impact (not exposed in API).

### blacklist table
```sql
-- Python                                     -- GO (storage/store.go:65)
jti             TEXT PRIMARY KEY              jti             TEXT PRIMARY KEY        ✓
hostname        TEXT NOT NULL                 hostname        TEXT NOT NULL           ✓
revoked_at      TIMESTAMP NOT NULL            revoked_at      TIMESTAMP NOT NULL      ✓
reason          TEXT                          reason          TEXT                    ✓
expires_at      TIMESTAMP NOT NULL            expires_at      TIMESTAMP NOT NULL      ✓
```

### SQLite Pragmas
- [x] WAL mode : `PRAGMA journal_mode=WAL` — IDENTICAL (store.go:109)
- [x] Foreign keys : `PRAGMA foreign_keys=ON` — IDENTICAL (store.go:114)
- [x] Indexes : `idx_blacklist_expires`, `idx_agents_status` — IDENTICAL (store.go:75-76)

**Database schema : 100% compatible.**

---

## 7. Authentication — Gaps Summary

| Endpoint | Python auth | GO auth | Compatible |
|----------|-------------|---------|------------|
| POST /api/register | None (public) | None | ✓ |
| POST /api/admin/authorize | Bearer ADMIN_TOKEN | Bearer ADMIN_TOKEN | ✓ (not constant-time) |
| POST /api/token/refresh | None (challenge-response) | None | ✓ |
| POST /api/exec/{hostname} | JWT role=plugin | **NONE** | ✗ CRITICAL |
| POST /api/upload/{hostname} | JWT role=plugin | **NONE** | ✗ CRITICAL |
| POST /api/fetch/{hostname} | JWT role=plugin | **NONE** | ✗ CRITICAL |
| GET /api/inventory | JWT role=plugin | **NONE** | ✗ CRITICAL |
| GET /api/async_status/{task_id} | JWT role=plugin | **NONE** | ✗ CRITICAL |
| WebSocket /ws/agent | JWT role=agent | **NONE** | ✗ CRITICAL |

---

## Conclusion

**Status : INCOMPLETE — GO server is NOT yet production-ready**

### What is 100% compatible

- JSON request/response formats for all endpoints
- JWT claims format (HS256, sub/role/jti/iat/exp)
- RSA-4096 OAEP/SHA256 encryption algorithm
- NATS stream configuration (names, subjects, TTL, policies, retention)
- SQLite database schema (tables, columns, indexes, pragmas)
- WebSocket message types (ack, stdout, result, exec, put_file, fetch_file)
- Stdout 5 MB buffer + truncation flag
- Task multiplexing by task_id

### What needs implementation before Phase 7 is complete

| Priority | Gap | Files to modify |
|----------|-----|-----------------|
| CRITICAL | JWT middleware on exec/upload/fetch/inventory/async_status | handlers/exec.go, handlers/inventory.go |
| CRITICAL | JWT auth in WebSocket handler (before upgrade) | ws/handler.go |
| CRITICAL | Extract hostname from JWT sub claim (not query param) | ws/handler.go |
| HIGH | authorized_keys check in RegisterAgent | handlers/register.go |
| HIGH | HTTP 409 on re-enrollment with different key | handlers/register.go |
| HIGH | token_refresh: fetch agent public key from DB | handlers/register.go |
| HIGH | token_refresh: blacklist old JTI | handlers/register.go |
| MEDIUM | Wire exec/upload/fetch → ws.RegisterFuture + ws.WaitForResult | handlers/exec.go |
| MEDIUM | Wire GetInventory → store.ListAgents() | handlers/inventory.go |
| MEDIUM | async_status: return status="running" for pending tasks | handlers/exec.go |
| LOW | AdminAuthorize: use hmac.Equal for constant-time comparison | handlers/register.go |

Python agents connecting to the GO server will work at the WebSocket protocol level once the JWT auth gaps are fixed. No changes required to agent code or protocol.
