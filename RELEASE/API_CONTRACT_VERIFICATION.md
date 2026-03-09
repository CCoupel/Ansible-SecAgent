# API Contract Verification — Python vs GO Server

**Date**: 2026-03-05
**Author**: dev-relay
**Task**: #46 — Migration Python → GO : vérifier API contracts, protocol compatibility

---

## Summary

| Area | Status | Notes |
|------|--------|-------|
| Request/Response formats | COMPATIBLE | JSON field names identical |
| HTTP status codes | PARTIAL GAP | GO exec returns 200 even on agent_disconnected |
| JWT format | COMPATIBLE | HS256, same claims (sub, role, jti, iat, exp) |
| WebSocket protocol | COMPATIBLE | Same message types (ack, stdout, result, put_file, fetch_file) |
| Auth enforcement | GAP | GO exec/upload/fetch handlers have no JWT auth — Python requires role=plugin |
| File size limit | COMPATIBLE | 500 KB (500*1024 bytes) |
| Stdout buffer limit | COMPATIBLE | 5 MB (5*1024*1024 bytes) |

---

## Endpoint-by-Endpoint Analysis

### POST /api/register

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Request: hostname | `string` (trimmed) | `string` (trimmed) | YES |
| Request: public_key_pem | `string` (trimmed) | `string` (trimmed) | YES |
| Response: token_encrypted | `string` (base64 RSA-OAEP) | `string` (base64 RSA-OAEP) | YES |
| Response: server_public_key_pem | `string` (PEM) | `string` (PEM) | YES |
| HTTP 200 | Successful enrollment | Successful enrollment | YES |
| HTTP 403 | hostname_not_authorized / public_key_mismatch | public_key_mismatch | **GAP** |
| HTTP 409 | hostname_conflict (different key enrolled) | Not implemented | **GAP** |
| Error body | `{"error": "..."}` | `{"error": "..."}` | YES |

**GAP 1** (`register_agent` — line 325 Python): Python returns 403 `hostname_not_authorized` when hostname is not in authorized_keys. GO skips this check (accepts all keys — TODO comment at register.go:127).

**GAP 2** (`register_agent` — line 357 Python): Python returns 409 `hostname_conflict` when agent re-enrolls with a different key. GO does not implement this check.

---

### POST /api/admin/authorize

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Request: hostname | `string` | `string` | YES |
| Request: public_key_pem | `string` | `string` | YES |
| Request: approved_by | `string` | `string` | YES |
| Response: hostname | `string` | `string` | YES |
| Response: status | `"authorized"` | `"authorized"` | YES |
| HTTP 201 | Created | Created | YES |
| HTTP 401 | invalid_admin_token | invalid_admin_token | YES |
| Auth | hmac.compare_digest | plain `!=` comparison | **GAP** |

**GAP 3** (`AdminAuthorize` — register.go:199): GO uses `token != server.AdminToken` — susceptible to timing attacks. Python uses `hmac.compare_digest`. The timing attack risk on this endpoint is low (Bearer token is long-enough entropy), but should be fixed for consistency.

---

### POST /api/token/refresh

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Request: hostname | `string` | `string` | YES |
| Request: challenge_encrypted | `string` (base64) | `string` (base64) | YES |
| Response: token_encrypted | `string` (base64) | `string` (base64) | YES |
| Response: server_public_key_pem | `string` (PEM) | `string` (PEM) | YES |
| HTTP 200 | Token refreshed | Token refreshed | YES |
| HTTP 403 | agent_not_found / challenge_decryption_failed | challenge_decryption_failed | **GAP** |
| Old JTI blacklisting | YES (Python line 483) | NO (TODO comment register.go:307) | **GAP** |
| Token JTI update in DB | YES | NO (TODO comment register.go:308) | **GAP** |

**GAP 4** (`token_refresh` — register.go:296): Python looks up the agent in DB and retrieves its public key for re-encryption. GO uses an empty `agentPublicKey` placeholder — token encryption will always fail in production.

**GAP 5** (`token_refresh` — register.go:307): Python blacklists the old JTI before issuing a new one. GO has a TODO comment — old tokens remain valid until natural expiry.

---

### POST /api/exec/{hostname}

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Request: cmd | `string` | `string` | YES |
| Request: stdin | `string\|null` | `string\|null` | YES |
| Request: timeout | `int` (default 30) | `int` (default 30) | YES |
| Request: become | `bool` | `bool` | YES |
| Request: become_method | `string` (default "sudo") | `string` (default "sudo") | YES |
| Response: rc | `int` | `int` | YES |
| Response: stdout | `string` | `string` | YES |
| Response: stderr | `string` | `string` | YES |
| Response: truncated | `bool` | `bool` | YES |
| HTTP 200 | OK | OK (stub — always mock) | YES |
| HTTP 503 | agent_offline | agent_offline | YES |
| HTTP 500 | agent_disconnected | NOT returned (no real WS call) | **GAP** |
| HTTP 429 | agent_busy | NOT returned (stub) | **GAP** |
| HTTP 504 | timeout | NOT returned (stub) | **GAP** |
| JWT Auth | role=plugin required | **NO AUTH** | **CRITICAL GAP** |
| NATS publish | YES | NOT implemented (TODO) | **GAP** |
| stdin stripping for become | YES (NATS path) | NOT implemented | **GAP** |

**GAP 6 (CRITICAL)** (`ExecCommand` — exec.go:162): Python requires `role=plugin` JWT on exec/upload/fetch. GO has NO authentication middleware — any unauthenticated caller can execute commands on agents.

**GAP 7**: GO ExecCommand is a stub — it does not actually send via WebSocket or NATS. It returns a hardcoded `rc=0` response.

---

### POST /api/upload/{hostname}

Same auth gap (GAP 6) and stub gap (GAP 7) as exec. Request/response format is identical between Python and GO.

---

### POST /api/fetch/{hostname}

Same auth gap (GAP 6) and stub gap (GAP 7) as exec. Request/response format is identical between Python and GO.

---

### GET /api/async_status/{task_id}

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Response: task_id | present | present | YES |
| Response: status | "running"\|"finished" | "finished" only | **GAP** |
| Response: rc | `int\|null` | `int` | YES |
| HTTP 200 | found | found | YES |
| HTTP 404 | task_not_found | task_not_found | YES |
| JWT Auth | role=plugin required | **NO AUTH** | **CRITICAL GAP** |

**GAP 8**: Python returns `status="running"` when Future is still pending. GO only returns `status="finished"` or 404 — no `running` state.

---

### GET /api/inventory

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Query: only_connected | `bool` | `bool` | YES |
| Response: all.hosts | `[]string` | `[]string` | YES |
| Response: _meta.hostvars.*.ansible_connection | `"relay"` | `"relay"` | YES |
| Response: _meta.hostvars.*.ansible_host | `string` | `string` | YES |
| Response: _meta.hostvars.*.secagent_status | `string` | `string` | YES |
| Response: _meta.hostvars.*.secagent_last_seen | `string` | `string` | YES |
| JWT Auth | role=plugin required | **NO AUTH** | **CRITICAL GAP** |
| DB query | real agents from SQLite | **hardcoded mock data** | **GAP** |

**GAP 9 (CRITICAL)**: Same auth gap — inventory is accessible without JWT.

**GAP 10**: GetInventory returns hardcoded mock data instead of querying SQLite.

---

### GET /health

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Response | `{"status": "healthy"}` | `{"status":"healthy","timestamp":...}` | MINOR |
| HTTP 200 | YES | YES | YES |

Minor difference: GO adds `timestamp` field — not a breaking change.

---

### WebSocket /ws/agent

| Field | Python | GO | Compatible |
|-------|--------|----|------------|
| Auth: JWT in Authorization header | Required (before accept) | TODO comment | **GAP** |
| Hostname from JWT sub claim | YES | NO (query param `?hostname=`) | **GAP** |
| Message: ack | supported | supported | YES |
| Message: stdout (streaming) | supported | supported | YES |
| Message: result | supported | supported | YES |
| Message: put_file | NOT in ws_handler (sent by exec) | NOT in ws_handler | N/A |
| Close code 4001 | WSCloseRevoked | WSCloseRevoked | YES |
| Close code 4002 | WSCloseExpired | WSCloseExpired | YES |
| 5 MB stdout buffer | YES | YES | YES |

**GAP 11** (`AgentHandler` — ws/handler.go:294): GO WebSocket handler has a `// TODO: Extract and verify JWT` comment. Current implementation accepts any connection with a `?hostname=` query parameter — no authentication.

**GAP 12**: Python extracts hostname from JWT `sub` claim. GO reads it from URL query parameter — a client can claim any hostname without authentication.

---

## JWT Token Format

Both implementations use identical JWT format:

```json
{
  "sub": "<hostname>",
  "role": "agent",
  "jti": "<uuid4>",
  "iat": <unix_timestamp>,
  "exp": <unix_timestamp>
}
```

Algorithm: `HS256` — COMPATIBLE.

---

## NATS Message Format

Python agent message sent to `tasks.<hostname>`:
```json
{
  "task_id": "...",
  "type": "exec|put_file|fetch_file",
  "cmd": "...",
  "stdin": null,
  "timeout": 30,
  "become": false,
  "become_method": "sudo",
  "expires_at": 1234567890
}
```

GO does not yet publish to NATS (stub). The GO broker package (`broker/nats.go`) exists but is not wired to the handlers.

---

## Critical Gaps — Action Required Before Deploy

| Priority | Gap | File | Action |
|----------|-----|------|--------|
| CRITICAL | GAP 6: No JWT auth on exec/upload/fetch/inventory/async_status | exec.go, inventory.go | Add JWT middleware |
| CRITICAL | GAP 11: No JWT auth on WebSocket | ws/handler.go | Implement JWT verification before upgrade |
| CRITICAL | GAP 12: Hostname from query param (not JWT) | ws/handler.go | Extract from JWT sub claim |
| HIGH | GAP 1: No authorized_keys check on register | register.go:127 | Query DB for authorized key |
| HIGH | GAP 2: No 409 on re-enrollment with different key | register.go | Add conflict check |
| HIGH | GAP 4: Token refresh uses empty agentPublicKey | register.go:296 | Fetch public key from DB |
| HIGH | GAP 5: Old JTI not blacklisted on refresh | register.go:307 | Implement JTI blacklist |
| MEDIUM | GAP 7: exec/upload/fetch are stubs | exec.go | Wire to ws.SendToAgent + ws.WaitForResult |
| MEDIUM | GAP 10: Inventory returns mock data | inventory.go | Query store.ListAgents() |
| MEDIUM | GAP 8: async_status missing "running" state | exec.go | Check pending tasks |
| LOW | GAP 3: Admin auth not constant-time | register.go:199 | Use hmac.Equal() |

---

## Compatibility Conclusion

The GO server is **NOT yet backward compatible** with Python agents due to critical authentication gaps. The request/response JSON formats are correct and will work once the auth middleware is implemented.

**Recommended next steps** (in priority order):
1. Implement JWT middleware for port 7770 API endpoints
2. Implement JWT auth in WebSocket handler (before upgrade)
3. Wire exec/upload/fetch to actual WebSocket sends + result channels
4. Implement authorized_keys check in RegisterAgent
5. Fix token_refresh to use DB-stored agent public key
