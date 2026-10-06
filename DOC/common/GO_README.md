# Ansible-SecAgent — GO Implementation (Phase 7-14, v3.0.3)

**Status**: v3.0.3 (NATS removed, state file, TLS native) — voir `CHANGELOG.md` et les rapports de qualification pour l'état de validation

This directory contains the high-performance GO implementation of Ansible-SecAgent server, agents, and inventory components.

> **Note**: v3.0.3 simplifies architecture (removes NATS, uses file-based state + verrou). See ARCHITECTURE.md for current specs.

## Directory Structure

```
GO/
├── cmd/
│   ├── secagent-server/
│   │   ├── main.go                          # HTTP + WSS server (TLS native)
│   │   ├── main_*.go                        # Tests, helpers
│   │   └── internal/
│   │       ├── server/                      # Core server (tls.go, config.go)
│   │       ├── handlers/                    # REST API endpoints
│   │       ├── ws/                          # WebSocket handlers (/ws/agent, /ws/relay)
│   │       ├── state/                       # State engine: relay.state / relay.state.prev (HMAC, AES-GCM secrets), `state init|verify|restore`
│   │       ├── lock/                        # Failover lock (relay.lock, actif/passif)
│   │       ├── storage/                     # Data access layer over the state (agents, tokens, relays; store.go, store_*.go)
│   │       ├── cli/                         # Admin CLI (Cobra)
│   │       └── repeater/                    # Relay-to-relay support (v3.0.1+)
│   ├── secagent-minion/
│   │   ├── main.go                          # Agent daemon (WSS client)
│   │   └── internal/
│   │       ├── ws/                          # WebSocket handler, reconnection
│   │       ├── executor/                    # Subprocess execution
│   │       ├── enrollment/                  # RSA-4096, enrollment flow
│   │       └── registry/                    # Async task registry
│   └── secagent-inventory/
│       └── main.go                          # Standalone inventory binary
├── go.mod                                   # Module definition
├── go.sum                                   # Dependency lock
├── Dockerfile / Dockerfile.agent / Dockerfile.ansible   # Container images (Dockerfile.ansible : OBSOLETE v3.0.3, voir #188 pour le remplaçant)
└── internal/endpoints/, internal/testnet/               # Shared packages (address lists, test helpers)

(Compose files are NOT under GO/: see ../DEPLOYMENT/qualif/ and ../DEPLOYMENT/prod/.)
```

## Features

### 1. Handlers (handlers/)

**register.go** (280 LOC)
- `RegisterAgent()`: POST /api/register
  - JWT generation (HS256)
  - RSA-OAEP/SHA256 encryption
  - Enrollment token + nonce challenge (a request without `enrollment_token` is refused: 403 `enrollment_token_required`, #192c)
- `AdminAuthorize()`: POST /api/admin/authorize
  - Bearer token validation
  - Stores the key in `authorized_keys` only: it grants NO enrollment right any more
- `POST /api/token/refresh` was removed (#192, 404): renewal = re-enrollment on 401, or the WS `rekey` message

**exec.go** (380 LOC)
- `ExecCommand()`: POST /api/exec/{hostname}
  - Command execution via WebSocket
  - Timeout + result waiting
  - Error handling (503, 504)
- `UploadFile()`: POST /api/upload/{hostname}
  - Base64 file transfer
  - 500KB size limit
  - Mode/permissions support
- `FetchFile()`: POST /api/fetch/{hostname}
  - Remote file retrieval
  - Base64 encoding

**inventory.go** (140 LOC)
- `GetInventory()`: GET /api/inventory
  - Ansible JSON format
  - Query filtering (only_connected)
  - Hostvars (secagent_status, secagent_last_seen)

### 2. WebSocket Handler (ws/)

**handler.go** (370 LOC)
- `AgentHandler()`: WebSocket /ws/agent
  - HTTP upgrade + JWT auth
  - Connection registry
  - Message dispatch loop
- `HandleMessage()`: Message dispatcher
  - ack (task acknowledged)
  - stdout (streaming with 5MB cap)
  - result (resolve futures, cleanup)
- `RegisterConnection()`: Register agent WS
- `SendToAgent()`: Send JSON via WS
- `RegisterFuture()`: Create result channel
- `ResolveFuturesForHostname()`: Cleanup on disconnect

### 3. State and Storage (state/, storage/) — v3.0.3

**internal/state/** (file-based state engine, no SQLite)
- `relay.state` (+ `relay.state.prev`, transient `relay.state.tmp`) in STATE_DIR
- File authenticated by HMAC-SHA-256 (key derived from `RSA_MASTER_KEY`); only the secrets are encrypted (AES-256-GCM, `enc:` prefix)
- Atomic writes (tmp + rename + fsync), `write_seq` anti-replay field, write guard tied to the lock identity
- CLI: `state init`, `state verify <file>`, `state restore --from <file>` (`internal/cli/state*.go`)

**internal/storage/** (store.go, store_*.go)
- Data access layer over the state engine: agents, authorized keys, enrollment / plugin tokens, relays, routing
- Volatile data (status, last_seen) is kept in memory and written to the file only piggybacked on another write

### 4. Lock Management (lock/) — v3.0.3

**Failover lock** (file-based, NFS-friendly)
- `relay.lock` is a file created with `O_EXCL` + a heartbeat counter (not a `flock`)
- Heartbeat 30s; master identity check / secondary polling every 5s
- Self-retire after 3min without a successful heartbeat; master considered dead after 5min without change
- Candidate stale timeout 10s; random pause 1-2s between creation and re-read
- Lock identity verified before every state write (write guard); a lost lock exits with code 75
- Constants in `internal/lock/params.go` (no environment variable)

No more NATS JetStream. Direct WebSocket dispatch to agents.

## Performance

No Python-vs-GO benchmark is kept in this repository: the figures that used to be listed here (latency, memory,
startup, throughput) were never measured by the project and have been removed. Scale validation (several thousand
agents, memory footprint) is described in `DEPLOYMENT/prod/README.md` (« Dimensionnement ») and the QA reports in `_work/reports/`.

## Dependencies

### Go Standard Library
- `crypto/rsa`, `crypto/x509`, `crypto/sha256`: Cryptography
- `encoding/json`, `encoding/pem`, `encoding/base64`: Encoding
- `database/sql`: (removed v3.0.3 — file-based state)
- `net/http`: HTTP server
- `context`, `sync`: Concurrency primitives

### External Packages (v3.0.3)
- `github.com/golang-jwt/jwt/v5`: JWT handling
- `github.com/google/uuid`: UUID generation
- `github.com/gorilla/websocket`: WebSocket upgrade

SQLite and NATS are removed in v3.0.3:
- File-based state (no DB)
- Direct WebSocket dispatch (no message broker)

```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/google/uuid
go get github.com/gorilla/websocket
```

## Build

```bash
# Build server binary (from GO/, module `secagent-server`; also ./cmd/secagent-minion, ./cmd/secagent-inventory)
go build -o secagent-server ./cmd/secagent-server

# Build with optimizations
go build -ldflags="-s -w" -o secagent-server ./cmd/secagent-server

# Cross-compile (Linux)
GOOS=linux GOARCH=amd64 go build -o secagent-server ./cmd/secagent-server
```

## Usage

### Environment Variables (v3.0.3)
- `JWT_SECRET_KEY`: Secret for JWT signing (required)
- `ADMIN_TOKEN`: Bearer token for admin endpoints (required)
- `STATE_DIR`: Directory for relay.state and relay.lock (default: /data, required for production)
- `RELAY_STATUS_FILE`: Healthcheck file path (local, outside STATE_DIR, optional)
- `TLS_CERT`, `TLS_KEY`: TLS certificate paths (required for production WSS)
- `TLS_DISABLE`: `true` serves plain HTTP (tests/CI only, unsafe, never in production)
- `ADMIN_TLS`, `ADMIN_INSECURE_HTTP` (+ `ADMIN_INSECURE_HTTP_ACK`): admin API TLS options (strict `true`/`false`)
- `RSA_MASTER_KEY`: Master secret (string, not an RSA key): required by `state init` and by the server (HMAC of relay.state, AES-256-GCM of the secrets); only `--insecure-test-mode` goes without it
- `ADMIN_ADDR` (default `:7771`, all interfaces: a non-loopback address requires `ADMIN_TLS=true`), `API_ADDR` (`:7770`), `WS_ADDR` (`:7772`)

### Quick Start (v3.0.3)
```bash
# Initialize state directory
mkdir -p ./data
./secagent-server state init --state-dir ./data

# Set environment
export JWT_SECRET_KEY="dev-secret-key"
export ADMIN_TOKEN="dev-admin-token"
export STATE_DIR="./data"
export TLS_CERT="./certs/server.crt"
export TLS_KEY="./certs/server.key"
# For tests only: export TLS_DISABLE=true

# Run server (WSS on 7770/7772)
./secagent-server
```

### CLI Access via Container

**Start the stack** : Compose files live in `DEPLOYMENT/qualif/` (`docker-compose.server.yml`, `docker-compose.minion.yml`, …) — see `DEPLOYMENT/qualif/README.md`. There is no Compose file under `GO/`. The CLI must be run in the container of the instance that currently holds the lock (the secondary opens no port):
```bash
SECAGENT="docker exec secagent-qualif-a secagent-server"   # or secagent-qualif-b
```

**Access CLI commands via container** (Phase 6 — admin commands) :
```bash
# Minions management
$SECAGENT minions list --format table
$SECAGENT minions get <hostname>
$SECAGENT minions suspend <hostname>
$SECAGENT minions resume <hostname>
$SECAGENT minions revoke <hostname>
$SECAGENT minions vars set <hostname> key=value [key=value ...]

# Security — Key rotation
$SECAGENT security keys status
$SECAGENT security keys rotate --grace 2h
$SECAGENT security tokens list
$SECAGENT security blacklist list

# Inventory
$SECAGENT inventory list --only-connected

# Server status
$SECAGENT server status --format json
```

**Format options** : `--format table|json|yaml` (default: table)

**Authentication** : CLI uses the `ADMIN_TOKEN` env var of the container (set in the Compose env file)

## Testing

### Unit Tests
```bash
cd GO/
JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./... -v -count=1
```

### Integration Tests — CLI via Docker

**Smoke tests (basic CLI validation)** :
```bash
# (stack started as described above)
$SECAGENT minions list
$SECAGENT security keys status
$SECAGENT server status
# (stop the stack with `docker compose ... down`)
```

**Enrollment workflow test (Phase 6)** :
Test the full enrollment flow by revoking agents and validating ré-enrôlement:
```bash
# Start the qualif stack with 3 connected agents (see above)

# 1. Verify agents are connected
$SECAGENT minions list --format table
# Expected: qualif-host-01/02/03 with status=enrolled

# 2. Revoke agents to force ré-enrôlement
$SECAGENT minions revoke qualif-host-01
$SECAGENT minions revoke qualif-host-02
$SECAGENT minions revoke qualif-host-03

# 3. Verify revocation (agents should disconnect then ré-enroll)
sleep 5
$SECAGENT minions list --format table
# Expected: status should cycle through revoked → enrolled as agents reconnect

# 4. Validate ré-enrôlement completed
$SECAGENT minions get qualif-host-01 --format json
# Check: enrolled_at timestamp updated, token_jti recorded in relay.state

# 5. Re-enrollment needs an enrollment token (a pre-authorized key is no longer enough, #192c)
$SECAGENT tokens create --role enrollment --hostname-pattern "qualif-host-01" --expires 1h
# give it to the minion (RELAY_ENROLLMENT_TOKEN), then:
$SECAGENT minions revoke qualif-host-01

# (stop the stack with `docker compose ... down`)
```

**What this validates** :
- ✅ `RegisterAgent()` flow : enrollment token + nonce challenge, JWT encryption, JTI persistence; refusal without token
- ✅ `AdminAuthorize()` : key storage (no enrollment right)
- ✅ 401 ré-enrôlement with a new enrollment token, new JWT encryption
- ✅ Dual-key JWT : grace period validation during rotation
- ✅ Agent 401 handling : automatic ré-enrôlement without manual intervention

### E2E Tests
- Full GO agent ↔ GO server
- Ansible playbook execution via secagent-inventory plugin
- Dynamic inventory with connected agents
- Multiple concurrent agents with key rotation
- JWT rotation with grace period (dual-key validation)
- Agent revocation → automatic ré-enrôlement cycle

## Architecture Decisions

### Concurrency Model
- **Goroutines** instead of asyncio for WebSocket handlers
- **Channels** instead of asyncio.Future for result delivery
- **sync.RWMutex** for concurrent map access
- No threading (pure Go async)

### Cryptography
- **RSA-4096**: Industry-standard key length
- **RSA-OAEP/SHA256**: Padding standard
- **HS256 JWT**: Symmetric signing (server-side validation only)
- **Constant-time comparison**: Prevention of timing attacks

### Persistence (v3.0.3)
- **File-based state**: relay.state (JSON, HMAC-signed, AES-256-GCM encrypted)
- **Atomic writes**: write_seq counter (anti-replay)
- **NFS-friendly**: Verrou fichier (exclusivité actif/passif)
- **Indexes**: None (file-based, lookup by JSON parsing)

### Messaging (v3.0.3)
- **Direct WebSocket dispatch**: No NATS
- **Task multiplexing**: By task_id (1 WS per agent)
- **No message persistence**: Agents reconnect + retry
- **Failover**: Relay active/passive with lock (both agents see same state file)

## Migration from Python

### API Compatibility
- ✅ All endpoints preserved (register, exec, inventory, etc.)
- ✅ Same JWT and RSA encryption
- ✅ Identical request/response formats
- ✅ WebSocket protocol unchanged
- ⚠️ NATS removed v3.0.3 (direct WebSocket dispatch)

### Behavioral Changes
- Goroutines instead of asyncio (no observable difference)
- Channels instead of futures (internal only)
- Binary compilation (no Python runtime)
- Reduced memory footprint

### Migration v3.0 → v3.0.3
- Removed: SQLite database, NATS JetStream client
- Added: File-based state (STATE_DIR), failover lock
- See STATE_SPEC.md for state file format and validation
- Agents must have correct STATE_DIR and RSA_MASTER_KEY to start

## Completed Phases

### Phase 7 — Server Rewrite ✅ (v2.x historical)
**Note**: Phase 7-8 used SQLite and NATS. v3.0.3 replaces these with file-based state and direct WebSocket dispatch.
- ✅ handlers/register.go — Enrollment, JWT, RSA-4096 (kept)
- ✅ handlers/exec.go — Task execution, file transfer (kept)
- ✅ handlers/inventory.go — Ansible inventory format (kept)
- ✅ handlers/admin.go — Admin endpoints (minions, status) (kept)
- ✅ ws/handler.go — WebSocket connections, dispatch (kept, direct WS in v3.0.3)
- ⚠️ storage/store.go — was the SQLite persistence; the file still exists in v3.0.3 as the data access layer over the file state (SQLite removed)
- ⚠️ broker/nats.go — NATS JetStream client (removed v3.0.3)
- ✅ main.go — HTTP server setup, request routing (kept)
- ✅ Unit tests — 80%+ coverage
- ✅ Docker — Dockerfile (Compose files: see ../DEPLOYMENT/)
- ✅ go.mod/go.sum — Dependency lock files

### Phase 8 — Agent Rewrite ✅
- ✅ cmd/secagent-minion/main.go — Agent daemon (renamed from cmd/agent)
- ✅ internal/ws/dispatcher.go — WebSocket handler, rekey support
- ✅ internal/executor/executor.go — Subprocess execution
- ✅ internal/enrollment/ — RSA-4096, enrollment flow
- ✅ internal/registry/ — Async task registry
- ✅ internal/facts/ — System facts collection
- ✅ Handler rekey + 401 ré-enrôlement

### Phase 9 — Inventory Plugin ✅
- ✅ cmd/secagent-inventory/main.go — secagent-inventory binary
- ✅ Ansible plugin wrapper
- ✅ Dynamic inventory format

### Phase 6 — Admin CLI ✅
- ✅ internal/cli/root.go — Cobra CLI framework
- ✅ internal/cli/minions.go — Minion management commands
- ✅ internal/cli/security.go — Key rotation & security commands
- ✅ internal/cli/inventory.go — Inventory listing
- ✅ internal/cli/server.go — Server status
- ✅ internal/auth/jwt.go — JWT service, dual-key validation
- ✅ internal/crypto/aes.go — AES-256-GCM encryption
- ✅ handlers/security.go — Key rotation endpoint + rekey WS
- ✅ 407 tests pass, CLI smoke tests OK

## Security

- **RSA-4096 OAEP/SHA256**: Agent enrollment encryption
- **HS256 JWT**: API request signing
- **Bearer tokens**: Admin authorization
- **JTI blacklist**: Token revocation
- **Constant-time comparison**: Timing attack prevention
- **TLS 1.2+**: Native HTTP/WSS (`MinVersion` TLS 1.2, no reverse proxy required)

## Performance Optimization

- **Compiled binary**: No Python startup overhead
- **Goroutine pooling**: Efficient WebSocket handling
- **Channel buffering**: Non-blocking result delivery
- **File-based state**: Lock-free reads (v3.0.3)
- **Atomic writes**: Verrou prevents split-brain (STATE_DIR)
- **Direct WebSocket**: No message broker (v3.0.3)

## Contributing

See `../CLAUDE.md` for project conventions:
- PEP 8 style (Go equivalent)
- Type hints (Go type system)
- Docstrings on public functions
- Error wrapping with `fmt.Errorf`
- Structured logging

## Documentation

- `PHASE7_COMPLETE.md`: Complete migration summary
- `ARCHITECTURE.md`: Technical specifications
- `HLD.md`: High-level design diagrams

---

**Last Updated**: 2026-03-05
**Phase**: 7 (Server Rewrite)
**Status**: Conversion Complete ✅ — Ready for Integration Testing
