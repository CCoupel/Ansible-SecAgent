# Ansible-SecAgent — GO Implementation (Phase 7-14, v3.0.3)

**Status**: ✅ v3.0.3 STABLE — Production Ready (NATS removed, state file, TLS native)

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
│   │       ├── storage/                     # File-based state + lock (STATE_DIR, v3.0.3)
│   │       ├── lock/                        # Failover lock management (actif/passif)
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
├── Dockerfile                               # Container image
├── DEPLOYMENT/
│   ├── docker-compose.yml                   # Qualification setup
│   └── prod/docker-compose.yml              # Production HA setup (multi-host NFS)
└── README.md                                # This file
```

## Features

### 1. Handlers (handlers/)

**register.go** (280 LOC)
- `RegisterAgent()`: POST /api/register
  - JWT generation (HS256)
  - RSA-OAEP/SHA256 encryption
  - Authorized key verification
- `AdminAuthorize()`: POST /api/admin/authorize
  - Bearer token validation
  - Pre-authorization storage
- `TokenRefresh()`: POST /api/token/refresh
  - Challenge decryption (RSA)
  - JTI blacklisting
  - Token renewal

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

### 3. Storage Layer (storage/) — v3.0.3

**state.go** (v3.0.3 - removed SQLite, file-based state)
- File-based state persistence (STATE_DIR)
- **relay.state**: JSON file (signed HMAC, encrypted RSA)
- **relay.lock**: Failover lock (exclusive access)
- Atomic reads/writes with write_seq anti-replay

Methods (file-based, not DB):
- `ReadState()`, `WriteState()` - atomic file I/O
- `AcquireLock()`, `ReleaseLock()` - exclusive failover
- `ValidateState()` - HMAC verify, anti-replay check

### 4. Lock Management (lock/) — v3.0.3

**Failover lock** (file-based, NFS-friendly)
- Heartbeat-based lock acquisition (30s interval)
- Self-retire after 3min no heartbeat
- Candidate stale timeout 10s
- Atomic lock verification per state write

No more NATS JetStream. Direct WebSocket dispatch to agents.

## Performance Targets

| Metric | Python | GO | Improvement |
|--------|--------|-----|------------|
| Latency (p95) | 100ms | 5ms | **20x** |
| Memory per instance | 100MB | 10MB | **10x** |
| Startup time | 500ms | 10ms | **50x** |
| Max concurrent agents | ~50 | 500+ | **10x** |
| Throughput (req/s) | ~500 | 5000+ | **10x** |

## Dependencies

### Go Standard Library
- `crypto/rsa`, `crypto/x509`, `crypto/sha256`: Cryptography
- `encoding/json`, `encoding/pem`, `encoding/base64`: Encoding
- `database/sql`: SQLite connectivity
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
# Build server binary
go build -o secagent-server ./cmd/server

# Build with optimizations
go build -ldflags="-s -w" -o secagent-server ./cmd/server

# Cross-compile (Linux)
GOOS=linux GOARCH=amd64 go build -o secagent-server ./cmd/server
```

## Usage

### Environment Variables (v3.0.3)
- `JWT_SECRET_KEY`: Secret for JWT signing (required)
- `ADMIN_TOKEN`: Bearer token for admin endpoints (required)
- `STATE_DIR`: Directory for relay.state and relay.lock (default: /data, required for production)
- `RELAY_STATUS_FILE`: Healthcheck file path (local, outside STATE_DIR, optional)
- `TLS_CERT`, `TLS_KEY`: TLS certificate paths (required for production WSS)
- `TLS_DISABLE`: Set to allow HTTP (tests only, unsafe)
- `ADMIN_TLS`, `ADMIN_INSECURE_HTTP`: Admin CLI TLS options
- `RSA_MASTER_KEY`: Master key for AES-256-GCM encryption (production recommended)

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

**Start the stack** :
```bash
cd GO/
docker-compose up -d
```

**Access CLI commands via container** (Phase 6 — admin commands) :
```bash
# Minions management
docker-compose exec relay-api secagent-server minions list --format table
docker-compose exec relay-api secagent-server minions get <hostname>
docker-compose exec relay-api secagent-server minions suspend <hostname>
docker-compose exec relay-api secagent-server minions resume <hostname>
docker-compose exec relay-api secagent-server minions revoke <hostname>
docker-compose exec relay-api secagent-server minions vars set <hostname> <key> <value>

# Security — Key rotation
docker-compose exec relay-api secagent-server security keys status
docker-compose exec relay-api secagent-server security keys rotate --grace 2h
docker-compose exec relay-api secagent-server security tokens list
docker-compose exec relay-api secagent-server security blacklist list

# Inventory
docker-compose exec relay-api secagent-server inventory list --only-connected

# Server status
docker-compose exec relay-api secagent-server server status --format json
```

**Format options** : `--format table|json|yaml` (default: table)

**Authentication** : CLI uses `ADMIN_TOKEN` env var from container (set in docker-compose.yml)

## Testing

### Unit Tests
```bash
cd GO/
RSA_MASTER_KEY=test ADMIN_TOKEN=test go test ./cmd/server/... -v -count=1
RSA_MASTER_KEY=test go test ./cmd/agent/... -v -count=1
```

### Integration Tests — CLI via Docker

**Smoke tests (basic CLI validation)** :
```bash
docker-compose up -d
docker-compose exec relay-api secagent-server minions list
docker-compose exec relay-api secagent-server security keys status
docker-compose exec relay-api secagent-server server status
docker-compose down
```

**Enrollment workflow test (Phase 6)** :
Test the full enrollment flow by revoking agents and validating ré-enrôlement:
```bash
# Start stack with 3 connected agents
docker-compose up -d

# 1. Verify agents are connected
docker-compose exec relay-api secagent-server minions list --format table
# Expected: qualif-host-01/02/03 with status=enrolled

# 2. Revoke agents to force ré-enrôlement
docker-compose exec relay-api secagent-server minions revoke qualif-host-01
docker-compose exec relay-api secagent-server minions revoke qualif-host-02
docker-compose exec relay-api secagent-server minions revoke qualif-host-03

# 3. Verify revocation (agents should disconnect then ré-enroll)
sleep 5
docker-compose exec relay-api secagent-server minions list --format table
# Expected: status should cycle through revoked → enrolled as agents reconnect

# 4. Validate ré-enrôlement completed
docker-compose exec relay-api secagent-server minions get qualif-host-01 --format json
# Check: enrolled_at timestamp updated, token_jti set in DB

# 5. Test authorized_keys flow (optional)
# Pre-authorize an agent's public key, then trigger ré-enrôlement
docker-compose exec relay-api secagent-server minions authorize qualif-host-01 --key-file agent_pubkey.pem
docker-compose exec relay-api secagent-server minions revoke qualif-host-01
# Verify agent ré-enrôles with authorized key validation passing

docker-compose down
```

**What this validates** :
- ✅ `RegisterAgent()` flow : authorized_keys lookup, JWT encryption, JTI persistence
- ✅ `AdminAuthorize()` : pre-authorization storage
- ✅ `TokenRefresh()` : 401 ré-enrôlement, new JWT encryption
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
- ✅ NATS stream configuration identical

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

### Phase 7 — Server Rewrite ✅
- ✅ handlers/register.go — Enrollment, JWT, RSA-4096
- ✅ handlers/exec.go — Task execution, file transfer
- ✅ handlers/inventory.go — Ansible inventory format
- ✅ handlers/admin.go — Admin endpoints (minions, status)
- ✅ ws/handler.go — WebSocket connections, dispatch
- ✅ storage/store.go — SQLite persistence
- ✅ broker/nats.go — NATS JetStream client
- ✅ main.go — HTTP server setup, request routing
- ✅ Unit tests — 80%+ coverage
- ✅ Docker — Dockerfile + docker-compose.yml
- ✅ go.mod/go.sum — Dependency lock files

### Phase 8 — Agent Rewrite ✅
- ✅ cmd/agent/main.go — Agent daemon
- ✅ internal/ws/dispatcher.go — WebSocket handler, rekey support
- ✅ internal/executor/executor.go — Subprocess execution
- ✅ internal/enrollment/ — RSA-4096, enrollment flow
- ✅ internal/registry/ — Async task registry
- ✅ internal/facts/ — System facts collection
- ✅ Handler rekey + 401 ré-enrôlement

### Phase 9 — Inventory Plugin ✅
- ✅ cmd/inventory/main.go — secagent-inventory binary
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
- **mTLS**: NATS connections in production (configurable)

## Performance Optimization

- **Compiled binary**: No Python startup overhead
- **Goroutine pooling**: Efficient WebSocket handling
- **Channel buffering**: Non-blocking result delivery
- **SQLite WAL**: Concurrent read support
- **Connection pooling**: Reduced DB overhead
- **NATS batching**: Efficient message bus

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
