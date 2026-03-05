# Phase 7: Server Rewrite — GO Conversion Progress

**Status**: INITIATED
**Start Date**: 2026-03-05
**Target Duration**: 3-5 hours (initial conversion), 6-8 weeks (full phases 7-9)

---

## Objective

Rewrite Python relay-server (2,585 LOC) to idiomatic GO for:
- **Performance**: p95 latency 100ms → 5ms (20x improvement)
- **Memory**: 100MB → 10MB per instance (10x reduction)
- **Type Safety**: Compiled binary prevents reverse engineering of .pyc files
- **Concurrency**: Handle 500+ agents vs 50 agents with Python

---

## Phase 7: Server Rewrite

### Checkpoint 1: Structure & Stubs ✅ COMPLETED

```
cmd/server/internal/
├── handlers/
│   ├── register.go      (enrollment, JWT, RSA-OAEP)
│   ├── exec.go          (task execution, file transfer)
│   └── inventory.go     (Ansible inventory format)
├── ws/
│   └── handler.go       (WebSocket agent connections)
├── storage/
│   └── store.go         (SQLite database access)
└── broker/
    └── nats.go          (JetStream pub/sub)
```

**Analysis Summary:**
- Total Python code: 2,585 lines
- Files converted: 6 modules
- Stub structure: Created with TODO markers for implementation

### Checkpoint 2: Implementation (IN PROGRESS)

**Priority Order:**

1. **Routes/Handlers** (routes_register.py, routes_exec.py, routes_inventory.py)
   - Migrate FastAPI route handlers to http.Handler
   - Convert Pydantic models to Go structs
   - Implement JWT signing/verification (golang-jwt/jwt)
   - RSA encryption: crypto/rsa, OAEP padding

2. **Database Layer** (agent_store.py)
   - SQLite queries (database/sql + github.com/mattn/go-sqlite3)
   - Agent registration CRUD
   - Authorized keys management
   - JTI blacklist operations

3. **Message Broker** (nats_client.py)
   - NATS JetStream streams (RELAY_TASKS, RELAY_RESULTS)
   - Publish/subscribe patterns
   - Stream configuration (retention, persistence)

4. **WebSocket Handler** (ws_handler.py)
   - websocket upgrade (gorilla/websocket)
   - Per-agent persistent connection
   - Message multiplexing by task_id
   - Graceful disconnection/reconnection

5. **Main Application** (main_multi_port.py)
   - Multi-port FastAPI → net/http mux
   - Lifespan management (init/shutdown)
   - Shared state (database, NATS, agents)
   - Health checks on ports 7770/7771/7772

### Checkpoint 3: Testing & Validation (TODO)

- Unit tests: 80%+ coverage required
- E2E backward compatibility with Python agents
- Performance baseline: latency, memory, throughput
- API contract verification (routes, response formats)

### Checkpoint 4: Build & Deployment (TODO)

- Compile to single binary (~10MB expected)
- Docker image for qualification testing
- Kubernetes manifests for production
- Gradual rollout (canary testing)

---

## Key Conversion Patterns

### Python → GO

| Python | GO | Notes |
|--------|-----|-------|
| `async/await` | goroutines + channels | Use `context.Context` for cancellation |
| `try/except` | `if err != nil` | Always check errors from library calls |
| Pydantic `BaseModel` | `struct` tags | Use JSON struct tags for HTTP |
| FastAPI `@app.post()` | `http.HandleFunc` | Return http.Handler or ResponseWriter |
| `asyncio.run()` | `sync.WaitGroup` + `go func()` | Manage goroutine lifecycle |
| SQLAlchemy queries | `database/sql` | Use prepared statements to prevent SQL injection |
| Python `dict` | `map[string]interface{}` or typed struct | Prefer structs for known schemas |
| `asyncio.Lock()` | `sync.RWMutex` | Reader/writer locks for concurrent access |

### Dependencies

```go
// Core
import (
    "net/http"
    "database/sql"
    "context"
    "crypto/rsa"
    "sync"
)

// Third-party
import (
    "github.com/golang-jwt/jwt/v5"          // JWT signing
    "github.com/mattn/go-sqlite3"            // SQLite driver
    "github.com/nats-io/nats.go"             // NATS JetStream
    "github.com/gorilla/websocket"           // WebSocket upgrade
    "github.com/google/uuid"                 // UUID generation
)
```

---

## Success Criteria

### API Compatibility
- ✅ All 5 endpoints return identical formats to Python version
- ✅ HTTP status codes match (200, 201, 400, 403, 409, etc.)
- ✅ WebSocket protocol unchanged (message format, multiplexing)
- ✅ JWT token format identical (HS256 signature, claims)

### Performance (Baseline: Python MVP @ 192.168.1.218)
- ✅ p95 latency: < 10ms (baseline: 100ms)
- ✅ Memory per instance: < 10MB RSS (baseline: 100MB)
- ✅ Throughput: 1000+ req/s (baseline: 50 req/s)
- ✅ Startup: < 50ms (baseline: 500ms)

### Code Quality
- ✅ 80%+ unit test coverage
- ✅ 0 linting warnings (staticcheck)
- ✅ Idiomatic GO (per Go Code Review Comments)
- ✅ Inline documentation for public functions

### Deployment Validation
- ✅ Docker image builds and runs (< 50MB)
- ✅ Health checks pass on all 3 ports
- ✅ E2E test: Python agents ↔ GO server (agents still on Python v1.0)
- ✅ Backward compatible (can rollback to mvp-python-v1.0)

---

## Timeline

| Task | Estimated Duration | Status |
|------|--------------------|--------|
| Structure & stubs | 30 min | ✅ DONE |
| Implement handlers (register, exec, inventory) | 90 min | ⏳ |
| Implement database layer | 60 min | ⏳ |
| Implement NATS broker | 45 min | ⏳ |
| Implement WebSocket handler | 60 min | ⏳ |
| Implement main app + health checks | 30 min | ⏳ |
| Format + lint | 15 min | ⏳ |
| Unit tests | 90 min | ⏳ |
| Manual code review & cleanup | 60 min | ⏳ |
| Build & E2E test | 30 min | ⏳ |
| **Total** | **~7-8 hours** | **⏳** |

---

## Rollback Plan

If any checkpoint fails:

```bash
# Revert to Python MVP
git checkout mvp-python-v1.0
cd ansible_server
docker-compose up -d

# Agents reconnect automatically (3-5 seconds)
# No data loss (SQLite database preserved in /data/relay.db)
```

---

## Notes

1. **Parallel work possible**: Phase 7 (server) and Phase 8 (agent) can run simultaneously after checkpoint 3
2. **No downtime**: Python MVP remains deployed during development
3. **Backward compatible**: GO server accepts Python agents (same protocol)
4. **Full coverage**: All Python features must be in GO version before Phase 8 starts

---

**Generated**: 2026-03-05
**Commit**: 56a8a9f (Phase 7 stubs initialized)
