# Architecture — Réarchitecturation vers GO (Performance & Sécurité)

## Analyse : Python vs GO pour AnsibleRelay

### Composants critiques

```
relay-agent (client)      | relay-server (API + broker) | plugins Ansible
────────────────────────────────────────────────────────────────────────────
Python (léger)            | Python FastAPI (bottleneck)  | Python (plugins)
Subprocess exec           | JWT, RSA, NATS               | HTTP calls
WSS WebSocket             | Multi-port (7770/7771/7772)  | Inventory, exec
```

### Comparaison Python vs GO

| Aspect | Python | GO | Impact |
|--------|--------|----|---------
| **Performance** | ~100ms p95 latency | ~5ms p95 latency | 20x faster API |
| **Memory** | 50-100MB per process | 5-10MB per process | 10x reduction |
| **Startup** | 500ms (imports) | 10ms (compiled) | Faster K8s startup |
| **Concurrency** | Threads/asyncio | Goroutines | Better handling |
| **Security** | Runtime, injection risk | Compiled, type-safe | Fewer vuln classes |
| **Deployment** | Requirements.txt + runtime | Single binary | Simpler image |
| **Latency SLA** | Difficult at scale | Easy (p95 < 10ms) | Production-ready |

---

## Stratégie de migration par phases

### Phase 7 — Server Rewrite (GO)
**Objectif** : Réécrire relay-server (FastAPI) en GO pour performance + sécurité

**Composants à migrer** :
- `routes_register.py` → `handlers/register.go` (enrollment, JWT)
- `routes_exec.py` → `handlers/exec.go` (exec, upload, fetch)
- `routes_inventory.py` → `handlers/inventory.go` (/api/inventory)
- `ws_handler.py` → `ws/handler.go` (WebSocket agent connections)
- `agent_store.py` → `storage/agent_store.go` (SQLite wrapper)
- `nats_client.py` → `broker/nats.go` (NATS JetStream)
- `main_multi_port.py` → `main.go` (multi-port app)

**Benefits** :
- ✅ API latency : 100ms → 5ms (20x)
- ✅ Memory : 100MB → 10MB per instance (10x)
- ✅ Single binary (no Python runtime)
- ✅ Type-safe (RSA, JWT, crypto)
- ✅ Concurrency optimized (high connection count)

**Stack** :
- Framework : Gin (lightweight) ou Echo (features)
- Crypto : `crypto/rsa`, `crypto/sha256`, `github.com/golang-jwt/jwt`
- DB : `github.com/mattn/go-sqlite3`
- NATS : `github.com/nats-io/nats.go`
- WebSocket : `github.com/gorilla/websocket`

**Tâches** : 12 (similar to Phase 2)

---

### Phase 8 — Agent Rewrite (GO)
**Objectif** : Réécrire relay-agent (Python daemon) en GO

**Composants à migrer** :
- `relay_agent.py` → `agent/main.go` (enrollment, WSS, dispatcher)
- `facts_collector.py` → `agent/facts.go` (system facts collection)
- `async_registry.py` → `agent/registry.go` (async task registry)

**Benefits** :
- ✅ Memory : 30MB → 2-3MB per agent
- ✅ Faster startup (10ms vs 500ms)
- ✅ Better subprocess isolation
- ✅ Single systemd binary (easier deployment)
- ✅ No Python garbage collector latency

**Stack** :
- Core : net, crypto, syscall packages
- WebSocket : `github.com/gorilla/websocket`
- Process : `os/exec` (native subprocess handling)
- Facts : `github.com/shirou/gopsutil` (system metrics)

**Tâches** : 10 (simpler than server)

---

### Phase 9 — Plugins Rewrite (GO)
**Objectif** : Réécrire plugins Ansible en GO (wrapper)

**Problem** : Ansible plugins DOIVENT être en Python (InventoryModule, ConnectionBase)
**Solution** : Wrapper GO qui appelle Python pour les plugins

**Architecture** :
```
ansible-playbook
    ↓
relay_inventory.py (Python, unchanged)
    ↓ calls
relay-inventory-go (compiled binary)
    ↓
HTTP /api/inventory (relay-server:7772)
    ↓
    response

relay.py (Python ConnectionBase, unchanged)
    ↓ calls via exec
relay-exec-go (compiled binary)
    ↓
HTTP /api/exec/{host} (relay-server:7771)
    ↓
response
```

**Alternative** : Réécrire plugins directement si Ansible API le permet
- Possible mais complex (Ansible plugin API très Python-centric)
- Wrapper GO est plus pragmatique

**Tâches** : 5 (minimal change, mostly CLI wrapping)

---

## Migration path détaillé

### Current state (MVP Python)
```
relay-agent (Python 3.11)    ← daemon léger
    ↓ (WSS)
relay-server (Python FastAPI) ← API bottleneck ⚠️
    ↓ (HTTP)
ansible_plugins/ (Python)    ← required by Ansible
    ↓
playbooks (Ansible standard)
```

### Post-migration (optimized GO)
```
relay-agent (GO compiled)           ← 2-3MB, 10ms startup
    ↓ (WSS)
relay-server (GO compiled)          ← 10MB, 5ms latency, high concurrency
    ↓ (HTTP)
relay-inventory-go wrapper (GO)     ← calls Python plugin for Ansible
ansible_plugins/relay.py (Python)   ← unchanged, calls relay-exec-go
ansible_plugins/relay_inventory.py  ← unchanged
    ↓
playbooks (Ansible standard)
```

---

## Backend API endpoints (Phase 7)

```go
// Registration & Auth
POST   /api/register              ← enrollment with RSA encryption
POST   /api/admin/authorize       ← pre-authorize public key
POST   /api/token/refresh         ← refresh JWT with challenge

// WebSocket
GET    /ws/agent/{hostname}       ← agent connection

// Exec API
POST   /api/exec/{hostname}       ← execute command
POST   /api/upload/{hostname}     ← put file
POST   /api/fetch/{hostname}      ← fetch file

// Inventory
GET    /api/inventory             ← list minions (Ansible format)

// Management (Phase 6 CLI backend)
GET    /api/admin/minions         ← list all minions
GET    /api/admin/minions/{id}    ← detail minion
DELETE /api/admin/minions/{id}    ← delete minion
POST   /api/admin/minions/{id}/revoke ← revoke token

// Health
GET    /health                    ← health check
```

---

## Sécurité améliorée (GO)

| Aspect | Python risk | GO benefit |
|--------|-------------|-----------|
| **Crypto** | Runtime crypto.py | compile-time type checking |
| **RSA-4096** | Possible, mais slow | Hardware-accelerated |
| **JWT signing** | python-jose, vulnérable | Standard lib, no deps |
| **SQL injection** | String formatting risk | Parameterized queries |
| **Buffer overflow** | Python safe, mais overhead | GO memory safety |
| **Reverse engineering** | .pyc files analyzable | Compiled binary opaque |
| **Dependencies** | 50+ transitive deps | Vendored, scanned |

---

## Performance targets (Phase 7)

| Métrique | Current (Python) | Target (GO) | SLA |
|----------|------------------|------------|-----|
| API p95 latency | 100ms | < 10ms | ✅ |
| API p99 latency | 200ms | < 20ms | ✅ |
| Memory/instance | 100MB | 10MB | ✅ |
| K8s startup | 30s | 5s | ✅ |
| Throughput | 100 req/s | 1000+ req/s | ✅ |
| Concurrent agents | 50 | 500+ | ✅ |

---

## Compatibility & Transition

### Non-breaking
- ✅ API contracts remain unchanged
- ✅ WebSocket protocol unchanged
- ✅ Ansible plugins interface unchanged
- ✅ Database schema unchanged
- ✅ Kubernetes manifests compatible

### Backward-compatible deployment
```yaml
Phase 4: FastAPI Python (MVP production)
Phase 5: Hardening (Python, still)
Phase 6: CLI management (Python + Python API)
Phase 7: Rewrite server GO (drop-in replacement)
Phase 8: Rewrite agent GO (drop-in systemd service)
Phase 9: Plugins wrapper GO (transparent to Ansible)
```

---

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Rewrite time | 2-3 months | Parallelize phases, smaller MVP first |
| GO skill gap | Team learning curve | Workshops, code review, pair programming |
| Testing | Regression risk | E2E tests from Phase 3 still pass |
| K8s Dockerfile | New image build | Multi-stage build, binary only |
| Rollback | Version control | Keep Python branches, feature flags |

---

## Implementation order

**Phase 7 (Server)** → Phase 8 (Agent) → Phase 9 (Plugins wrapper)

Reasoning :
1. Server first = most impactful (API latency, concurrency)
2. Agent second = deployable independently (no Ansible changes)
3. Plugins last = minimal impact, wrapper only

---

## Resources

### GO Learning
- `https://go.dev/doc/` (official docs)
- `https://go.dev/tour/` (interactive tour)
- Books : "The GO Programming Language" (Donovan & Kernighan)

### Libraries
- Gin : `https://github.com/gin-gonic/gin` (web framework)
- gorilla/websocket : `https://github.com/gorilla/websocket`
- NATS GO : `https://github.com/nats-io/nats.go`
- gopsutil : `https://github.com/shirou/gopsutil` (system stats)
- sqlc : `https://sqlc.dev/` (type-safe SQL)

### CI/CD
- Multi-arch builds : `docker buildx`
- Binary releases : GitHub Actions
- Kubernetes : same as Python (no changes)

---

## Timeline estimate

- Phase 7 (Server rewrite) : 3-4 weeks (12 tasks)
- Phase 8 (Agent rewrite) : 2-3 weeks (10 tasks)
- Phase 9 (Plugins wrapper) : 1 week (5 tasks)

**Total** : 6-8 weeks post-Phase 6

---

## Decision: Should we migrate?

**YES, Phase 7+** because:
1. ✅ MVP (Phase 1-6) validates requirements
2. ✅ Production deployment (Phase 4+) requires performance
3. ✅ Security hardening (Phase 5) needs compiled binaries
4. ✅ Kubernetes scale → need <10ms latency
5. ✅ GO ecosystem mature for infrastructure tools

**NOT immediately** because:
- Phase 4-6 works with Python (validates market fit)
- GO rewrite can be parallel
- Start Phase 7 after Phase 5 validation
