# GO Migration — Starting Phase 7

## Status
- **Commit**: e4f1deb (mvp-python-v1.0)
- **Tag**: mvp-python-v1.0
- **Branch**: master
- **Ready**: ✅ YES

## Snapshot Verified

### Python MVP Running
```bash
# Agents deployed
curl http://192.168.1.218:7770/health
# → {"status": "ok", "db": "ok", "nats": "ok"}

# Inventory working
curl http://192.168.1.218:7772/api/inventory
# → {"all": {"hosts": ["qualif-host-01", "qualif-host-02", "qualif-host-03"]}, ...}

# 3 agents connected
relay minions list  # (if CLI running)
```

### Codebase Size
- **Server**: 240K (routes_register.py, routes_exec.py, ws_handler.py, agent_store.py, nats_client.py, main_multi_port.py)
- **Agent**: 85K (secagent_agent.py, facts_collector.py, async_registry.py)
- **Total Python**: ~325K

### Tools Ready
- ✅ Claude API (convert_python_to_go.py)
- ✅ Task automation (Taskfile-conversion.yml)
- ✅ GO 1.25.5
- ✅ Conversion strategy (550+ lines)

---

## Phase 7 Launch Checklist

### Prerequisites
- [ ] Verify Python MVP is running stable on 192.168.1.218
- [ ] Confirm all agents are connected (status: connected)
- [ ] Verify inventory endpoint returns all hosts
- [ ] Backup /data/relay.db (database)
- [ ] Document current performance baseline (latency, memory)

### Environment Setup
```bash
# 1. Install task runner
go install github.com/go-task/task/v3/cmd/task@latest

# 2. Install conversion dependencies
pip install anthropic

# 3. Verify GO setup
go version
# → go version go1.25.5 windows/amd64

# 4. Test conversion tool
python3 tools/convert_python_to_go.py --help
```

### Phase 7 Execution
```bash
# Full automated pipeline (including manual review points)
cd /c/Users/cyril/Documents/VScode/Ansible_Agent

# OPTION A: Fully automated (4-5 hours)
task phase7
# → Analyze → Convert → Format → Lint → Test → Build

# OPTION B: Step-by-step (with manual review)
task analyze              # Extract Python structure
task convert-server       # Claude API conversion
task format              # goimports + gofmt
task lint                # staticcheck
task test-server         # Unit + E2E tests
task build-server        # Compile binary
```

---

## Expected Output

### Step 1: Analysis
```
✅ Analysis: 6 files, 20 functions, 4 classes
```

### Step 2: Conversion
```
✅ Wrote: cmd/server/internal/handlers/register.go
✅ Wrote: cmd/server/internal/handlers/exec.go
✅ Wrote: cmd/server/internal/handlers/inventory.go
✅ Wrote: cmd/server/internal/ws/handler.go
✅ Wrote: cmd/server/internal/storage/agent_store.go
✅ Wrote: cmd/server/internal/broker/nats.go
```

### Step 3: Format & Lint
```
✅ Formatting complete
✅ Linting complete (0 warnings)
```

### Step 4: Build
```
✅ Built: secagent-server (single binary, ~10MB)
```

### Step 5: Test
```
✅ Unit tests: 50/50 passed
✅ E2E tests: 15/15 passed (backward-compat verified)
```

---

## Success Criteria (Phase 7)

### API Compatibility
- ✅ All endpoints: `/api/register`, `/api/exec`, `/api/inventory`, `/ws/agent`
- ✅ Response formats: Identical to Python version
- ✅ Error codes: Same HTTP status codes
- ✅ Protocol: WebSocket unchanged

### Performance
- ✅ Latency: p95 < 10ms (vs 100ms Python)
- ✅ Memory: < 10MB per instance (vs 100MB Python)
- ✅ Throughput: 1000+ req/s
- ✅ Startup: < 50ms

### Quality
- ✅ Test coverage: 80%+
- ✅ Lint warnings: 0
- ✅ Code review: idiomatic GO
- ✅ Documentation: inline comments

---

## Rollback Plan

If Phase 7 fails at any point:

```bash
# Revert to Python MVP
git checkout mvp-python-v1.0

# Restart Python server
cd ansible_server
docker-compose up -d

# Agents reconnect automatically (backward compatible)
# No data loss (SQLite database preserved)
```

---

## Timeline

| Task | Duration | Status |
|------|----------|--------|
| Analyze | ~5 min | ⏳ |
| Convert (Claude API) | ~15 min | ⏳ |
| Manual refactoring | ~2-4 hours | ⏳ |
| Format + Lint | ~5 min | ⏳ |
| Unit tests | ~15 min | ⏳ |
| E2E tests | ~15 min | ⏳ |
| Build | ~2 min | ⏳ |
| **Total** | **~3-5 hours** | **⏳ READY** |

---

## Launch Command

```bash
# Ready to start Phase 7 Server Rewrite?
task phase7
```

**Status**: ✅ READY TO MIGRATE

---

## Notes

1. **Parallel work possible**: Phase 7 (server) and Phase 8 (agent) can run simultaneously
2. **No downtime**: Python MVP remains deployed during migration
3. **Backward compatible**: Can test GO server alongside Python agents
4. **Full rollback**: Any point up to Phase 9 can rollback to mvp-python-v1.0

---

Generated: 2026-03-05
Commit: e4f1deb
Tag: mvp-python-v1.0
