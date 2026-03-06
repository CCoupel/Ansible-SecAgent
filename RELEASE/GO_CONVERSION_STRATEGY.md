# GO Conversion Strategy — Outils et processus de migration Python → GO

## Vue d'ensemble

Conversion semi-automatique du code Python (relay-agent, relay-server) vers GO compilé.

**Approche** : Combinaison d'outils automatiques + refactoring manuel

```
Python codebase
    ↓
[Automated analysis]
  - AST parsing (pylint, ast module)
  - Type hints extraction
  - Dependency mapping
    ↓
[Code generation]
  - Generative AI (Claude API)
  - go-bindings generators
  - sqlc for SQL queries
    ↓
[Manual review & refactoring]
  - Idiom conversion (Pythonic → Goist)
  - Error handling (.py exception → GO error)
  - Concurrency model (async → goroutines)
    ↓
GO codebase
    ↓
[Testing & validation]
  - Existing E2E tests run against GO binary
  - Performance baseline established
    ↓
Production deployment
```

---

## 1. Outils automatiques

### A. Code Analysis & Extraction

#### 1.1 Python AST Analysis
```python
# analyze_python.py — Extract structure from Python source

import ast
import json

class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.functions = []
        self.classes = []
        self.imports = []

    def visit_FunctionDef(self, node):
        self.functions.append({
            'name': node.name,
            'args': [arg.arg for arg in node.args.args],
            'returns': ast.get_source_segment(code, node),
            'decorators': [d.id for d in node.decorator_list if hasattr(d, 'id')],
        })
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes.append({
            'name': node.name,
            'methods': [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
        })
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

# Usage
analyzer = PythonAnalyzer()
analyzer.visit(tree)
print(json.dumps({
    'functions': analyzer.functions,
    'classes': analyzer.classes,
    'imports': analyzer.imports,
}, indent=2))
```

**Output**: JSON structure of entire Python codebase

#### 1.2 Type Hints Extraction
```bash
# Use pylint to extract types
pylint --disable=all --enable=type-hints relay_agent.py > types.json

# Or mypy
mypy --strict --ignore-missing-imports relay_agent.py > types.txt

# Extract via inspecting runtime annotations
python3 -c "
import relay_agent
import inspect

for name, obj in inspect.getmembers(relay_agent):
    if callable(obj):
        sig = inspect.signature(obj)
        print(f'{name}: {sig}')
"
```

#### 1.3 Dependency Graph
```bash
# pipdeptree — Show all Python dependencies
pipdeptree > python_deps.txt

# deptree (GO equivalent we'll use)
go mod graph > go_deps.txt

# Manual mapping: Python lib → GO equivalent
# Example:
#   fastapi → gin-gonic/gin
#   pydantic → github.com/go-playground/validator
#   asyncio → goroutines + channels
```

---

### B. Automated Code Generation

#### 2.1 Claude API for Conversion
```python
# convert_python_to_go.py — Use Claude API to convert code

import anthropic
import sys

def convert_python_to_go(python_code: str) -> str:
    """Convert Python function to GO using Claude API."""
    client = anthropic.Anthropic()

    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        system="""You are an expert GO programmer. Convert Python code to idiomatic GO.

Rules:
1. Use stdlib whenever possible (crypto/*, encoding/json, net/http)
2. Error handling: use if err != nil pattern, not exceptions
3. Concurrency: use goroutines + channels, not async/await
4. Naming: CamelCase for exported, camelCase for private
5. Type safety: define structs for complex types, use interfaces
6. No nil pointers: use error returns or Optional pattern
7. No generics unless Go 1.18+
8. Defer for cleanup (like Python context managers)

Return ONLY the GO code, with comments explaining key differences.""",
        messages=[
            {
                "role": "user",
                "content": f"Convert this Python code to GO:\n\n```python\n{python_code}\n```"
            }
        ]
    )

    return message.content[0].text

# Usage
with open('relay_agent.py', 'r') as f:
    python_code = f.read()

go_code = convert_python_to_go(python_code)
print(go_code)
```

**Flow**:
1. Read Python file in chunks (per function)
2. Call Claude API for each function
3. Assemble GO file from converted chunks
4. Manual review + formatting

#### 2.2 sqlc for Database Queries
```bash
# Install sqlc
go install github.com/kyleconroy/sqlc/cmd/sqlc@latest

# Create sqlc.yaml
cat > sqlc.yaml << 'EOF'
version: "2"
sql:
  - schema: "schema.sql"  # Convert from Python ORM queries
    queries: "queries.sql"  # SQL queries extracted from agent_store.py
    engine: "sqlite"
    gen:
      go:
        package: "storage"
        out: "agent/storage"
EOF

# Generate type-safe GO code
sqlc generate
```

**Benefits**:
- Type-safe SQL queries
- No reflection overhead
- Compile-time validation

#### 2.3 go-bindings for Dynamic Code
```bash
# For WebSocket + async patterns, use code generators

# Install task runner
go install github.com/go-task/task/v3/cmd/task@latest

# Taskfile.yml for automation
cat > Taskfile.yml << 'EOF'
version: '3'

tasks:
  analyze:
    cmds:
      - python3 analyze_python.py > codebase.json

  convert:
    cmds:
      - python3 convert_python_to_go.py < relay_agent.py > relay_agent.go

  generate:
    cmds:
      - go generate ./...

  build:
    cmds:
      - go build -o relay-agent ./cmd/agent
      - go build -o relay-server ./cmd/server

  test:
    cmds:
      - go test ./... -v
      - bash test_e2e.sh  # Run existing pytest against GO binary
EOF

# Run automated pipeline
task analyze convert generate build test
```

---

## 2. Refactoring Manual (Idiom Conversion)

### A. Exception Handling → Error Returns

**Python**:
```python
def register_agent(hostname: str, public_key_pem: str) -> str:
    try:
        auth_rec = store.get_authorized_key(hostname)
        if auth_rec is None:
            raise HTTPException(status_code=403, detail="Not authorized")

        jwt_token = _issue_jwt(hostname)
        return jwt_token
    except Exception as e:
        logger.error(f"Enrollment failed: {e}")
        raise
```

**GO**:
```go
func (s *Server) RegisterAgent(hostname, publicKeyPEM string) (string, error) {
    authRec, err := s.store.GetAuthorizedKey(hostname)
    if err != nil {
        logger.Error("failed to lookup authorized key", "error", err)
        return "", fmt.Errorf("lookup failed: %w", err)
    }

    if authRec == nil {
        logger.Warn("enrollment rejected", "hostname", hostname)
        return "", ErrHostnameNotAuthorized  // Custom error type
    }

    jwtToken, err := s.issueJWT(hostname)
    if err != nil {
        logger.Error("failed to issue JWT", "error", err)
        return "", fmt.Errorf("jwt issue failed: %w", err)
    }

    return jwtToken, nil
}

// Custom error types
var ErrHostnameNotAuthorized = errors.New("hostname not authorized")
```

### B. Async/Await → Goroutines + Channels

**Python (FastAPI async)**:
```python
@router.post("/api/exec/{hostname}")
async def exec_command(hostname: str, body: ExecRequest, request: Request):
    store: AgentStore = request.app.state.store
    nats_client = request.app.state.nats_client

    # Async NATS publish
    await nats_client.publish(f"RELAY_TASKS", json.dumps(payload))

    # Wait for result (async future)
    result = await asyncio.wait_for(
        futures[task_id],
        timeout=30
    )
    return result
```

**GO**:
```go
func (s *Server) ExecCommand(w http.ResponseWriter, r *http.Request) {
    hostname := chi.URLParam(r, "hostname")
    var req ExecRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), 400)
        return
    }

    // Goroutine + channel for async wait
    resultChan := make(chan interface{}, 1)
    s.pendingFutures[taskID] = resultChan
    defer delete(s.pendingFutures, taskID)

    // Publish to NATS (non-blocking)
    err := s.nats.Publish("RELAY_TASKS", payload)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    // Wait for result with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    select {
    case result := <-resultChan:
        json.NewEncoder(w).Encode(result)
    case <-ctx.Done():
        http.Error(w, "timeout", 504)
    }
}
```

### C. Classes → Structs + Methods

**Python**:
```python
class AgentStore:
    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path)

    async def get_agent(self, hostname: str) -> Dict:
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE hostname = ?", (hostname,))
        row = cursor.fetchone()
        return dict(row) if row else None
```

**GO**:
```go
type AgentStore struct {
    db *sql.DB  // Use database/sql
}

func NewAgentStore(dbPath string) (*AgentStore, error) {
    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, err
    }
    return &AgentStore{db: db}, nil
}

func (s *AgentStore) GetAgent(ctx context.Context, hostname string) (map[string]interface{}, error) {
    row := s.db.QueryRowContext(ctx, "SELECT * FROM agents WHERE hostname = ?", hostname)

    var agent map[string]interface{}
    // Use sqlc generated code or manual scanning
    err := row.Scan(&agent.ID, &agent.Hostname, ...)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return agent, nil
}
```

### D. Decorators → Middleware/Wrapper Functions

**Python (FastAPI)**:
```python
@router.post("/api/admin/authorize")
async def admin_authorize(body: AdminAuthorizeRequest, request: Request,
                         authorization: str = Header(None)):
    # Dependency injection: require_role("admin")
    store = request.app.state.store
    token = extract_bearer(authorization)
    payload = await verify_jwt(token, store)
    # ...
```

**GO**:
```go
// Middleware wrapper
func (s *Server) adminOnly(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractBearer(r.Header.Get("Authorization"))
        payload, err := s.verifyJWT(r.Context(), token)
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        if payload.Role != "admin" {
            http.Error(w, "Forbidden", 403)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// Usage
router.Post("/api/admin/authorize", s.adminOnly(s.AdminAuthorize))
```

---

## 3. Phase-by-Phase Conversion Process

### Phase 7 Conversion (Server)

```
Week 1: Analysis & Preparation
  ✅ Extract Python AST from routes_register.py, routes_exec.py, etc
  ✅ Map Python types to GO types
  ✅ Identify cryptography patterns (RSA, JWT)
  ✅ Create GO project layout (cmd/server, pkg/storage, pkg/broker)

Week 2-3: Code Generation + Refactoring
  ✅ Convert handlers/register.go (Claude API)
  ✅ Convert handlers/exec.go (Claude API)
  ✅ Convert handlers/inventory.go (Claude API)
  ✅ Convert ws/handler.go (manual, WebSocket complex)
  ✅ Convert storage/agent_store.go (sqlc + manual)
  ✅ Convert broker/nats.go (NATS-GO lib)
  ✅ Manual refactoring: idioms, error handling

Week 4: Testing & Integration
  ✅ Unit tests (gotest)
  ✅ E2E tests (run existing pytest against GO binary)
  ✅ Performance baseline (latency, memory)
  ✅ Integration with Python agents (cross-version testing)
```

### Phase 8 Conversion (Agent)

```
Week 1-2: Conversion
  ✅ Extract relay_agent.py → relay_agent.go (main.go)
  ✅ Convert facts_collector.py → agent/facts.go
  ✅ Convert async_registry.py → agent/registry.go
  ✅ Subprocess handling: os/exec package

Week 3: Testing
  ✅ Unit tests
  ✅ E2E enrollment tests
  ✅ Cross-version testing (GO agent ↔ Python server, Python agent ↔ GO server)
```

### Phase 9 Conversion (Wrappers)

```
Week 1: Wrappers
  ✅ Simple CLI converters (hand-written, ~200 lines each)
  ✅ No complex logic, just HTTP calls + parsing
```

---

## 4. Tools & Dependencies for Conversion

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Claude API** | Code generation | `pip install anthropic` |
| **pylint** | Type extraction | `pip install pylint` |
| **mypy** | Type checking | `pip install mypy` |
| **ast module** | Python analysis | Built-in |
| **sqlc** | SQL codegen | `go install github.com/kyleconroy/sqlc/cmd/sqlc@latest` |
| **go-task** | Task automation | `go install github.com/go-task/task/v3/cmd/task@latest` |
| **gopls** | IDE support | `go install golang.org/x/tools/gopls@latest` |
| **staticcheck** | Linting | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| **goimports** | Format + imports | `go install golang.org/x/tools/cmd/goimports@latest` |

---

## 5. Validation Strategy

### A. API Contract Testing
```bash
# E2E tests UNCHANGED — run against both Python and GO

# Python (current)
RELAY_SERVER=http://localhost:7770 pytest tests/e2e/test_enrollment.py -v

# GO (new)
RELAY_SERVER=http://localhost:7770 pytest tests/e2e/test_enrollment.py -v
# Same tests, both should pass
```

### B. Performance Baseline
```bash
# Before migration
python3 -c "
import time
import requests

start = time.time()
for i in range(1000):
    requests.post('http://localhost:7770/api/register', json={...})
elapsed = time.time() - start
print(f'Python: {elapsed/1000*1000:.2f}ms per request')
"

# After migration
# Same test, expect 20x improvement
```

### C. Binary Compatibility
```bash
# Run existing agents against GO server
# Run GO agents against Python server
# Verify protocol compatibility
```

---

## 6. Automation Script Example

```bash
#!/bin/bash
# convert_relay_server.sh — Automated conversion pipeline

set -e

PYTHON_SRC="server/api"
GO_SRC="server"
PYTHON_ANALYSIS="analysis.json"

echo "=== Step 1: Analyze Python codebase ==="
python3 << 'EOF'
import ast
import json
import os

analysis = {
    'files': {},
    'functions': [],
    'classes': [],
    'imports': set()
}

for root, dirs, files in os.walk('server/api'):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path) as f:
                try:
                    tree = ast.parse(f.read())
                    analysis['files'][path] = {
                        'functions': [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)],
                        'classes': [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)],
                    }
                except:
                    print(f"Failed to parse {path}")

with open('$PYTHON_ANALYSIS', 'w') as f:
    # JSON needs custom encoder for sets
    import json
    json.dump(analysis, f, default=str, indent=2)
EOF

echo "✅ Analysis complete: $PYTHON_ANALYSIS"

echo "=== Step 2: Extract types with mypy ==="
mypy server/api/ --show-column-numbers > types.txt 2>&1 || true

echo "=== Step 3: Generate GO structure ==="
mkdir -p "$GO_SRC"/cmd/server "$GO_SRC"/pkg/{handlers,storage,broker}
go mod init ansiblerelay-server || true
go mod edit -require github.com/gorilla/websocket@latest
go mod edit -require github.com/nats-io/nats.go@latest
go mod tidy

echo "=== Step 4: Convert Python → GO via Claude API ==="
python3 convert_python_to_go.py \
    --input server/api/routes_register.py \
    --output server/pkg/handlers/register.go

python3 convert_python_to_go.py \
    --input server/api/routes_exec.py \
    --output server/pkg/handlers/exec.go

# ... repeat for other files

echo "=== Step 5: Generate SQL code with sqlc ==="
sqlc generate

echo "=== Step 6: Format and lint ==="
goimports -w ./...
staticcheck ./...

echo "=== Step 7: Test ==="
go test ./... -v
bash tests/e2e/test_against_go_server.sh

echo "✅ Conversion complete!"
```

---

## 7. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| **Missed edge cases** | Keep E2E tests, run against both versions |
| **Performance regression** | Baseline before, measure after, profile hotspots |
| **Breaking API changes** | Verify HTTP contracts, use API contract testing |
| **Dependency issues** | Vendor dependencies, test offline builds |
| **Team skill gap** | Pair programming, code review, GO workshops |
| **Rollback complexity** | Keep Python branches, use feature flags for cutover |

---

## 8. Success Criteria

✅ **Code quality**
- Zero test failures (pytest E2E)
- staticcheck: zero warnings
- Test coverage: ≥ 80%

✅ **Performance**
- Latency: p95 < 10ms (vs 100ms Python)
- Memory: < 10MB per server instance
- Throughput: 1000+ req/s

✅ **Compatibility**
- API contracts 100% compatible
- WebSocket protocol unchanged
- Can inter-op with Python components

✅ **Deployment**
- Single binary (no runtime deps)
- K8s manifest unchanged
- Systemd service unchanged

---

## Resources

### GO Learning
- [Go Tour](https://go.dev/tour/)
- [Effective GO](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### Libraries & Tools
- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [gorilla/websocket](https://github.com/gorilla/websocket)
- [NATS-GO Client](https://github.com/nats-io/nats.go)
- [sqlc](https://sqlc.dev/)
- [Go Benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)

### Conversion Patterns
- [Python to GO conversion guide](https://github.com/golang/wiki/wiki/ProjectsInTheWild)
- [async → goroutines](https://go.dev/blog/pipelines)
- [exception → error handling](https://go.dev/blog/error-handling-and-go)
