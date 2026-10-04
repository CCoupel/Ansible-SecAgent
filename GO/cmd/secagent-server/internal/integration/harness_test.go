package integration

// Parent side of the harness: starts nodes (one OS process each), drives them through their
// public HTTP / WebSocket surface and captures every node's logs.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const waitLimit = 15 * time.Second

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !fn() {
		t.Fatalf("timeout after %s waiting for: %s", waitLimit, what)
	}
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// plain strips the double quotes: the servers may quote logged values (relay_id=root or
// relay_id="root"); the assertions must not depend on that formatting.
func plain(s string) string { return strings.ReplaceAll(s, `"`, "") }

func (s *syncBuf) count(sub string) int { return strings.Count(plain(s.String()), plain(sub)) }

func (s *syncBuf) has(sub string) bool { return s.count(sub) > 0 }

type nodeSpec struct {
	ID          string
	ParentURL   string // pull: this node dials its parent (wss://…)
	ParentToken string
	Env         []string
}

type node struct {
	t         *testing.T
	id        string
	url       string // https://127.0.0.1:port
	adminTok  string
	jwtSecret string
	logs      *syncBuf
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	plugin    string
}

var httpc = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed test certificate
}

func startNode(t *testing.T, spec nodeSpec) *node {
	t.Helper()
	n := &node{t: t, id: spec.ID, adminTok: "admin-" + spec.ID + "-secret-token", jwtSecret: "jwt-signing-secret-of-" + spec.ID + "-0123456789", logs: &syncBuf{}}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeProcess$", "-test.v")
	env := append(os.Environ(),
		envNodeProcess+"=1",
		"ADMIN_TOKEN="+n.adminTok,
		"JWT_SECRET_KEY="+n.jwtSecret,
		"RSA_MASTER_KEY=integration-master-key-"+spec.ID,
		"DATABASE_URL=sqlite:///"+t.TempDir()+"/relay.db",
		"REPEATER_ID="+spec.ID,
		"REPEATER_UPSTREAM_URL="+spec.ParentURL,
		"REPEATER_UPSTREAM_TOKEN="+spec.ParentToken,
	)
	cmd.Env = append(env, spec.Env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = n.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n.cmd, n.stdin = cmd, stdin
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, nodeReadyMarkerLine) && !sent {
				ready <- strings.TrimPrefix(line, nodeReadyMarkerLine)
				sent = true
				continue
			}
			_, _ = n.logs.Write([]byte(line + "\n"))
		}
	}()
	select {
	case n.url = <-ready:
	case <-time.After(waitLimit):
		_ = cmd.Process.Kill()
		t.Fatalf("node %s did not start; logs:\n%s", spec.ID, n.logs.String())
	}
	t.Cleanup(n.stop)
	return n
}

func (n *node) stop() {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.stdin.Close()
	done := make(chan struct{})
	go func() { _ = n.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	}
	n.cmd = nil
}

func (n *node) wssURL() string { return "wss" + strings.TrimPrefix(n.url, "https") }

// call issues an HTTP request on the node; bearer is the Authorization token.
func (n *node) call(method, path, bearer string, body any) (int, []byte) {
	n.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, n.url+path, rd)
	if err != nil {
		n.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpc.Do(req)
	if err != nil {
		n.t.Fatalf("%s %s on %s: %v", method, path, n.id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (n *node) admin(method, path string, body any) (int, map[string]any) {
	n.t.Helper()
	code, raw := n.call(method, path, n.adminTok, body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return code, m
}

// pluginToken lazily creates the plugin token used for /api/exec, upload, fetch, inventory.
func (n *node) pluginToken() string {
	n.t.Helper()
	if n.plugin == "" {
		code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "plugin", "description": "integration"})
		if code != http.StatusCreated {
			n.t.Fatalf("create plugin token on %s: %d %v", n.id, code, m)
		}
		n.plugin = m["token"].(string)
	}
	return n.plugin
}

// registerChild registers a pull child on this node and returns the relay token it must present.
func (n *node) registerChild(childID string) string {
	n.t.Helper()
	tok, _ := n.registerChildWithID(childID)
	return tok
}

// registerChildWithID also returns the relay's internal id (used by the revoke endpoint).
func (n *node) registerChildWithID(childID string) (token, id string) {
	n.t.Helper()
	code, m := n.admin("POST", "/api/admin/relays", map[string]any{"relay_id": childID, "mode": "pull"})
	if code != http.StatusCreated {
		n.t.Fatalf("register child %s on %s: %d %v", childID, n.id, code, m)
	}
	return m["jwt_token"].(string), m["id"].(string)
}

// mintParentToken mints on THIS (child) node a relay-parent token for the parent parentID.
func (n *node) mintParentToken(parentID string) (token, id string) {
	n.t.Helper()
	exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-parent", "sub": parentID, "expires_at": exp})
	if code != http.StatusCreated {
		n.t.Fatalf("mint relay-parent token on %s: %d %v", n.id, code, m)
	}
	return m["token"].(string), m["id"].(string)
}

type execResult struct {
	Code int
	Body map[string]any
}

func (n *node) exec(host string, body map[string]any) execResult {
	n.t.Helper()
	code, raw := n.call("POST", "/api/exec/"+host, n.pluginToken(), body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return execResult{Code: code, Body: m}
}

// inventoryHosts returns the hosts of the node's aggregated inventory (relay-routed ones included).
func (n *node) inventoryHosts() map[string]map[string]any {
	n.t.Helper()
	code, raw := n.call("GET", "/api/inventory", n.pluginToken(), nil)
	if code != http.StatusOK {
		n.t.Fatalf("inventory on %s: %d %s", n.id, code, raw)
	}
	var inv struct {
		Meta struct {
			Hostvars map[string]map[string]any `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		n.t.Fatal(err)
	}
	return inv.Meta.Hostvars
}

func (n *node) hasHost(host string) bool { _, ok := n.inventoryHosts()[host]; return ok }

type health struct {
	Degraded bool `json:"degraded"`
	Links    struct {
		Upstream *struct {
			Mode   string `json:"mode"`
			Peer   string `json:"peer"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"upstream"`
		Push []struct {
			RelayID string `json:"relay_id"`
			State   string `json:"state"`
			Reason  string `json:"reason"`
		} `json:"push_children"`
	} `json:"links"`
}

// health returns the DETAILED link state, which lives on the admin status (the public /health
// only exposes the degraded flag, see publicHealth).
func (n *node) health() health {
	n.t.Helper()
	code, raw := n.call("GET", "/api/admin/status", n.adminTok, nil)
	if code != http.StatusOK {
		n.t.Fatalf("admin status on %s: %d %s", n.id, code, raw)
	}
	var st struct {
		Links struct {
			Upstream *struct {
				Mode   string `json:"mode"`
				Peer   string `json:"peer"`
				State  string `json:"state"`
				Reason string `json:"reason"`
			} `json:"upstream"`
			Push []struct {
				RelayID string `json:"relay_id"`
				State   string `json:"state"`
				Reason  string `json:"reason"`
			} `json:"push_children"`
			Degraded bool `json:"degraded"`
		} `json:"links"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		n.t.Fatal(err)
	}
	h := health{Degraded: st.Links.Degraded}
	h.Links.Upstream = st.Links.Upstream
	h.Links.Push = st.Links.Push
	return h
}

// publicHealth returns the raw body of the unauthenticated /health.
func (n *node) publicHealth() string {
	n.t.Helper()
	code, raw := n.call("GET", "/health", "", nil)
	if code != http.StatusOK {
		n.t.Fatalf("/health on %s answered %d: it must stay 200", n.id, code)
	}
	return string(raw)
}

func (n *node) upstreamState() string {
	if u := n.health().Links.Upstream; u != nil {
		return u.State
	}
	return ""
}

func (n *node) pushState(child string) string {
	for _, p := range n.health().Links.Push {
		if p.RelayID == child {
			return p.State
		}
	}
	return ""
}

// closeRelay makes this node cut its link with the child relay using the given close code.
func (n *node) closeRelay(child string, code int) {
	n.t.Helper()
	status, raw := n.call("POST", fmt.Sprintf("/__test/close-relay?id=%s&code=%d", child, code), "", nil)
	if status != http.StatusOK || !strings.Contains(string(raw), "true") {
		n.t.Fatalf("close-relay %s on %s: %d %s", child, n.id, status, raw)
	}
}

// ── minion ───────────────────────────────────────────────────────────────────

type minion struct {
	host string
	mu   sync.Mutex
	got  []map[string]any
	conn *websocket.Conn
}

func (m *minion) received() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]map[string]any(nil), m.got...)
}

// connectMinion opens a real /ws/agent link signed with the node's secret and answers tasks.
func connectMinion(t *testing.T, n *node, host string) *minion {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": host, "role": "agent", "jti": "agent-" + host,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(n.jwtSecret))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second} //nolint:gosec // test cert
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		t.Fatalf("minion %s dial %s: %v (resp %v)", host, n.id, err, resp)
	}
	m := &minion{host: host, conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		for {
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			m.mu.Lock()
			m.got = append(m.got, msg)
			m.mu.Unlock()
			reply := map[string]any{"task_id": msg["task_id"], "type": "result", "rc": 0}
			switch msg["type"] {
			case "exec":
				reply["stdout"] = fmt.Sprintf("ran %q on %s", msg["cmd"], host)
			case "fetch_file":
				reply["data"] = "ZmV0Y2hlZA=="
			case "put_file":
			default:
				continue
			}
			_ = conn.WriteJSON(reply)
		}
	}()
	return m
}

// allLogs concatenates the logs of every given node.
func allLogs(nodes ...*node) string {
	var sb strings.Builder
	for _, n := range nodes {
		sb.WriteString("=== " + n.id + " ===\n" + n.logs.String())
	}
	return sb.String()
}
