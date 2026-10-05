package integration

// Parent side of the harness: starts nodes (one OS process each, through the real entry point
// internal/server), drives them through their public / admin HTTPS and WebSocket surface and
// captures every node's logs.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/crypto"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// waitLimit is only ever reached on failure (every wait polls every 5 ms), so it costs nothing when
// green. Each node is a separate process: on a machine at load average 40+ (QA, shared runners) a
// process start / reconnection alone can stall for more than 30 s.
const waitLimit = 60 * time.Second

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

// expectLog asserts that sub shows up in the log (bounded wait). The node is a separate process:
// its log reaches this buffer through a pipe, ASYNCHRONOUSLY, so a line written by the server
// BEFORE it answered (HTTP status, close frame) may not be in the buffer yet when the test
// observes that answer — never assert a log with has() right after waiting for something else.
func (s *syncBuf) expectLog(t *testing.T, sub, why string) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if s.has(sub) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !s.has(sub) {
		t.Errorf("%s (no %q after %s):\n%s", why, sub, waitLimit, s.String())
	}
}

type nodeSpec struct {
	ID          string
	ParentURL   string // pull: this node dials its parent (wss://…)
	ParentToken string
	Env         []string
	// Hooks builds the node's hooks configuration (JSON) from the file its file-actions append to;
	// nil = no hooks file (the node starts with 0 hooks).
	Hooks func(out string) string
}

type node struct {
	t         *testing.T
	id        string
	ready     nodeReady // listeners of the node (host:port) and control URL
	adminTok  string
	jwtSecret string
	env       []string // environment of the node process (restart reuses it)
	hooksPath string   // RELAY_HOOKS_CONFIG of the node
	hookOut   string   // file the hooks' file-actions append to
	logs      *syncBuf
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	plugin    string
}

// ── shared test material: TLS certificate and RSA key ────────────────────────
//
// Every node serves the same self-signed certificate (SAN 127.0.0.1) and trusts it through
// SSL_CERT_FILE, so node-to-node and client-to-node verification is REAL. The RSA key pre-seeds
// each node's database so the real InitServerState loads it instead of generating a 4096-bit key.

var (
	sharedOnce sync.Once
	sharedErr  error
	sharedDir  string
	certPath   string
	keyPath    string
	tlsPool    *x509.CertPool
	rsaKeyPEM  string
	httpc      *http.Client
)

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedDir != "" {
		_ = os.RemoveAll(sharedDir)
	}
	os.Exit(code)
}

// slots bounds the number of scenarios running at once: every scenario starts 2-3 real nodes
// (each a race-instrumented process with its own database), 14 at a time starve even a big runner.
var slots = make(chan struct{}, 5)

// parallel runs the test concurrently with the others, within the slot limit.
func parallel(t *testing.T) {
	t.Helper()
	t.Parallel()
	slots <- struct{}{}
	t.Cleanup(func() { <-slots })
}

func initShared() error {
	dir, err := os.MkdirTemp("", "secagent-integration-")
	if err != nil {
		return err
	}
	sharedDir = dir
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "secagent-integration"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	tlsPool = x509.NewCertPool()
	tlsPool.AppendCertsFromPEM(certPEM)
	httpc = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsClientConfig()}}

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rkDER, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		return err
	}
	rsaKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rkDER}))
	return nil
}

func tlsClientConfig() *tls.Config {
	return &tls.Config{RootCAs: tlsPool, MinVersion: tls.VersionTLS12}
}

// seedDatabase pre-creates the node's database with its RSA key (encrypted like in production).
func seedDatabase(t *testing.T, dbPath, masterKey string) {
	t.Helper()
	st, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.EncryptAESGCM(rsaKeyPEM, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConfigSet(context.Background(), "rsa_key_current", "enc:"+enc); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func startNode(t *testing.T, spec nodeSpec) *node {
	t.Helper()
	n := prepareNode(t, spec)
	n.launch(nil)
	t.Cleanup(n.stop)
	return n
}

// prepareNode builds the node's identity, database and environment without starting it.
func prepareNode(t *testing.T, spec nodeSpec) *node {
	t.Helper()
	if err := func() error { sharedOnce.Do(func() { sharedErr = initShared() }); return sharedErr }(); err != nil {
		t.Fatalf("shared test material: %v", err)
	}
	n := &node{t: t, id: spec.ID, adminTok: "admin-" + spec.ID + "-secret-token", jwtSecret: "jwt-signing-secret-of-" + spec.ID + "-0123456789", logs: &syncBuf{}}
	masterKey := "integration-master-key-" + spec.ID
	dbPath := filepath.Join(t.TempDir(), "relay.db")
	n.hooksPath = filepath.Join(t.TempDir(), "hooks.json")
	n.hookOut = filepath.Join(t.TempDir(), "hooks.out")
	if spec.Hooks != nil {
		if err := os.WriteFile(n.hooksPath, []byte(spec.Hooks(n.hookOut)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seedDatabase(t, dbPath, masterKey)

	n.env = append(append(os.Environ(),
		envNodeProcess+"=1",
		envNodeCert+"="+certPath, envNodeKey+"="+keyPath,
		"SSL_CERT_FILE="+certPath, // the node trusts the test certificate: real TLS verification
		"ADMIN_TOKEN="+n.adminTok,
		"JWT_SECRET_KEY="+n.jwtSecret,
		"RSA_MASTER_KEY="+masterKey,
		"DATABASE_URL=sqlite:///"+dbPath,
		"RELAY_ACTION_LOG="+filepath.Join(filepath.Dir(dbPath), "actions.log"),
		"RELAY_HOOKS_CONFIG="+n.hooksPath, // absent unless spec.Hooks: 0 hooks active
		"REPEATER_ID="+spec.ID,
		"REPEATER_UPSTREAM_URL="+spec.ParentURL,
		"REPEATER_UPSTREAM_TOKEN="+spec.ParentToken,
	), spec.Env...)
	return n
}

// dbScalar runs a read-only query on the node's database file and returns its first column.
func (n *node) dbScalar(query string) string {
	n.t.Helper()
	path := ""
	for _, e := range n.env {
		if strings.HasPrefix(e, "DATABASE_URL=sqlite:///") {
			path = strings.TrimPrefix(e, "DATABASE_URL=sqlite:///")
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		n.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v sql.NullString
	if err := db.QueryRow(query).Scan(&v); err != nil {
		n.t.Fatalf("%s: %v", query, err)
	}
	return v.String
}

// enrollAgent records host in the node's database with the given current JTI, as an enrollment
// would: /ws/agent refuses (401) a token whose agent is unknown or whose JTI is not the current one
// (#169). It goes through the database file because the node is a separate process.
func (n *node) enrollAgent(host, jti string) {
	n.t.Helper()
	path := ""
	for _, e := range n.env {
		if strings.HasPrefix(e, "DATABASE_URL=sqlite:///") {
			path = strings.TrimPrefix(e, "DATABASE_URL=sqlite:///")
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		n.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=10000"); err != nil {
		n.t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO agents (hostname, public_key_pem, token_jti, enrolled_at, last_seen, status)
		VALUES (?, 'pem', ?, ?, ?, 'disconnected')
		ON CONFLICT(hostname) DO UPDATE SET token_jti = excluded.token_jti`,
		host, jti, now, now); err != nil {
		n.t.Fatalf("enroll %s: %v", host, err)
	}
}

// setEnv sets (or replaces) one environment variable of the node for its NEXT start / restart.
func (n *node) setEnv(key, value string) {
	for i, e := range n.env {
		if strings.HasPrefix(e, key+"=") {
			n.env[i] = key + "=" + value
			return
		}
	}
	n.env = append(n.env, key+"="+value)
}

// runExpectingExit starts the node process and returns its exit code and combined output; it is for
// configurations the server must REFUSE to start with (the process is expected to exit by itself).
func (n *node) runExpectingExit() (code int, output string) {
	n.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeProcess$", "-test.v")
	cmd.Env = append([]string(nil), n.env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		n.t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	var out syncBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		n.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), out.String()
		}
		return 0, out.String()
	case <-time.After(waitLimit):
		_ = cmd.Process.Kill()
		<-done
		return -1, out.String() + "\n(the process did not exit: it must have started)"
	}
}

// launch starts the node process with n.env (+ extra) and waits until it serves.
func (n *node) launch(extra []string) {
	t := n.t
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeProcess$", "-test.v")
	cmd.Env = append(append([]string(nil), n.env...), extra...)
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
	ready := make(chan nodeReady, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, readyMarker) && !sent {
				var r nodeReady
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, readyMarker)), &r); err == nil {
					ready <- r
					sent = true
					continue
				}
			}
			_, _ = n.logs.Write([]byte(line + "\n"))
		}
	}()
	select {
	case n.ready = <-ready:
	case <-time.After(waitLimit):
		_ = cmd.Process.Kill()
		t.Fatalf("node %s did not start; logs:\n%s", n.id, n.logs.String())
	}
}

// restart stops the node and starts it again on the SAME database file, the same identity, secrets,
// configuration and the SAME listening addresses (so that peers configured with its URL find it).
func (n *node) restart() {
	n.t.Helper()
	prev := n.ready
	n.stop()
	n.launch([]string{"NODE_API_ADDR=" + prev.API, "NODE_ADMIN_ADDR=" + prev.Admin, "NODE_WS_ADDR=" + prev.WS})
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
	case <-time.After(40 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	}
	n.cmd = nil
}

// setHooks rewrites the node's hooks file (the node only reads it at start-up and on reloadHooks).
func (n *node) setHooks(content string) {
	n.t.Helper()
	if err := os.WriteFile(n.hooksPath, []byte(content), 0o600); err != nil {
		n.t.Fatal(err)
	}
}

// reloadHooks makes the node re-read its hooks file, like a SIGHUP does.
func (n *node) reloadHooks() {
	n.t.Helper()
	resp, err := http.Post(n.ready.Control+"/reload-hooks", "text/plain", nil)
	if err != nil {
		n.t.Fatalf("reload hooks on %s: %v", n.id, err)
	}
	_ = resp.Body.Close()
}

// hookLines returns what the node's hooks wrote so far, one entry per line.
func (n *node) hookLines() []string {
	b, _ := os.ReadFile(n.hookOut)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func (n *node) hookHas(prefix string) bool {
	for _, l := range n.hookLines() {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func (n *node) hookCount(prefix string) int {
	c := 0
	for _, l := range n.hookLines() {
		if strings.HasPrefix(l, prefix) {
			c++
		}
	}
	return c
}

// Listeners of the node. Each one is a SEPARATE TLS listener, like the production ports.
func (n *node) apiURL() string   { return "https://" + n.ready.API }
func (n *node) adminURL() string { return "https://" + n.ready.Admin }
func (n *node) wsURL() string    { return "https://" + n.ready.WS }

// wssURL is where relays and minions connect (the WebSocket listener).
func (n *node) wssURL() string { return "wss://" + n.ready.WS }

// callOn issues an HTTPS request on the given base URL; bearer is the Authorization token.
func (n *node) callOn(base, method, path, bearer string, body any) (int, []byte) {
	n.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
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
		n.t.Fatalf("%s %s%s on %s: %v", method, base, path, n.id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// call is a request on the PUBLIC API listener.
func (n *node) call(method, path, bearer string, body any) (int, []byte) {
	n.t.Helper()
	return n.callOn(n.apiURL(), method, path, bearer, body)
}

// admin is a request on the ADMIN listener with the node's admin token.
func (n *node) admin(method, path string, body any) (int, map[string]any) {
	n.t.Helper()
	code, raw := n.callOn(n.adminURL(), method, path, n.adminTok, body)
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
	code, raw := n.callOn(n.adminURL(), "GET", "/api/admin/status", n.adminTok, nil)
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
	resp, err := http.Post(fmt.Sprintf("%s/close-relay?id=%s&code=%d", n.ready.Control, child, code), "text/plain", nil)
	if err != nil {
		n.t.Fatalf("close-relay %s on %s: %v", child, n.id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "true") {
		n.t.Fatalf("close-relay %s on %s: %d %s", child, n.id, resp.StatusCode, raw)
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
	n.enrollAgent(host, "agent-"+host)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": host, "role": "agent", "jti": "agent-" + host,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(n.jwtSecret))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
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
