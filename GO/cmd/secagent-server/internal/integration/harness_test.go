package integration

// Parent side of the harness: starts nodes (one OS process each, through the real entry point
// internal/server), drives them through their public / admin HTTPS and WebSocket surface and
// captures every node's logs.

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/state"
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
	// Root is the root relay that signs the link tokens of the tree (v3.0.4, #141): a node that has a
	// parent is anchored on its public key (REPEATER_ROOT_LINK_KEY_FILE). Implied by a ParentToken
	// minted through registerChild; give it explicitly for a push child (its parent dials in).
	Root *node
	Env  []string
	// NoMasterKey starts the node WITHOUT RSA_MASTER_KEY on a state created in the explicit test mode
	// (secrets in clear, `state init --insecure-test-mode`): the only way a node can run without a master
	// key. Used to test what the server must refuse to do without one (mint of link tokens → 503).
	NoMasterKey bool
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
	stateDir  string   // STATE_DIR of the node
	hooksPath string   // RELAY_HOOKS_CONFIG of the node
	hookOut   string   // file the hooks' file-actions append to
	logs      *syncBuf
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	plugin    string
	root      *node // the root relay of the tree this node belongs to (nil for the root itself)

	statusPath   string         // RELAY_STATUS_FILE of this instance (local, outside STATE_DIR)
	pendingReady chan nodeReady // of a secondary: receives the addresses once it is promoted
	exited       chan struct{}  // closed when the current process ended
	exitCode     int            // its exit code (valid once exited is closed)
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

var (
	stateTplMu sync.Mutex
	stateTpl   = map[string]string{}
)

// seedState creates the node's state like `secagent-server state init` does (RSA key and JWT secret
// encrypted with the node's master key). The RSA-2048 generation is done once per master key.
func seedState(t *testing.T, dir, masterKey string) {
	t.Helper()
	stateTplMu.Lock()
	tpl, ok := stateTpl[masterKey]
	if !ok {
		d, err := os.MkdirTemp("", "secagent-itest-state-*")
		if err != nil {
			stateTplMu.Unlock()
			t.Fatal(err)
		}
		if err := state.Init(state.InitOptions{Dir: d, MasterKey: masterKey, RSABits: 2048}); err != nil {
			stateTplMu.Unlock()
			t.Fatal(err)
		}
		tpl = filepath.Join(d, state.StateFile)
		stateTpl[masterKey] = tpl
	}
	stateTplMu.Unlock()
	data, err := os.ReadFile(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, state.StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func startNode(t *testing.T, spec nodeSpec) *node {
	t.Helper()
	n := prepareNode(t, spec)
	n.launch(nil)
	t.Cleanup(n.stop)
	t.Cleanup(func() { // registered last = runs first: a failed test keeps the node's life-cycle lines
		if t.Failed() {
			var keep []string
			for _, l := range strings.Split(n.logs.String(), "\n") {
				if strings.Contains(l, "lock") || strings.Contains(l, "SHUTDOWN") || strings.Contains(l, "SECURITY") || strings.Contains(l, "INIT") || strings.Contains(l, "ERROR") {
					keep = append(keep, l)
				}
			}
			t.Logf("life-cycle lines of node %s:\n%s", n.id, strings.Join(keep, "\n"))
		}
	})
	return n
}

// prepareNode builds the node's identity, database and environment without starting it.
func prepareNode(t *testing.T, spec nodeSpec) *node {
	t.Helper()
	if err := func() error { sharedOnce.Do(func() { sharedErr = initShared() }); return sharedErr }(); err != nil {
		t.Fatalf("shared test material: %v", err)
	}
	root := spec.Root
	if root == nil && spec.ParentToken != "" {
		if r, ok := tokenRoots.Load(spec.ParentToken); ok {
			root = r.(*node)
		}
	}
	n := &node{t: t, id: spec.ID, adminTok: "admin-" + spec.ID + "-secret-token", jwtSecret: "jwt-signing-secret-of-" + spec.ID + "-0123456789", logs: &syncBuf{}}
	masterKey := "integration-master-key-" + spec.ID
	stateDir := filepath.Join(t.TempDir(), "state")
	n.stateDir = stateDir
	n.hooksPath = filepath.Join(t.TempDir(), "hooks.json")
	n.hookOut = filepath.Join(t.TempDir(), "hooks.out")
	if spec.Hooks != nil {
		if err := os.WriteFile(n.hooksPath, []byte(spec.Hooks(n.hookOut)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if spec.NoMasterKey {
		if err := state.Init(state.InitOptions{Dir: stateDir, AllowPlaintext: true, RSABits: 2048}); err != nil {
			t.Fatal(err)
		}
		masterKey = ""
	} else {
		seedState(t, stateDir, masterKey)
	}

	n.statusPath = filepath.Join(t.TempDir(), "status.json")
	n.env = append(append(os.Environ(),
		envNodeProcess+"=1",
		"TLS_DISABLE=true",       // the harness wraps the listeners in TLS itself (injected listeners)
		"ADMIN_ADDR=127.0.0.1:0", // loopback: the admin port is not under test here (#175b); the listener is injected anyway
		envNodeCert+"="+certPath, envNodeKey+"="+keyPath,
		"SSL_CERT_FILE="+certPath, // the node trusts the test certificate: real TLS verification
		"ADMIN_TOKEN="+n.adminTok,
		"JWT_SECRET_KEY="+n.jwtSecret,
		"RSA_MASTER_KEY="+masterKey,
		"NODE_INSECURE_STATE="+map[bool]string{true: "1", false: ""}[spec.NoMasterKey],
		"STATE_DIR="+stateDir,
		"RELAY_ACTION_LOG="+filepath.Join(filepath.Dir(stateDir), "actions.log"),
		"RELAY_HOOKS_CONFIG="+n.hooksPath, // absent unless spec.Hooks: 0 hooks active
		"RELAY_STATUS_FILE="+n.statusPath, // local health file, outside STATE_DIR
		"REPEATER_ID="+spec.ID,
		"REPEATER_UPSTREAM_URL="+spec.ParentURL,
		"REPEATER_UPSTREAM_TOKEN="+spec.ParentToken,
	), spec.Env...)
	if root != nil {
		n.anchorTo(root)
	}
	return n
}

// tokenRoots remembers which root signed a link token handed out by registerChild: a node started
// with that token is anchored on that root.
var tokenRoots sync.Map

// anchorTo pins the root's public key (REPEATER_ROOT_LINK_KEY_FILE) and identity (REPEATER_ROOT_ID) in
// the environment of the node: it then verifies the link tokens signed by that root.
func (n *node) anchorTo(root *node) {
	n.t.Helper()
	code, m := root.admin("GET", "/api/admin/link/pubkey", nil)
	pem, _ := m["current_pub_pem"].(string)
	if code != http.StatusOK || pem == "" {
		n.t.Fatalf("root %s link public key: %d %v", root.id, code, m)
	}
	path := filepath.Join(n.t.TempDir(), "root_link.pub")
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		n.t.Fatal(err)
	}
	n.root = root
	n.setEnv("REPEATER_ROOT_ID", root.id)
	n.setEnv("REPEATER_ROOT_LINK_KEY_FILE", path)
}

// treeRoot is the node that signs the link tokens of the tree n belongs to.
func (n *node) treeRoot() *node {
	if n.root != nil {
		return n.root
	}
	return n
}

// statePayload returns the permanent data of the node as written in its relay.state (the file is
// read-only for the test: the node is its single writer). Volatile data (routing, relay status,
// last_seen) is never in it.
func (n *node) statePayload() map[string]json.RawMessage {
	n.t.Helper()
	raw, err := os.ReadFile(filepath.Join(n.stateDir, state.StateFile))
	if err != nil {
		n.t.Fatal(err)
	}
	var env struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		n.t.Fatalf("relay.state of %s: %v", n.id, err)
	}
	return env.Payload
}

// stateSection decodes one section (e.g. "relay_nodes", "agents") of the state file.
func (n *node) stateSection(name string) map[string]map[string]any {
	n.t.Helper()
	out := map[string]map[string]any{}
	if raw, ok := n.statePayload()[name]; ok {
		if err := json.Unmarshal(raw, &out); err != nil {
			n.t.Fatalf("state section %s: %v", name, err)
		}
	}
	return out
}

// agentKey is the RSA key every harness minion enrolls with.
var (
	agentKeyOnce sync.Once
	agentKey     *rsa.PrivateKey
	agentKeyPEM  string
)

var agentKeyErr error

func harnessAgentKeyErr() (*rsa.PrivateKey, string, error) {
	agentKeyOnce.Do(func() {
		// 4096 bits like a real minion: a JWT does not fit in an RSA-OAEP block of a 2048-bit key
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			agentKeyErr = err
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		agentKey, agentKeyPEM = k, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	})
	return agentKey, agentKeyPEM, agentKeyErr
}

// enrollAgent enrolls host through the REAL flow (admin pre-authorization of its key, then
// POST /api/register) and returns the JWT the server issued: /ws/agent refuses a token whose agent
// is unknown or whose JTI is not the current one (#169), and the server signs with the secret of
// its state.
func (n *node) enrollAgent(host string) string {
	n.t.Helper()
	tok, err := n.enrollAgentErr(host)
	if err != nil {
		n.t.Fatal(err)
	}
	return tok
}

// enrollAgentErr is enrollAgent for goroutines other than the test's (it never calls t.Fatal).
func (n *node) enrollAgentErr(host string) (string, error) {
	key, pubPEM, err := harnessAgentKeyErr()
	if err != nil {
		return "", err
	}
	// 1. the operator creates a one-shot enrollment token bound to this hostname (#192c: there is no
	// tokenless enrollment any more)
	code, raw, err := n.callErr("POST", n.adminURL(), "/api/admin/tokens", n.adminTok,
		map[string]any{"role": "enrollment", "hostname_pattern": regexp.QuoteMeta(host), "created_by": "harness"})
	if err != nil || code >= 300 {
		return "", fmt.Errorf("enrollment token for %s on %s: %d %s %v", host, n.id, code, raw, err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Token == "" {
		return "", fmt.Errorf("enrollment token response of %s: %v %s", host, err, raw)
	}
	// 2. step 1: the server answers with a nonce encrypted with the agent's public key
	code, raw, err = n.callErr("POST", n.apiURL(), "/api/register", "",
		map[string]any{"hostname": host, "public_key_pem": pubPEM, "enrollment_token": tok.Token})
	if err != nil || code != http.StatusOK {
		return "", fmt.Errorf("register step 1 of %s on %s: %d %s %v", host, n.id, code, raw, err)
	}
	var ch struct {
		Challenge       string `json:"challenge"`
		ServerPublicKey string `json:"server_public_key_pem"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil || ch.Challenge == "" || ch.ServerPublicKey == "" {
		return "", fmt.Errorf("register step 1 response of %s: %v %s", host, err, raw)
	}
	ctBytes, err := base64.StdEncoding.DecodeString(ch.Challenge)
	if err != nil {
		return "", err
	}
	nonce, err := rsa.DecryptOAEP(sha256.New(), nil, key, ctBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt the challenge of %s: %w", host, err)
	}
	// 3. step 2: prove possession of the private key: OAEP(nonce + token, server public key)
	block, _ := pem.Decode([]byte(ch.ServerPublicKey))
	if block == nil {
		return "", fmt.Errorf("server public key of %s: no PEM block", host)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	serverPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("server public key of %s is not RSA", host)
	}
	resp2, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPub, append(append([]byte{}, nonce...), []byte(tok.Token)...), nil)
	if err != nil {
		return "", err
	}
	code, raw, err = n.callErr("POST", n.apiURL(), "/api/register", "",
		map[string]any{"hostname": host, "public_key_pem": pubPEM, "enrollment_token": tok.Token,
			"challenge_response": base64.StdEncoding.EncodeToString(resp2)})
	if err != nil || code != http.StatusOK {
		return "", fmt.Errorf("register step 2 of %s on %s: %d %s %v", host, n.id, code, raw, err)
	}
	var resp struct {
		TokenEncrypted string `json:"token_encrypted"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.TokenEncrypted == "" {
		return "", fmt.Errorf("register response of %s: %v %s", host, err, raw)
	}
	ct, err := base64.StdEncoding.DecodeString(resp.TokenEncrypted)
	if err != nil {
		return "", err
	}
	jwtRaw, err := rsa.DecryptOAEP(sha256.New(), nil, key, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt the token of %s: %w", host, err)
	}
	return string(jwtRaw), nil
}

// callErr is callOn for goroutines other than the test's.
func (n *node) callErr(method, base, path, bearer string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
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
	n.t.Helper()
	ready, _ := n.startProcess(extra)
	select {
	case n.ready = <-ready:
	case <-n.exited:
		n.t.Fatalf("node %s exited with code %d before serving; logs:\n%s", n.id, n.exitCode, n.logs.String())
	case <-time.After(waitLimit):
		_ = n.cmd.Process.Kill()
		n.t.Fatalf("node %s did not start; logs:\n%s", n.id, n.logs.String())
	}
}

// launchSecondary starts an instance that is expected to WAIT for the lock (no port): it returns once
// the process runs its lock loop.
func (n *node) launchSecondary(extra []string) {
	n.t.Helper()
	ready, started := n.startProcess(extra)
	n.pendingReady = ready
	select {
	case <-started:
	case <-n.exited:
		n.t.Fatalf("instance %s exited with code %d; logs:\n%s", n.id, n.exitCode, n.logs.String())
	case <-time.After(waitLimit):
		_ = n.cmd.Process.Kill()
		n.t.Fatalf("instance %s did not start; logs:\n%s", n.id, n.logs.String())
	}
}

// startProcess runs the child; ready receives the serving addresses (once promoted), started is
// closed at the first line the child prints (its lock loop is about to run).
func (n *node) startProcess(extra []string) (ready chan nodeReady, started chan struct{}) {
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
	n.exited = make(chan struct{})
	exited := n.exited
	ready = make(chan nodeReady, 1)
	started = make(chan struct{})
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(stdout)
		sent, startedSent := false, false
		for sc.Scan() {
			line := sc.Text()
			if line == startedMarker && !startedSent {
				startedSent = true
				close(started)
				continue
			}
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
	go func() {
		<-scanDone // every read of the pipe is done before Wait closes it
		_ = cmd.Wait()
		n.exitCode = cmd.ProcessState.ExitCode()
		close(exited)
	}()
	return ready, started
}

// waitExit waits for the process to end by itself and returns its exit code.
func (n *node) waitExit(d time.Duration) (code int, ok bool) {
	select {
	case <-n.exited:
		return n.exitCode, true
	case <-time.After(d):
		return 0, false
	}
}

// sibling is a SECOND instance of the same node: same identity, secrets, configuration and the SAME
// STATE_DIR (shared storage), its own logs, local status file and process.
func (n *node) sibling() *node {
	s := *n
	s.logs = &syncBuf{}
	s.cmd, s.stdin, s.exited, s.exitCode, s.ready = nil, nil, nil, 0, nodeReady{}
	s.env = append([]string(nil), n.env...)
	s.statusPath = filepath.Join(n.t.TempDir(), "status.json")
	s.setEnv("RELAY_STATUS_FILE", s.statusPath)
	return &s
}

// restart stops the node and starts it again on the SAME database file, the same identity, secrets,
// configuration and the SAME listening addresses (so that peers configured with its URL find it).
func (n *node) restart() {
	n.t.Helper()
	prev := n.ready
	n.stop()
	n.launch([]string{"NODE_API_ADDR=" + prev.API, "NODE_ADMIN_ADDR=" + prev.Admin, "NODE_WS_ADDR=" + prev.WS})
}

// kill9 stops the node like a crash (SIGKILL, no graceful shutdown) and restarts it on its previous
// addresses and its persistent state. The crashed master leaves its lock behind: the new process
// waits for it to go stale (the fast calibration of the children: a few seconds).
func (n *node) kill9() {
	n.t.Helper()
	prev := n.ready
	n.killNow()
	n.launch([]string{"NODE_API_ADDR=" + prev.API, "NODE_ADMIN_ADDR=" + prev.Admin, "NODE_WS_ADDR=" + prev.WS})
}

// killNow SIGKILLs the process and waits for it to be gone (no restart).
func (n *node) killNow() {
	n.t.Helper()
	if n.cmd == nil || n.cmd.Process == nil {
		n.t.Fatal("kill: node not running")
	}
	_ = n.cmd.Process.Kill()
	<-n.exited
	_ = n.stdin.Close()
	n.cmd = nil
}

// freeze / thaw: SIGSTOP / SIGCONT (a frozen process: VM pause, storage stall).
func (n *node) freeze() { n.t.Helper(); _ = n.cmd.Process.Signal(syscall.SIGSTOP) }
func (n *node) thaw()   { n.t.Helper(); _ = n.cmd.Process.Signal(syscall.SIGCONT) }

func (n *node) stop() {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.stdin.Close()
	select {
	case <-n.exited:
	case <-time.After(40 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.exited
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

// registerChildWithID declares a pull child on this node and returns the relay-child link token the
// ROOT of the tree minted for it (aud = this node, the verifier), plus the relay's internal id (used by
// the revoke endpoint). v3.0.4: the declaration itself mints nothing.
func (n *node) registerChildWithID(childID string) (token, id string) {
	n.t.Helper()
	code, m := n.admin("POST", "/api/admin/relays", map[string]any{"relay_id": childID, "mode": "pull"})
	if code != http.StatusCreated {
		n.t.Fatalf("register child %s on %s: %d %v", childID, n.id, code, m)
	}
	root := n.treeRoot()
	code, tk := root.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-child", "sub": childID, "aud": n.id})
	if code != http.StatusCreated {
		n.t.Fatalf("mint relay-child %s -> %s on root %s: %d %v", childID, n.id, root.id, code, tk)
	}
	token, _ = tk["token"].(string)
	tokenRoots.Store(token, root)
	return token, m["id"].(string)
}

// mintParentToken returns a relay-parent link token for the parent parentID to present to THIS
// node (sub = the parent, aud = this node), signed by the root of the tree.
func (n *node) mintParentToken(parentID string) (token, id string) {
	n.t.Helper()
	exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	root := n.treeRoot()
	code, m := root.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-parent", "sub": parentID, "aud": n.id, "expires_at": exp})
	if code != http.StatusCreated {
		n.t.Fatalf("mint relay-parent token for %s on root %s: %d %v", n.id, root.id, code, m)
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
	// closed receives the error that ended the read loop (a *websocket.CloseError for a close frame)
	closed chan error
}

// closeCode waits for the link to end and returns the close code the server sent (-1: no close frame).
func (m *minion) closeCode(d time.Duration) (int, bool) {
	select {
	case err := <-m.closed:
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return ce.Code, true
		}
		return -1, true
	case <-time.After(d):
		return 0, false
	}
}

func (m *minion) received() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]map[string]any(nil), m.got...)
}

// connectMinion opens a real /ws/agent link signed with the node's secret and answers tasks.
func connectMinion(t *testing.T, n *node, host string) *minion {
	t.Helper()
	return connectMinionWithToken(t, n, host, n.enrollAgent(host))
}

// connectMinionWithToken opens the /ws/agent link of an already enrolled agent.
func connectMinionWithToken(t *testing.T, n *node, host, tok string) *minion {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		t.Fatalf("minion %s dial %s: %v (resp %v)", host, n.id, err, resp)
	}
	m := &minion{host: host, conn: conn, closed: make(chan error, 1)}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		for {
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				m.closed <- err
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

// awaitPromotion waits for a secondary (launchSecondary) to be promoted and serving.
func (n *node) awaitPromotion(d time.Duration) bool {
	select {
	case r := <-n.pendingReady:
		n.ready = r
		return true
	case <-n.exited:
		return false
	case <-time.After(d):
		return false
	}
}

// linkTo gives a node that was started WITHOUT a parent its pull parent (restart on its own address and
// state). Enrolling an agent is a real host.new event that climbs to the root and moves routes: a test
// that counts conflicts between relays enrolls its agents while the relay is still unlinked (the
// events have nowhere to go), then links it.
func (n *node) linkTo(parent *node) {
	n.t.Helper()
	n.setEnv("REPEATER_UPSTREAM_URL", parent.wssURL())
	n.setEnv("REPEATER_UPSTREAM_TOKEN", parent.registerChild(n.id))
	n.anchorTo(parent.treeRoot())
	n.restart()
}
