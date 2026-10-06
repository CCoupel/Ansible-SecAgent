package ws

// #182 — ré-enrôlement automatique contre un VRAI serveur : le binaire secagent-server est
// compilé puis lancé comme en production (API, admin, WS), avec un vrai client d'enrôlement.
// Scénario : le JWT du minion est remplacé côté serveur (nouvel enrôlement → JTI changé → 401 au
// handshake WS, contrôle de #169) ; le dispatcher se ré-enrôle (étapes 1 et 2, clef publique et
// hostname), se reconnecte (101) et l'agent apparaît « connected ».

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
	"secagent-server/internal/testnet"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// localAddr gives an address that the server process will bind: outside the ephemeral range and
// reserved (a released ":0" port could be taken by anything before the process binds it).
func localAddr(t *testing.T) string { t.Helper(); return testnet.ClosedAddr(t) }

func TestReEnrollAgainstARealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the real secagent-server")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "secagent-server")
	build := exec.Command("go", "build", "-o", bin, "./cmd/secagent-server")
	build.Dir = moduleRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build secagent-server: %v\n%s", err, out)
	}

	// the relay state, created by the real `secagent-server state init` (RSA-4096 generation: heavy-tailed duration under load)
	stateDir := filepath.Join(dir, "state")
	initCmd := exec.Command(bin, "state", "init")
	initCmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "RSA_MASTER_KEY=realserver-master-key", "STATE_DIR=" + stateDir}
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("state init: %v\n%s", err, out)
	}
	api, adminAddr, wsAddr := localAddr(t), localAddr(t), localAddr(t)
	const adminToken = "realserver-admin-token"
	srv := exec.Command(bin)
	srv.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir,
		"JWT_SECRET_KEY=realserver-jwt-secret", "ADMIN_TOKEN=" + adminToken,
		"RSA_MASTER_KEY=realserver-master-key", "STATE_DIR=" + stateDir,
		"RELAY_STATUS_FILE=" + filepath.Join(dir, "status.json"), // local health file, outside STATE_DIR
		"RELAY_HOOKS_CONFIG=" + filepath.Join(dir, "absent-hooks.json"), "TLS_DISABLE=true",
		"API_ADDR=" + api, "ADMIN_ADDR=" + adminAddr, "WS_ADDR=" + wsAddr,
	}
	out := &syncBuffer{}
	srv.Stdout, srv.Stderr = out, out
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })

	// wait for the three ports
	deadline := time.Now().Add(240 * time.Second) // failure-only bound: RSA-4096 key generation has a heavy-tailed duration (>120 s observed under load, empty server output)
	for _, a := range []string{api, adminAddr, wsAddr} {
		for {
			c, err := net.DialTimeout("tcp", a, 300*time.Millisecond)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("server not listening on %s; output:\n%s", a, out.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	adminDo := func(method, path string, body any, into any) {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, "http://"+adminAddr+path, rd)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode/100 != 2 {
			t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
		}
		if into != nil {
			if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
				t.Fatal(err)
			}
		}
	}
	var tok struct {
		Token string `json:"token"`
	}
	adminDo("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "hostname_pattern": "^minion-182$", "reusable": 1}, &tok)
	if tok.Token == "" {
		t.Fatal("no enrollment token")
	}

	// RSA-4096 like the real minion: the server encrypts the JWT (~250 bytes) with OAEP, which
	// does not fit in a 2048-bit key
	key, err := enrollment.GenerateRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	jwtPath := filepath.Join(dir, "token.jwt")
	enrollCfg := enrollment.Config{
		RegisterURL: "http://" + api + "/api/register", Hostname: "minion-182", PrivateKey: key,
		EnrollmentToken: tok.Token, JWTPath: jwtPath, Insecure: true,
	}
	pub, err := enrollment.PublicKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	enrollCfg.PublicKeyPEM = pub
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	staleJWT, err := enrollment.Enroll(ctx, enrollCfg)
	if err != nil {
		t.Fatalf("first enrollment: %v\n%s", err, out.String())
	}
	// a second enrollment (same hostname and key) replaces the current JTI: staleJWT is now refused
	if _, err := enrollment.Enroll(ctx, enrollCfg); err != nil {
		t.Fatalf("second enrollment: %v", err)
	}

	t.Logf("enrolled twice, starting the dispatcher with the stale JWT")
	logs := captureLog(t)
	d := NewDispatcher(ConnConfig{ServerURL: "ws://" + wsAddr + "/ws/agent", JWT: staleJWT, Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{
			RegisterURL: "http://" + api + "/api/register", Hostname: "minion-182", PrivateKey: key,
			JWTPath: jwtPath, EnrollmentToken: tok.Token, Insecure: true,
		})
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- d.Run(runCtx) }()
	defer func() { stop(); <-done }()

	// the minion re-enrolls (real protocol) and reconnects: the agent shows up as connected
	var status string
	for time.Now().Before(deadline.Add(60 * time.Second)) {
		var minions []struct{ Hostname, Status string }
		adminDo("GET", "/api/admin/minions", nil, &minions)
		for _, m := range minions {
			if strings.EqualFold(m.Hostname, "minion-182") {
				status = m.Status
			}
		}
		if status == "connected" {
			break
		}
		t.Logf("agent status %q", status)
		select {
		case err := <-done:
			t.Fatalf("dispatcher stopped: %v\nminion logs:\n%s\nserver:\n%s", err, logs.String(), out.String())
		case <-time.After(300 * time.Millisecond):
		}
	}
	if status != "connected" {
		t.Fatalf("agent status %q, want connected\nminion logs:\n%s\nserver:\n%s", status, logs.String(), out.String())
	}
	if !strings.Contains(logs.String(), "Re-enrollment after JWT rejection (401)") {
		t.Errorf("the connection must come from a re-enrollment:\n%s", logs.String())
	}
	if d.currentJWT() == staleJWT || d.currentJWT() == "" {
		t.Error("the dispatcher must hold the new JWT")
	}
	if b, err := os.ReadFile(jwtPath); err != nil || string(b) != d.currentJWT() {
		t.Errorf("the new JWT must be persisted (err %v)", err)
	}
	for name, secret := range map[string]string{"enrollment token": tok.Token, "stale JWT": staleJWT, "new JWT": d.currentJWT()} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("%s leaked in the minion logs", name)
		}
	}
}
