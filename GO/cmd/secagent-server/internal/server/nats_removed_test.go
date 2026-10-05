package server

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// #178: NATS is gone. The server starts without any broker, never mentions one, and an operator
// still exporting NATS_URL gets one warning, not an error.

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureLogs(t *testing.T) *lockedBuf {
	t.Helper()
	buf := &lockedBuf{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

func TestBuild_NoNATSTrace(t *testing.T) {
	t.Setenv("NATS_URL", "")
	buf := captureLogs(t)
	dir := testStateDir(t)
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: dir, InsecureTestState: true, WriteGuard: allowWrites})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	// the temporary directories are named after the test: do not read "NATS" in a path
	if out := strings.ReplaceAll(buf.String(), dir, "<state-dir>"); strings.Contains(strings.ToLower(out), "nats") || strings.Contains(strings.ToLower(out), "jetstream") {
		t.Errorf("start-up must not mention NATS:\n%s", out)
	}
}

func TestBuild_ObsoleteNATSURLWarnsOnceAndStarts(t *testing.T) {
	t.Setenv("NATS_URL", "nats://legacy.example:4222")
	buf := captureLogs(t)
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites})
	if err != nil {
		t.Fatalf("an obsolete NATS_URL must not be an error: %v", err)
	}
	n.Close()
	out := buf.String()
	if got := strings.Count(out, "[WARN] NATS_URL is obsolete and ignored"); got != 1 {
		t.Errorf("obsolescence warning count = %d, want 1:\n%s", got, out)
	}
	if strings.Contains(out, "legacy.example") || strings.Contains(out, "NATS unavailable") {
		t.Errorf("the value must not be echoed and no connection may be attempted:\n%s", out)
	}
}

func TestAdminStatus_HasNoNATSField(t *testing.T) {
	_, _, admin, _ := startNode(t, nil)
	code, body := adminCall(t, admin, "GET", "/api/admin/status", nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d %s", code, body)
	}
	if strings.Contains(string(body), "nats") {
		t.Errorf("GET /api/admin/status must not carry a nats field: %s", body)
	}
	if !strings.Contains(string(body), `"db"`) {
		t.Errorf("db must stay: %s", body)
	}
}
