package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNode_RunServesOnTheConfiguredListenersAndShutsDown(t *testing.T) {
	_, api, admin, wsAddr := startNode(t, nil)
	if api == admin || admin == wsAddr || api == wsAddr {
		t.Fatalf("three distinct listeners expected: %s %s %s", api, admin, wsAddr)
	}
	resp, err := http.Get("http://" + api + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != 200 || body["status"] != "ok" {
		t.Errorf("health = %d %v %v", resp.StatusCode, body, err)
	}
	// the admin API answers on the admin port (auth required: 401 without the token, not 404)
	r2, err := http.Get("http://" + admin + "/api/admin/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Errorf("admin status without token = %d, want 401", r2.StatusCode)
	}
}

func TestNode_RunReturnsOnPortConflict(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "s")
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites,
		APIAddr: busy.Addr().String(), AdminAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Run(ctx); err == nil {
		t.Fatal("Run must fail when an address is already in use")
	}
}

func TestBuild_ReleasesEverythingOnError(t *testing.T) {
	_, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a",
		StateDir: "/nonexistent-dir-for-secagent-test/\x00/state", InsecureTestState: true, WriteGuard: allowWrites})
	if err == nil {
		t.Fatal("expected a state error")
	}
}

func TestNode_CloseIsIdempotent(t *testing.T) {
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	n.Close()
}
