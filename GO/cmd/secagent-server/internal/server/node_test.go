package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// startNode builds and runs a REAL node (production wiring) on ephemeral loopback ports and
// returns it with its effective addresses. Hooks are package-level in ws/handlers: one node per
// process at a time; tests using it must not run in parallel.
func startNode(t *testing.T, mutate func(*Config)) (n *Node, api, admin, wsAddr string) {
	t.Helper()
	t.Setenv("JWT_SECRET_KEY", "node-test-secret")
	t.Setenv("ADMIN_TOKEN", "node-test-admin")
	t.Setenv("RSA_MASTER_KEY", "node-test-master-key")
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent-hooks.json")
	t.Setenv("RELAY_ACTION_LOG", t.TempDir()+"/actions.log") // hook journal (#161): never /data in tests
	cfg := Config{
		JWTSecret: "node-test-secret", AdminToken: "node-test-admin",
		DatabaseURL: ":memory:",
		LogLevel:    "INFO",
	}
	for _, p := range []*net.Listener{&cfg.APIListener, &cfg.AdminListener, &cfg.WSListener} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		*p = ln
	}
	if mutate != nil {
		mutate(&cfg)
	}
	node, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(35 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	select {
	case <-node.Ready():
	case err := <-done:
		t.Fatalf("node stopped before being ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("node not ready")
	}
	a, ad, w := node.Addrs()
	return node, a, ad, w
}
