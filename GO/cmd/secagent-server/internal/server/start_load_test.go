package server

import (
	"context"
	"net"
	"testing"
	"time"

	"secagent-server/internal/testnet"
)

// unreachableAddrListener delegates to a real listener but advertises an address nobody listens
// on: any readiness probe that dials the listener's advertised address (the old isListening,
// 1 s timeout after a 100 ms sleep) fails exactly as on an overloaded host (#194).
type unreachableAddrListener struct {
	net.Listener
	addr net.Addr
}

func (l unreachableAddrListener) Addr() net.Addr { return l.addr }

func TestRun_ReadinessDoesNotDialItsOwnListeners(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "node-test-secret")
	t.Setenv("ADMIN_TOKEN", "node-test-admin")
	t.Setenv("RSA_MASTER_KEY", "node-test-master-key")
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent-hooks.json")
	t.Setenv("RELAY_ACTION_LOG", t.TempDir()+"/actions.log")
	cfg := Config{
		TLSDisable: true, JWTSecret: "node-test-secret", AdminToken: "node-test-admin",
		StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites, LogLevel: "INFO",
	}
	for _, p := range []*net.Listener{&cfg.APIListener, &cfg.AdminListener, &cfg.WSListener} {
		real, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		// a closed port: connection refused. Taken from below the ephemeral range (testnet.ClosedAddr): a
		// port released from a ":0" listener could be handed to another process or test in the meantime
		deadAddr, err := net.ResolveTCPAddr("tcp", testnet.ClosedAddr(t))
		if err != nil {
			t.Fatal(err)
		}
		*p = unreachableAddrListener{Listener: real, addr: deadAddr}
	}
	node, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- node.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(35 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}()
	select {
	case <-node.Ready():
	case err := <-finished:
		t.Fatalf("node failed to start although its listeners are bound: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("node not ready")
	}
}
