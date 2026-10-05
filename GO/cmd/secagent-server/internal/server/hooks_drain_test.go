package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// #183: a clean stop flushes the hooks queue before the node is released: events accepted before
// the stop all run.
func TestNode_CleanStopFlushesTheHooksQueue(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	cfg := `{"hooks":[{"event":"host.up","actions":[{"type":"shell","cmd":"/bin/sh","args":["-c","sleep 0.05; echo {{hostname}} >> ` + out + `"],"timeout_seconds":5}]}]}`
	hp := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(hp, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_HOOKS_CONFIG", hp)
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "2")
	t.Setenv("RELAY_ACTION_LOG", filepath.Join(dir, "actions.log"))
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", DatabaseURL: ":memory:",
		APIAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	select {
	case <-n.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("node not ready")
	}
	const events = 30 // ~0.75 s of work for 2 workers
	for i := 0; i < events; i++ {
		hooks.GlobalDispatcher.Dispatch("host.up", "h"+string(rune('a'+i%26))+string(rune('a'+i/26)), "connected", "")
	}
	cancel() // clean stop requested while most events are still queued
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return")
	}
	b, _ := os.ReadFile(out)
	if got := strings.Count(string(b), "\n"); got != events {
		t.Errorf("%d hooks ran before the node stopped, want %d (the queue must be flushed)", got, events)
	}
}
