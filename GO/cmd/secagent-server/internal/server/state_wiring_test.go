package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// #160 wiring: the state is loaded before anything is served, a missing or foreign state refuses to
// start, without a write guard the node is read-only, and the blacklist is purged periodically.

func TestBuild_MissingStateRefusesToStartAndCreatesNothing(t *testing.T) {
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	empty := t.TempDir()
	_, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: empty, WriteGuard: allowWrites})
	if err == nil || !strings.Contains(err.Error(), "run 'secagent-server state init' to initialize") {
		t.Fatalf("Build without a state: %v", err)
	}
	if names, _ := os.ReadDir(empty); len(names) != 0 {
		t.Errorf("Build must never create the state: %v", names)
	}
}

func TestBuild_WithoutAWriteGuardTheNodeIsReadOnly(t *testing.T) {
	n, _, admin, _ := startNode(t, func(c *Config) { c.WriteGuard = nil })
	before, _ := os.ReadFile(filepath.Join(n.cfg.StateDir, state.StateFile))
	// reads work
	if code, _ := adminCall(t, admin, "GET", "/api/admin/status", nil); code != http.StatusOK {
		t.Errorf("status: %d", code)
	}
	// every write is refused and nothing reaches the disk
	code, body := adminCall(t, admin, "POST", "/api/admin/authorize", map[string]any{"hostname": "h", "public_key_pem": "pem", "approved_by": "ci"})
	if code < 500 {
		t.Errorf("a write without a guard answered %d %s, want a server error", code, body)
	}
	after, _ := os.ReadFile(filepath.Join(n.cfg.StateDir, state.StateFile))
	if string(before) != string(after) {
		t.Error("relay.state changed while the node is read-only")
	}
	if _, err := os.Stat(filepath.Join(n.cfg.StateDir, state.TmpFile)); err == nil {
		t.Error("a temporary state file was created")
	}
}

func TestBuild_PeriodicPurgeRemovesExpiredBlacklistEntriesAndHonoursTheGuard(t *testing.T) {
	n, _, _, _ := startNode(t, func(c *Config) { c.PurgeInterval = 20 * time.Millisecond })
	ctx := context.Background()
	r := "t"
	if err := n.store.AddToBlacklist(ctx, "expired", "h", time.Now().Add(-time.Minute).Format(time.RFC3339), &r); err != nil {
		t.Fatal(err)
	}
	if err := n.store.AddToBlacklist(ctx, "live", "h", time.Now().Add(time.Hour).Format(time.RFC3339), &r); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if bl, _ := n.store.IsJTIBlacklisted(ctx, "expired"); !bl {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if bl, _ := n.store.IsJTIBlacklisted(ctx, "expired"); bl {
		t.Error("the expired entry was not purged by the periodic task")
	}
	if bl, _ := n.store.IsJTIBlacklisted(ctx, "live"); !bl {
		t.Error("a live entry was purged")
	}

	// a refusing guard: nothing is purged, nothing crashes
	writes := n.store.Engine().Writes()
	refuse := true
	n.store.SetWriteGuard(func() error {
		if refuse {
			return http.ErrAbortHandler
		}
		return nil
	})
	_ = n.store.Engine().Mutate(func(tx *state.Tx) error { return nil }) // sanity: the guard is honoured
	time.Sleep(100 * time.Millisecond)
	if n.store.Engine().Writes() != writes {
		t.Error("a write happened while the guard refuses")
	}
	refuse = false
}

// With no lock wired (#163) a lone relay declares itself SingleInstance: writes then work, and are
// durable; without that declaration the node stays read-only (previous test).
func TestBuild_SingleInstanceAllowsTheWrites(t *testing.T) {
	n, _, admin, _ := startNode(t, func(c *Config) { c.WriteGuard = nil; c.SingleInstance = true })
	code, body := adminCall(t, admin, "POST", "/api/admin/authorize", map[string]any{"hostname": "h", "public_key_pem": "pem", "approved_by": "ci"})
	if code >= 300 {
		t.Fatalf("authorize on a single instance: %d %s", code, body)
	}
	k, err := n.store.GetAuthorizedKey(context.Background(), "h")
	if err != nil || k == nil {
		t.Fatalf("the key was not stored: %v %v", k, err)
	}
	raw, _ := os.ReadFile(filepath.Join(n.cfg.StateDir, state.StateFile))
	if !strings.Contains(string(raw), `"h":{"hostname":"h"`) {
		t.Error("the write did not reach relay.state")
	}
}
