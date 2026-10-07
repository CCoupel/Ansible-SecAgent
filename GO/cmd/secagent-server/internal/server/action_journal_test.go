package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// #161 wired end to end: a hook fires, the action lands as a masked JSON line in the journal
// (RELAY_ACTION_LOG) and GET /api/admin/hooks/log serves it; the store has no action_log any more.
func TestWiring_HookActionsAreJournaledWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal", "actions.log")
	hooksFile := filepath.Join(dir, "hooks.json")
	out := filepath.Join(dir, "hook.out")
	cfg := `{"hooks":[{"event":"host.up","actions":[
		{"type":"file","path":"` + out + `","append":"APPEND-SECRET {{hostname}}\n"},
		{"type":"api","method":"POST","url":"http://127.0.0.1:1/x?token=URL-TOKEN","headers":{"Authorization":"Bearer HEADER-SECRET"},"timeout_seconds":2}]}]}`
	if err := os.WriteFile(hooksFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, admin, _ := startNode(t, func(*Config) {
		t.Setenv("RELAY_HOOKS_CONFIG", hooksFile)
		t.Setenv("RELAY_ACTION_LOG", journalPath)
	})
	hooks.GlobalDispatcher.Dispatch("host.up", "journaled-host", "connected", "")

	var entries []map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, body := adminCall(t, admin, "GET", "/api/admin/hooks/log?hostname=journaled-host", nil)
		if code != http.StatusOK {
			t.Fatalf("hooks log: %d %s", code, body)
		}
		entries = nil
		_ = json.Unmarshal(body, &entries)
		if len(entries) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) < 2 {
		t.Fatalf("expected 2 journaled actions, got %v", entries)
	}
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("the journal must be at RELAY_ACTION_LOG: %v", err)
	}
	for _, secret := range []string{"HEADER-SECRET", "URL-TOKEN", "APPEND-SECRET"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("journal leaks %q:\n%s", secret, raw)
		}
	}
	_, body := adminCall(t, admin, "GET", "/api/admin/hooks/log", nil)
	for _, secret := range []string{"HEADER-SECRET", "URL-TOKEN", "APPEND-SECRET"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("GET /api/admin/hooks/log leaks %q: %s", secret, body)
		}
	}
	if fi, err := os.Stat(journalPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("journal mode: %v %v", fi, err)
	}
}
