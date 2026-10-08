package cli

import (
	"net/http"
	"strings"
	"testing"
)

func resetRelaysAddFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		for name, def := range map[string]string{"id": "", "mode": "pull", "url": "", "token": "", "description": ""} {
			_ = relaysAddCmd.Flags().Set(name, def)
		}
	}
	reset()
	t.Cleanup(reset)
}

func runRelaysAdd(t *testing.T, args ...string) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetArgs(append([]string{"relays", "add"}, args...))
		err = rootCmd.Execute()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// v3.0.4: a pull declaration returns no token; the output points to 'tokens create --role relay-child'.
func TestRelaysAdd_Pull_NoTokenSection(t *testing.T) {
	resetRelaysAddFlags(t)
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		mustEncode(t, w, map[string]interface{}{
			"id": "u1", "relay_id": "dmz1", "mode": "pull", "status": "pending", "created_at": "2026-10-08T00:00:00Z",
		})
	})
	out := runRelaysAdd(t, "--id", "dmz1")
	if strings.Contains(out, "JWT Token") || strings.Contains(out, "shown once") {
		t.Errorf("stale token section in output:\n%s", out)
	}
	if !strings.Contains(out, "tokens create --role relay-child --sub dmz1") {
		t.Errorf("missing relay-child guidance:\n%s", out)
	}
	if strings.Contains(relaysAddCmd.Long, "JWT token returned") || !strings.Contains(relaysAddCmd.Long, "relay-child") {
		t.Errorf("stale help:\n%s", relaysAddCmd.Long)
	}
}

func TestRelaysAdd_Push_NoPullGuidance(t *testing.T) {
	resetRelaysAddFlags(t)
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		mustEncode(t, w, map[string]interface{}{
			"id": "u2", "relay_id": "dmz2", "mode": "push", "status": "pending", "created_at": "2026-10-08T00:00:00Z",
			"urls": []string{"wss://dmz2:7772"},
		})
	})
	out := runRelaysAdd(t, "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token", "x.y.z")
	if strings.Contains(out, "No token was issued") || strings.Contains(out, "x.y.z") {
		t.Errorf("unexpected output in push mode:\n%s", out)
	}
}
