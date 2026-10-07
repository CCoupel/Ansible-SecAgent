package cli

import (
	"net/http"
	"strings"
	"testing"
)

func runStatus(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	mockServer(t, func(w http.ResponseWriter, r *http.Request) { mustEncode(t, w, payload) })
	return captureStdout(t, func() {
		rootCmd.SetArgs([]string{"server", "status"})
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("status: %v", err)
		}
	})
}

func TestServerStatus_ShowsRefusedPermanentLinkAndWarning(t *testing.T) {
	out := runStatus(t, map[string]interface{}{
		"db": "ok", "ws_connections": 2, "uptime": "10s",
		"links": map[string]interface{}{
			"degraded": true,
			"upstream": map[string]interface{}{"mode": "pull", "peer": "central", "state": "refused_permanent",
				"reason": "peer closed with code 4010 (token revoked)", "since": "2026-10-04T20:00:00Z"},
			"push_children": []interface{}{
				map[string]interface{}{"relay_id": "dmz2", "state": "connected", "since": "2026-10-04T20:00:01Z"},
			},
		},
	})
	for _, want := range []string{"upstream (pull)", "central", "refused_permanent", "4010", "push child", "dmz2", "connected", "operator action required"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestServerStatus_NoLinksSectionWithoutLinks(t *testing.T) {
	out := runStatus(t, map[string]interface{}{"db": "ok", "ws_connections": 0, "uptime": "1s"})
	if strings.Contains(out, "LINK") || strings.Contains(out, "WARNING") {
		t.Errorf("unexpected links section:\n%s", out)
	}
}

func TestServerStatus_HealthyLinksNoWarning(t *testing.T) {
	out := runStatus(t, map[string]interface{}{
		"db": "ok", "ws_connections": 0, "uptime": "1s",
		"links": map[string]interface{}{"degraded": false,
			"upstream": map[string]interface{}{"mode": "push", "state": "connected"}},
	})
	if !strings.Contains(out, "upstream (push)") || strings.Contains(out, "WARNING") {
		t.Errorf("output:\n%s", out)
	}
}
