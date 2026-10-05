package integration

import (
	"net/http"
	"strings"
	"testing"
)

// The admin API lives on its own listener (production port 7771, never exposed publicly): even
// with a VALID admin token, no admin endpoint may answer on the public API or WebSocket listeners.
func TestPorts_AdminEndpointsAreNotReachableOnPublicListeners(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	adminRoutes := []struct{ method, path string }{
		{"GET", "/api/admin/status"},
		{"GET", "/api/admin/tokens"},
		{"POST", "/api/admin/tokens"},
		{"GET", "/api/admin/relays"},
		{"POST", "/api/admin/relays"},
		{"GET", "/api/admin/relays/status"},
		{"POST", "/api/admin/relays/some-id/revoke"},
		{"DELETE", "/api/admin/relays/some-id"},
		{"GET", "/api/admin/minions"},
		{"POST", "/api/admin/keys/rotate"},
		{"GET", "/api/admin/security/tokens"},
	}
	body := map[string]any{"relay_id": "x", "role": "plugin"}
	for _, listener := range []struct{ name, base string }{{"public API", root.apiURL()}, {"WebSocket", root.wsURL()}} {
		for _, r := range adminRoutes {
			code, raw := root.callOn(listener.base, r.method, r.path, root.adminTok, body)
			// the MUX must not know the route: a handler answering 404 itself (relay_not_found…) would
			// prove the route IS mounted here
			if code != http.StatusNotFound || !strings.Contains(string(raw), "page not found") {
				t.Errorf("%s %s on the %s listener = %d (%s), want the mux's 404: admin endpoints must only exist on the admin listener", r.method, r.path, listener.name, code, raw)
			}
		}
	}
	// control: the same requests DO work on the admin listener
	if code, _ := root.admin("GET", "/api/admin/status", nil); code != http.StatusOK {
		t.Errorf("admin status on the admin listener = %d", code)
	}
	// and the public listener really serves the public API
	if code, raw := root.callOn(root.apiURL(), "GET", "/health", "", nil); code != http.StatusOK {
		t.Errorf("/health on the public listener = %d %s", code, raw)
	}
	// the three listeners are distinct sockets
	if a, b, c := root.ready.API, root.ready.Admin, root.ready.WS; a == b || b == c || a == c {
		t.Errorf("API, admin and WebSocket must be three different listeners: %s %s %s", a, b, c)
	}
	// the admin listener serves neither the agent / relay WebSocket nor the exec API
	for _, p := range []string{"/ws/agent", "/ws/relay", "/api/exec/h", "/api/inventory"} {
		if code, _ := root.callOn(root.adminURL(), "GET", p, root.pluginToken(), nil); code == http.StatusOK || code == http.StatusSwitchingProtocols {
			t.Errorf("%s answered %d on the admin listener", p, code)
		}
	}
}
