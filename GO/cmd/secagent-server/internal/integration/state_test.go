package integration

// The relay state on its file (#160), end to end on a real node process: enrollment, revocation,
// suspension, vars, tokens, inventory and exec, then a crash (kill -9) and a graceful restart: what
// is permanent comes back, a revoked agent stays refused, and nothing volatile is invented.

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/websocket"
)

func dialAgentToken(n *node, tok string) (*websocket.Conn, int, error) {
	h := http.Header{"Authorization": {"Bearer " + tok}}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig()}
	c, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return c, status, err
}

func TestState_EndToEndSurvivesCrashAndRestart(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "solo"})

	tokA := n.enrollAgent("host-a")
	n.enrollAgent("host-b")
	tokC := n.enrollAgent("host-c")
	connectMinionWithToken(t, n, "host-a", tokA)
	if code, m := n.admin("POST", "/api/admin/minions/host-b/suspend", nil); code != http.StatusOK {
		t.Fatalf("suspend: %d %v", code, m)
	}
	if code, m := n.admin("POST", "/api/admin/minions/host-c/vars", map[string]any{"env": "prod", "n": 3}); code != http.StatusOK {
		t.Fatalf("set vars: %d %v", code, m)
	}
	if code, m := n.admin("POST", "/api/admin/revoke/host-a", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, m)
	}
	plugin := n.pluginToken()
	if code, _ := n.call("GET", "/api/inventory", plugin, nil); code != http.StatusOK {
		t.Fatalf("inventory with the plugin token: %d", code)
	}
	if r := n.exec("host-b", execBody("id")); r.Code != http.StatusServiceUnavailable || r.Body["error"] != "agent_suspended" {
		t.Fatalf("exec on the suspended agent: %d %v", r.Code, r.Body)
	}

	check := func(label string) {
		t.Helper()
		// revocation persisted: the token of host-a is refused at the handshake
		if _, status, err := dialAgentToken(n, tokA); err == nil || status != http.StatusUnauthorized {
			t.Errorf("%s: the revoked agent's token = status %d err %v, want 401", label, status, err)
		}
		// an enrolled agent reconnects with the token it already had
		c, status, err := dialAgentToken(n, tokC)
		if err != nil {
			t.Fatalf("%s: host-c with its token: %v (status %d)", label, err, status)
		}
		_ = c.Close()
		// suspension and vars persisted; the plugin token still valid
		if r := n.exec("host-b", execBody("id")); r.Code != http.StatusServiceUnavailable || r.Body["error"] != "agent_suspended" {
			t.Errorf("%s: suspension lost: %d %v", label, r.Code, r.Body)
		}
		if code, m := n.admin("GET", "/api/admin/minions/host-c/vars", nil); code != http.StatusOK || !jsonHas(m, "prod") {
			t.Errorf("%s: vars lost: %d %v", label, code, m)
		}
		if code, _ := n.call("GET", "/api/inventory", plugin, nil); code != http.StatusOK {
			t.Errorf("%s: the plugin token must stay valid across the restart: %d", label, code)
		}
		inv := n.inventoryHosts()
		for _, h := range []string{"host-a", "host-b", "host-c"} {
			if _, ok := inv[h]; !ok {
				t.Errorf("%s: %s missing from the inventory", label, h)
			}
		}
		// the file on disk is private and valid JSON with the agents in it
		fi, err := os.Stat(filepath.Join(n.stateDir, "relay.state"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: relay.state: %v %v", label, fi, err)
		}
		if got := n.stateSection("agents"); len(got) != 3 {
			t.Errorf("%s: %d agents in the state file, want 3", label, len(got))
		}
	}
	check("before")

	n.kill9() // crash: no graceful shutdown, the last durable write is what comes back
	check("after kill -9")

	n.restart()
	check("after a graceful restart")
	if _, err := os.Stat(filepath.Join(n.stateDir, "relay.state.tmp")); err == nil {
		t.Error("a stale relay.state.tmp was left behind")
	}
}
