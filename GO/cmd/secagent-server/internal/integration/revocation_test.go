package integration

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dialRelayWith opens /ws/relay with a bearer token and returns the HTTP status of the upgrade
// attempt (101 when it succeeds).
func dialRelayWith(t *testing.T, n *node, token string) int {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second} //nolint:gosec // test cert
	conn, resp, err := d.Dial(n.wssURL()+"/ws/relay", h)
	if err == nil {
		_ = conn.Close()
		return http.StatusSwitchingProtocols
	}
	if resp == nil {
		t.Fatalf("dial %s: %v", n.id, err)
	}
	return resp.StatusCode
}

// (e) pull child: revoking its relay token cuts the ACTIVE link in 4010, the child stops for good
// (refused_permanent in /health) and any new connection with that token is refused in 401.
func TestRevocation_PullRelayToken_CutsLinkAndBlocksReconnection(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	tok, relayRowID := root.registerChildWithID("relay1")
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tok})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	if relay1.health().Degraded {
		t.Fatal("a healthy node must not be degraded")
	}

	code, m := root.admin("POST", "/api/admin/relays/"+relayRowID+"/revoke", nil)
	if code != http.StatusOK || m["revoked"] != true {
		t.Fatalf("revoke = %d %v", code, m)
	}
	waitFor(t, "relay1 stopped for good", func() bool { return relay1.upstreamState() == "refused_permanent" })
	if !relay1.health().Degraded {
		t.Error("the admin status must report degraded once the parent refused the link permanently")
	}
	// the PUBLIC /health stays 200 and only carries the flag: no relay id, state, reason or links
	pub := relay1.publicHealth()
	if !strings.Contains(pub, `"degraded":true`) {
		t.Errorf("the public /health must expose degraded=true: %s", pub)
	}
	for _, leak := range []string{"relay1", "root", "refused_permanent", "reason", "links", "upstream"} {
		if strings.Contains(pub, leak) {
			t.Errorf("the public /health leaks %q: %s", leak, pub)
		}
	}
	if got := dialRelayWith(t, root, tok); got != http.StatusUnauthorized {
		t.Errorf("reconnection with the revoked token = %d, want 401", got)
	}
	// the child does not hammer the parent once stopped: its state stays terminal
	base := root.logs.count("Relay connected: relay_id=relay1")
	if relay1.upstreamState() != "refused_permanent" || root.logs.count("Relay connected: relay_id=relay1") != base {
		t.Error("a permanently refused child must not reconnect")
	}
	assertNoSecrets(t, allLogs(root, relay1), tok)
}

// pushRevocationSetup links root ──push──▶ relay1 and revokes the relay-parent token on relay1.
func pushRevocationSetup(t *testing.T) (root, relay1 *node, tok string) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root"})
	relay1 = startNode(t, nodeSpec{ID: "relay1"})
	var tokID string
	tok, tokID = relay1.mintParentToken("root")
	if code, m := root.admin("POST", "/api/admin/relays", map[string]any{"relay_id": "relay1", "mode": "push", "url": relay1.wssURL(), "token": tok}); code != http.StatusCreated {
		t.Fatalf("register push: %d %v", code, m)
	}
	waitFor(t, "dialed link up", func() bool { return root.pushState("relay1") == "connected" })
	code, m := relay1.admin("POST", "/api/admin/tokens/"+tokID+"/revoke", nil)
	if code != http.StatusOK {
		t.Fatalf("revoke relay-parent token = %d %v", code, m)
	}
	return root, relay1, tok
}

// (e) push child: revoking the relay-parent token on the CHILD cuts the dialed link in 4010 and
// every new dial with the token is refused in 401.
func TestRevocation_RelayParentToken_CutsDialedLinkAndRefusesRedial(t *testing.T) {
	t.Parallel()
	root, relay1, tok := pushRevocationSetup(t)
	waitFor(t, "the parent's link is cut", func() bool { return root.pushState("relay1") != "connected" })
	if got := dialRelayWith(t, relay1, tok); got != http.StatusUnauthorized {
		t.Errorf("dial with the revoked relay-parent token = %d, want 401", got)
	}
	if !relay1.logs.has("token_revoked") {
		t.Errorf("the child must log why it refuses the token:\n%s", relay1.logs.String())
	}
	if !relay1.logs.has("parent link closed: token revoked") {
		t.Errorf("the child must log that it closed the live parent link:\n%s", relay1.logs.String())
	}
	if u := relay1.health().Links.Upstream; u != nil && u.State == "connected" {
		t.Error("the child must no longer report a connected parent")
	}
	assertNoSecrets(t, allLogs(root, relay1), tok)
}

// (e) SERVER_SPEC §9.2/§9.3: after the revocation the parent's dialer stops for good
// (refused_permanent + degraded in the parent's /health, log ERROR). Found by this suite: the
// 4010 close frame used to be swallowed by ws.ServeDialedRelay (dialer stuck in "retrying").
func TestRevocation_RelayParentToken_DialerStopsForGood(t *testing.T) {
	t.Parallel()
	root, _, _ := pushRevocationSetup(t)
	waitFor(t, "root's dialer stopped for good", func() bool { return root.pushState("relay1") == "refused_permanent" })
	if !root.health().Degraded {
		t.Error("the parent must report degraded when a push child refused it permanently")
	}
	if root.logs.count("ERROR child relay1 refused link (permanent)") == 0 {
		t.Error("the permanent refusal must be logged at ERROR level for the operator")
	}
}

// (e) 4012 is a CORRECTABLE refusal: the child reconnects with backoff, every time, and never
// becomes terminal.
func TestRevocation_Code4012IsRetried(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	for i := 1; i <= 3; i++ {
		before := root.logs.count("Relay connected: relay_id=relay1")
		root.closeRelay("relay1", 4012)
		waitFor(t, "relay1 reconnected after a 4012", func() bool {
			return root.logs.count("Relay connected: relay_id=relay1") > before && relay1.upstreamState() == "connected"
		})
	}
	if relay1.health().Degraded || relay1.upstreamState() == "refused_permanent" {
		t.Error("4012 must never be terminal")
	}
	if relay1.logs.count("peer closed with code 4012") < 3 {
		t.Errorf("the child must have seen three 4012 closes:\n%s", relay1.logs.String())
	}
}

// DELETE of a relay whose token cannot be blacklisted (push) is refused with 409 unless it was
// revoked first (#153); a revoked one can be deleted and its dialer stops.
func TestRevocation_DeletingAPushRelayRequiresRevocationFirst(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1"})
	tok, _ := relay1.mintParentToken("root")
	code, m := root.admin("POST", "/api/admin/relays", map[string]any{"relay_id": "relay1", "mode": "push", "url": relay1.wssURL(), "token": tok})
	if code != http.StatusCreated {
		t.Fatalf("register push: %d %v", code, m)
	}
	rowID := m["id"].(string)
	waitFor(t, "dialed link up", func() bool { return root.pushState("relay1") == "connected" })

	code, m = root.admin("DELETE", "/api/admin/relays/"+rowID, nil)
	if code != http.StatusConflict || m["error"] != "relay_not_revoked" {
		t.Fatalf("DELETE of an unrevoked push relay = %d %v, want 409 relay_not_revoked", code, m)
	}
	if root.pushState("relay1") != "connected" {
		t.Error("a refused DELETE must leave the link untouched")
	}

	if code, m = root.admin("POST", "/api/admin/relays/"+rowID+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("revoke = %d %v", code, m)
	}
	if code, m = root.admin("DELETE", "/api/admin/relays/"+rowID, nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("DELETE after revocation = %d %v", code, m)
	}
	waitFor(t, "the dialer of the deleted relay is gone", func() bool { return root.pushState("relay1") == "" })
	assertNoSecrets(t, allLogs(root, relay1), tok)
}
