package integration

// #192c on a REAL node: there is no enrollment without a token. The old "pre-authorized key" flow
// answered with a JWT and a NEW JTI to anybody knowing a hostname and its (public) key: a revoked agent
// re-registered itself, and the JTI of an enrolled agent could be replaced at will.

import (
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// openAgentWS opens /ws/agent with a token: the HTTP status (101 on success) and the connection.
func openAgentWS(n *node, token string) (int, *websocket.Conn) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		if resp != nil {
			return resp.StatusCode, nil
		}
		return 0, nil
	}
	return http.StatusSwitchingProtocols, conn
}

func TestRegister_TokenlessEnrollmentIsRefusedOnARealNode(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	tok := n.enrollAgent("victim-host") // the real flow: enrollment token + nonce challenge
	_, pubPEM, err := harnessAgentKeyErr()
	if err != nil {
		t.Fatal(err)
	}
	// the operator also pre-authorizes the key (documented, harmless now)
	if code, _ := n.admin("POST", "/api/admin/authorize", map[string]any{"hostname": "victim-host", "public_key_pem": pubPEM, "approved_by": "ops"}); code >= 300 {
		t.Fatalf("authorize: %d", code)
	}

	tokenless := func() (int, string) {
		code, raw := n.call("POST", "/api/register", "", map[string]any{"hostname": "victim-host", "public_key_pem": pubPEM})
		return code, string(raw)
	}
	// anybody knowing the hostname and the public key: 40 forged requests change nothing
	for i := 0; i < 40; i++ {
		if code, body := tokenless(); code != http.StatusForbidden {
			t.Fatalf("tokenless register %d: %d %s, want 403", i, code, body)
		}
	}
	if c, conn := openAgentWS(n, tok); c != http.StatusSwitchingProtocols {
		t.Fatalf("the victim's token was invalidated by forged registrations: %d", c)
	} else {
		_ = conn.Close()
	}

	// a revoked agent cannot register itself back
	if code, _ := n.admin("POST", "/api/admin/revoke/victim-host", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, body := tokenless(); code != http.StatusForbidden {
		t.Fatalf("a revoked agent registering without a token: %d %s, want 403", code, body)
	}
	if c, conn := openAgentWS(n, tok); c != http.StatusUnauthorized {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("the revoked token must stay refused: %d", c)
	}
}
