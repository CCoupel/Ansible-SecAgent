package integration

// #192: POST /api/token/refresh no longer exists. It accepted any hostname without proof (a revoked
// agent got a fresh JWT, anyone could invalidate the JTI of any agent) and no client of this
// repository ever called it (the minion re-enrolls on 401 and handles the WS "rekey" message).
// A removed route answers 404 whatever the caller presents, a revoked agent included.

import (
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestTokenRefreshRoute_IsGone404EvenForARevokedAgent(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	tok := n.enrollAgent("gone-host")

	for name, bearer := range map[string]string{"no credential": "", "a valid agent token": tok, "garbage": "x.y.z"} {
		for _, method := range []string{"POST", "GET"} {
			if code, _ := n.call(method, "/api/token/refresh", bearer, map[string]string{"hostname": "gone-host"}); code != http.StatusNotFound {
				t.Errorf("%s %s: %d, want 404", method, name, code)
			}
		}
	}
	if code, _ := n.admin("POST", "/api/admin/revoke/gone-host", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	// the revoked agent cannot get a new token through this route ...
	if code, _ := n.call("POST", "/api/token/refresh", tok, map[string]string{"hostname": "gone-host"}); code != http.StatusNotFound {
		t.Fatalf("a revoked agent on the removed route: %d, want 404", code)
	}
	// ... and its token stays refused where it matters
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err == nil {
		_ = conn.Close()
		t.Fatal("the revoked token must stay refused on /ws/agent")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token on /ws/agent: %v, want 401", resp)
	}
}
