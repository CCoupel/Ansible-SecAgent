package integration

// POST /api/token/refresh against a REAL node process, with the real enrollment flow of the harness
// (#192). The Go minion re-enrolls instead of calling this route, so the client here is the harness'
// agent (its RSA key reads the encrypted answer, its JWT opens /ws/agent).

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func refreshCall(n *node, bearer string) (int, map[string]string) {
	code, raw := n.call("POST", "/api/token/refresh", bearer, nil)
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	return code, m
}

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

func decryptRefreshed(t *testing.T, enc string) string {
	t.Helper()
	priv, _, err := harnessAgentKeyErr()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
	if err != nil {
		t.Fatalf("the answer must be readable with the agent key: %v", err)
	}
	return string(plain)
}

func TestTokenRefresh_RealNodeRefreshRotationAndRevocation(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	tok := n.enrollAgent("refresh-host")

	// no credential: refused
	if code, _ := refreshCall(n, ""); code != http.StatusUnauthorized {
		t.Fatalf("without a Bearer: %d, want 401", code)
	}
	if code, _ := refreshCall(n, "forged.jwt.token"); code != http.StatusUnauthorized {
		t.Fatalf("with a forged token: %d, want 401", code)
	}
	// the legitimate refresh rotates the token
	code, resp := refreshCall(n, tok)
	if code != http.StatusOK || resp["token_encrypted"] == "" {
		t.Fatalf("legitimate refresh: %d %v", code, resp)
	}
	newTok := decryptRefreshed(t, resp["token_encrypted"])
	if c, conn := openAgentWS(n, newTok); c != http.StatusSwitchingProtocols {
		t.Fatalf("the new token must open /ws/agent: %d", c)
	} else {
		_ = conn.Close()
	}
	// the OLD token is dead: on /ws/agent and on refresh
	if c, conn := openAgentWS(n, tok); c != http.StatusUnauthorized {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("the replaced token must be refused on /ws/agent: %d", c)
	}
	if code, _ := refreshCall(n, tok); code != http.StatusUnauthorized {
		t.Fatalf("the replaced token must not refresh again: %d", code)
	}

	// REVOCATION CANNOT BE UNDONE (the critical finding): once revoked, the current token cannot refresh
	if code, _ := n.admin("POST", "/api/admin/revoke/refresh-host", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := refreshCall(n, newTok); code != http.StatusUnauthorized {
		t.Fatalf("a revoked agent must not obtain a new token: %d", code)
	}
	if c, conn := openAgentWS(n, newTok); c != http.StatusUnauthorized {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("a revoked token must stay refused: %d", c)
	}
}

func TestTokenRefresh_RealNodeSuspendedAndAttackerCannotKickAnAgent(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	tok := n.enrollAgent("victim-host")

	// the attacker only knows the hostname: flood forged refreshes; the victim's token keeps working
	for i := 0; i < 40; i++ {
		_, _ = n.callOn(n.apiURL(), "POST", "/api/token/refresh", "forged-"+string(rune('a'+i%26)), map[string]string{"hostname": "victim-host"})
	}
	if c, conn := openAgentWS(n, tok); c != http.StatusSwitchingProtocols {
		t.Fatalf("the victim's token was invalidated by forged requests: %d", c)
	} else {
		_ = conn.Close()
	}

	if code, _ := n.admin("POST", "/api/admin/minions/victim-host/suspend", nil); code != http.StatusOK {
		t.Fatalf("suspend: %d", code)
	}
	// right away: the forged flood above (same address) must not have blocked the victim's valid token
	if code, _ := refreshCall(n, tok); code != http.StatusForbidden {
		t.Fatalf("a suspended agent must get 403 (and not be rate limited by a flood of forged requests): %d", code)
	}
}
