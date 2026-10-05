package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// ── /ws/agent authentication is fail closed (#169b) ──────────────────────────

func signRoleToken(t *testing.T, secret, sub, role, jti string) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": sub, "role": role, "jti": jti, "exp": time.Now().Add(time.Hour).Unix()}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// dialAgentRaw dials /ws/agent<query> with arbitrary headers.
func dialAgentRaw(addr, query string, h http.Header) (*websocket.Conn, int, error) {
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws/agent"+query, h)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return c, status, err
}

// TestWiring_AgentAuthFailsClosedOnBothPorts: on the real node (7770 and 7772) nothing but a
// valid signed agent token opens /ws/agent — notably not an unsigned ?hostname=, whether the
// agent is enrolled, revoked or unknown.
func TestWiring_AgentAuthFailsClosedOnBothPorts(t *testing.T) {
	n, api, admin, wsAddr := startNode(t, nil)
	ctx := context.Background()
	for _, h := range []string{"host-ok", "host-revoked"} {
		if _, err := n.store.RegisterAgent(ctx, h, "pem", "jti-"+h); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := adminCall(t, admin, "POST", "/api/admin/revoke/host-revoked", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	secret := serverJWTSecret()
	bearer := func(tok string) http.Header { return http.Header{"Authorization": {"Bearer " + tok}} }

	refused := []struct {
		name, query string
		hdr         http.Header
	}{
		{"revoked, no token", "?hostname=host-revoked", nil},
		{"unknown, no token", "?hostname=ghost", nil},
		{"enrolled, no token", "?hostname=host-ok", nil},
		{"no credentials at all", "", nil},
		{"basic auth", "?hostname=host-ok", http.Header{"Authorization": {"Basic abc"}}},
		{"empty bearer", "?hostname=host-ok", http.Header{"Authorization": {"Bearer "}}},
		{"unsigned forged bearer", "", http.Header{"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJob3N0LW9rIn0.x"}}},
		{"bad secret", "", bearer(signRoleToken(t, "other-secret", "host-ok", "agent", "jti-host-ok"))},
		{"plugin role", "", bearer(signRoleToken(t, secret, "host-ok", "plugin", "jti-host-ok"))},
		{"admin role", "", bearer(signRoleToken(t, secret, "host-ok", "admin", "jti-host-ok"))},
		{"relay role", "", bearer(signRoleToken(t, secret, "host-ok", "relay", "jti-host-ok"))},
		{"no role", "", bearer(signRoleToken(t, secret, "host-ok", "", "jti-host-ok"))},
		{"revoked agent, valid-looking token", "", bearer(signRoleToken(t, secret, "host-revoked", "agent", "jti-host-revoked"))},
	}
	for port, addr := range map[string]string{"7772 (ws)": wsAddr, "7770 (api)": api} {
		for _, tc := range refused {
			c, status, err := dialAgentRaw(addr, tc.query, tc.hdr)
			if c != nil {
				_ = c.Close()
			}
			if err == nil || status != http.StatusUnauthorized {
				t.Errorf("%s / %s: status %d err %v, want 401", port, tc.name, status, err)
			}
		}
		c, status, err := dialAgentRaw(addr, "", bearer(signRoleToken(t, secret, "host-ok", "agent", "jti-host-ok")))
		if err != nil {
			t.Fatalf("%s: valid agent token refused: %v (status %d)", port, err, status)
		}
		_ = c.Close()
	}
}
