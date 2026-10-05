package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// ── /ws/agent revocation check (#169) ────────────────────────────────────────

func signAgentToken(t *testing.T, secret, host, jti string) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": host, "role": "agent", "exp": time.Now().Add(time.Hour).Unix()}
	if jti != "" {
		claims["jti"] = jti
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dialAgentWS(addr, token string) (*websocket.Conn, int, error) {
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws/agent", h)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return c, status, err
}

func TestWiring_AgentRevocationIsEnforcedOnBothPorts(t *testing.T) {
	n, api, admin, wsAddr := startNode(t, nil)
	ctx := context.Background()
	if _, err := n.store.RegisterAgent(ctx, "host-a", "pem", "jti-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.store.RegisterAgent(ctx, "host-b", "pem", "jti-b"); err != nil {
		t.Fatal(err)
	}
	tokA := signAgentToken(t, "node-test-secret", "host-a", "jti-a")
	tokB := signAgentToken(t, "node-test-secret", "host-b", "jti-b")

	// a legitimate agent connects on the API port (7770) and on the WS port (7772)
	cA, status, err := dialAgentWS(wsAddr, tokA)
	if err != nil {
		t.Fatalf("host-a must connect on the WS port: %v (status %d)", err, status)
	}
	defer func() { _ = cA.Close() }()

	// revoke while connected: the live WS is closed with 4001
	code, body := adminCall(t, admin, "POST", "/api/admin/revoke/host-a", nil)
	if code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if got := readUntilClose(t, cA); got != 4001 {
		t.Errorf("close code = %d, want 4001", got)
	}

	// the revoked token is refused with 401 BEFORE the upgrade, on both ports
	for name, addr := range map[string]string{"7772 (ws)": wsAddr, "7770 (api)": api} {
		if _, status, err := dialAgentWS(addr, tokA); err == nil || status != http.StatusUnauthorized {
			t.Errorf("revoked agent reconnected on %s: status %d err %v, want 401", name, status, err)
		}
	}
	// another agent is unaffected, on both ports
	for name, addr := range map[string]string{"7772 (ws)": wsAddr, "7770 (api)": api} {
		c, status, err := dialAgentWS(addr, tokB)
		if err != nil {
			t.Fatalf("host-b must connect on %s: %v (status %d)", name, err, status)
		}
		_ = c.Close()
	}
}

func TestWiring_AgentReplacedTokenIsRefused(t *testing.T) {
	n, _, _, wsAddr := startNode(t, nil)
	ctx := context.Background()
	if _, err := n.store.RegisterAgent(ctx, "host-r", "pem", "jti-old"); err != nil {
		t.Fatal(err)
	}
	old := signAgentToken(t, "node-test-secret", "host-r", "jti-old")
	// re-enrollment / refresh / rekey replace the current JTI
	if _, err := n.store.UpdateTokenJTI(ctx, "host-r", "jti-new"); err != nil {
		t.Fatal(err)
	}
	if _, status, err := dialAgentWS(wsAddr, old); err == nil || status != http.StatusUnauthorized {
		t.Errorf("replaced token accepted: status %d err %v, want 401", status, err)
	}
	c, status, err := dialAgentWS(wsAddr, signAgentToken(t, "node-test-secret", "host-r", "jti-new"))
	if err != nil {
		t.Fatalf("current token must connect: %v (status %d)", err, status)
	}
	_ = c.Close()
	// unknown agent and token without jti: refused (fail closed)
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, "node-test-secret", "ghost", "jti-g")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("unknown agent accepted: status %d err %v", status, err)
	}
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, "node-test-secret", "host-r", "")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("token without jti accepted: status %d err %v", status, err)
	}
}

func newMemStore(t *testing.T) *storage.Store {
	t.Helper()
	st, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestAgentJTICheck_Matrix(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	if _, err := st.RegisterAgent(ctx, "h", "pem", "cur"); err != nil {
		t.Fatal(err)
	}
	reason := "t"
	if err := st.AddToBlacklist(ctx, "bad", "h", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), &reason); err != nil {
		t.Fatal(err)
	}
	check := agentJTICheck(st)

	cases := []struct {
		name    string
		host    string
		jti     string
		prev    bool
		wantErr string
	}{
		{"current token", "h", "cur", false, ""},
		{"blacklisted", "h", "bad", false, "token_revoked"},
		{"blacklisted even in grace period", "h", "bad", true, "token_revoked"},
		{"replaced token", "h", "older", false, "token_replaced"},
		{"older token during rotation grace period is accepted", "h", "older", true, ""},
		{"unknown agent", "nobody", "cur", false, "unknown_agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := check(tc.host, tc.jti, tc.prev)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	// store failure → refused (fail closed)
	closed := newMemStore(t)
	_ = closed.Close()
	if err := agentJTICheck(closed)("h", "cur", false); err == nil {
		t.Error("a store failure must refuse the connection")
	}
}
