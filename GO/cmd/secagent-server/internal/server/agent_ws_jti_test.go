package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/storage/storagetest"
	"secagent-server/cmd/secagent-server/internal/ws"
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
	tokA := signAgentToken(t, serverJWTSecret(), "host-a", "jti-a")
	tokB := signAgentToken(t, serverJWTSecret(), "host-b", "jti-b")

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
	old := signAgentToken(t, serverJWTSecret(), "host-r", "jti-old")
	// a re-enrollment replaces the current JTI and forgets the old one (a rekey keeps it until the new
	// one is used: TestAgentJTICheck_ReplacedJTIIsKeptUntilTheCurrentOneIsUsed)
	if _, err := n.store.RegisterAgent(ctx, "host-r", "pem", "jti-new"); err != nil {
		t.Fatal(err)
	}
	if _, status, err := dialAgentWS(wsAddr, old); err == nil || status != http.StatusUnauthorized {
		t.Errorf("replaced token accepted: status %d err %v, want 401", status, err)
	}
	c, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), "host-r", "jti-new"))
	if err != nil {
		t.Fatalf("current token must connect: %v (status %d)", err, status)
	}
	_ = c.Close()
	// unknown agent and token without jti: refused (fail closed)
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), "ghost", "jti-g")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("unknown agent accepted: status %d err %v", status, err)
	}
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), "host-r", "")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("token without jti accepted: status %d err %v", status, err)
	}
}

func newMemStore(t *testing.T) *storage.Store {
	t.Helper()
	st, err := storagetest.OpenTemp()
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
		{"older token signed with the previous secret is refused too (M1)", "h", "older", true, "token_replaced"},
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

// M1/M2 (#217): the JTI replaced by a rekey stays valid only until the current one serves a handshake.
func TestAgentJTICheck_ReplacedJTIIsKeptUntilTheCurrentOneIsUsed(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	if _, err := st.RegisterAgent(ctx, "h", "pem", "j1"); err != nil {
		t.Fatal(err)
	}
	check := agentJTICheck(st)
	if _, err := st.UpdateTokenJTIUnlessRevoked(ctx, "h", "j2"); err != nil { // renewal: j1 -> prev
		t.Fatal(err)
	}
	for _, usedPrev := range []bool{false, true} { // whichever secret signed it
		if err := check("h", "j1", usedPrev); err != nil {
			t.Fatalf("the replaced JTI must be accepted while j2 was never used (usedPrevious=%v): %v", usedPrev, err)
		}
	}
	if err := check("h", "j2", false); err != nil { // first handshake with the current JTI
		t.Fatal(err)
	}
	for _, usedPrev := range []bool{false, true} {
		if err := check("h", "j1", usedPrev); err == nil || !strings.Contains(err.Error(), "token_replaced") {
			t.Fatalf("j1 must be refused once j2 was used (usedPrevious=%v): %v", usedPrev, err)
		}
	}
	a, _ := st.GetAgent(ctx, "h")
	if a.PrevTokenJTI != "" || a.TokenJTI != "j2" {
		t.Fatalf("state after confirmation: %+v", a)
	}
	// two renewals without a handshake: only the JTI right before the current one is kept
	_, _ = st.UpdateTokenJTIUnlessRevoked(ctx, "h", "j3")
	_, _ = st.UpdateTokenJTIUnlessRevoked(ctx, "h", "j4")
	if err := check("h", "j2", false); err == nil {
		t.Error("a JTI two generations old must be refused")
	}
	if err := check("h", "j3", false); err != nil {
		t.Errorf("the previous generation is still accepted: %v", err)
	}
	// a re-enrollment forgets the replaced JTI
	if _, err := st.RegisterAgent(ctx, "h", "pem", "j5"); err != nil {
		t.Fatal(err)
	}
	if err := check("h", "j4", false); err == nil {
		t.Error("an enrollment must drop the replaced JTI")
	}
}

// N1 (#217): without a live connection the replaced JTI is accepted.
func TestAgentJTICheck_ReplacedJTIIsAcceptedWithoutALiveConnection(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	if _, err := st.RegisterAgent(ctx, "n1-host", "pem", "k1"); err != nil {
		t.Fatal(err)
	}
	_, _ = st.UpdateTokenJTIUnlessRevoked(ctx, "n1-host", "k2")
	if err := agentJTICheck(st)("n1-host", "k1", true); err != nil {
		t.Fatalf("without a live connection the replaced JTI is accepted: %v", err)
	}
}

// N1 with the probe, through the real handshake: a live connection that answers the ping makes the
// replaced JTI be refused (401) and stays registered; one that does not answer within the probe delay
// is dropped and the replaced JTI is accepted.
func TestWiring_ReplacedJTIProbeDecidesBetweenALiveAndADeadConnection(t *testing.T) {
	n, _, _, wsAddr := startNode(t, func(c *Config) { c.AgentWSProbeTimeout = time.Second; c.AgentWSPingInterval = 5 * time.Second })
	ctx := context.Background()
	secret := serverJWTSecret()

	// enroll with j1, then a rekey makes j2 current; the agent connects with j2; a later rekey makes
	// j3 current and j2 the replaced JTI that a stale holder (or the agent after a cut) presents
	connect := func(host string) *websocket.Conn {
		if _, err := n.store.RegisterAgent(ctx, host, "pem", "j1"); err != nil {
			t.Fatal(err)
		}
		_, _ = n.store.UpdateTokenJTIUnlessRevoked(ctx, host, "j2")
		c, status, err := dialAgentWS(wsAddr, signAgentToken(t, secret, host, "j2"))
		if err != nil {
			t.Fatalf("current token must connect: %v (%d)", err, status)
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = n.store.UpdateTokenJTIUnlessRevoked(ctx, host, "j3")
		return c
	}

	// responsive agent: its client keeps reading, so gorilla answers the ping
	live := connect("n1-live")
	go func() {
		for {
			if _, _, err := live.ReadMessage(); err != nil {
				return
			}
		}
	}()
	if c, status, err := dialAgentWS(wsAddr, signAgentToken(t, secret, "n1-live", "j2")); err == nil || status != http.StatusUnauthorized {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("a responsive live connection must make the replaced JTI be refused: status %d err %v", status, err)
	}
	if _, gerr := ws.GetConnection("n1-live"); gerr != nil {
		t.Fatalf("the live connection must stay registered: %v", gerr)
	}

	// dead agent: its client never reads, so no pong
	_ = connect("n1-dead") // its client never reads: no pong
	// N2: the probe concludes "dead" only after one ping interval without any sign of life
	time.Sleep(5200 * time.Millisecond)
	start := time.Now()
	c, status, err := dialAgentWS(wsAddr, signAgentToken(t, secret, "n1-dead", "j2"))
	if err != nil {
		t.Fatalf("a connection that does not answer the probe must let the replaced JTI in: status %d err %v", status, err)
	}
	_ = c.Close()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the handshake waited %s for the probe (probe delay 1 s)", d)
	}
}

// M12 (#233): after `minions delete`, the old JWT is refused at the handshake (the row is gone and the JTIs are
// blacklisted) and the live socket is closed; a reconnection DURING the deletion cannot be accepted either, since
// the JTI is refused before the row goes.
func TestWiring_DeletedAgentCannotComeBackWithItsJWT(t *testing.T) {
	n, _, admin, wsAddr := startNode(t, nil)
	ctx := context.Background()
	secret := serverJWTSecret()
	if _, err := n.store.RegisterAgent(ctx, "del-host", "pem", "jti-d1"); err != nil {
		t.Fatal(err)
	}
	tok := signAgentToken(t, secret, "del-host", "jti-d1")
	live, status, err := dialAgentWS(wsAddr, tok)
	if err != nil {
		t.Fatalf("connect: %v (%d)", err, status)
	}
	defer live.Close()
	closed := make(chan struct{})
	go func() {
		for {
			if _, _, rerr := live.ReadMessage(); rerr != nil {
				close(closed)
				return
			}
		}
	}()

	// hammer the handshake with the old JWT while the deletion runs: once it is blacklisted, nothing is accepted
	stop := make(chan struct{})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, _, derr := dialAgentWS(wsAddr, tok); derr == nil {
				accepted.Add(1)
				_ = c.Close()
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	code, body := adminCall(t, admin, "DELETE", "/api/admin/minions/del-host", nil)
	if code != http.StatusOK {
		t.Fatalf("delete: %d %s", code, body)
	}
	before := accepted.Load()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	if accepted.Load() != before {
		t.Errorf("%d handshake(s) accepted AFTER the deletion returned", accepted.Load()-before)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Error("the live socket was not closed")
	}
	if c, st, derr := dialAgentWS(wsAddr, tok); derr == nil || st != http.StatusUnauthorized {
		if c != nil {
			_ = c.Close()
		}
		t.Errorf("the old JWT after the deletion: status %d err %v, want 401", st, derr)
	}
	if bl, _ := n.store.IsJTIBlacklisted(ctx, "jti-d1"); !bl {
		t.Error("the deleted agent's JTI must be blacklisted")
	}
}
