package integration

// #217 (v3.0.5, D1) — periodic renewal of the agent JWT on the authenticated WebSocket, through the
// existing control frame {"type":"rekey","token_encrypted":…}. Source: the invariants I1-I7 of
// _work/mockup/v3.0.5/conception/agent_jwt__renouvellement_217.md. Before the fix a minion that stayed
// connected longer than the JWT lifetime (1 h hard-coded) came back with an expired token after any
// relay restart, and — its enrollment token being consumed — stopped for good (exit 78).
//
// The nodes are started with a short TTL through AGENT_JWT_TTL / AGENT_JWT_RENEW_INTERVAL (6 s / 2 s,
// the "TTL court" of the plan); the I6 load test is in jwt_renewal_load_slow_test.go.
//
//	I1 revoked agent never receives a renewal            I5 no JWT / token in the logs
//	I2 replaced JTI refused (401 token_replaced)         I6 3 000 agents without burst (slow file)
//	I3 reconnection after > TTL without enrollment token  I7 rotation + renewal: last JTI wins

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const (
	shortTTL      = "6s"
	shortInterval = "2s"
)

func renewalEnv(ttl, interval string) []string {
	return []string{"AGENT_JWT_TTL=" + ttl, "AGENT_JWT_RENEW_INTERVAL=" + interval}
}

func claimsOf(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	c := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, c); err != nil {
		t.Fatalf("not a JWT: %v", err)
	}
	return c
}

func expOf(c jwt.MapClaims) int64  { f, _ := c["exp"].(float64); return int64(f) }
func jtiOf(c jwt.MapClaims) string { s, _ := c["jti"].(string); return s }

// openRekey decrypts the token_encrypted of a rekey frame with the harness agent key.
func openRekey(t *testing.T, frame map[string]any) string {
	t.Helper()
	key, _, err := harnessAgentKeyErr()
	if err != nil {
		t.Fatal(err)
	}
	return openRekeyWith(t, key, frame)
}

func openRekeyWith(t *testing.T, key *rsa.PrivateKey, frame map[string]any) string {
	t.Helper()
	enc, _ := frame["token_encrypted"].(string)
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("token_encrypted must be base64: %v", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, key, ct, nil)
	if err != nil {
		t.Fatalf("token_encrypted must be RSA-OAEP(SHA-256) under the agent's public key: %v", err)
	}
	return string(plain)
}

// rekeyJWTs returns, in order, the JWTs of every rekey frame the minion received.
func rekeyJWTs(t *testing.T, m *minion) []string {
	t.Helper()
	var out []string
	for _, f := range m.received() {
		if f["type"] == "rekey" {
			out = append(out, openRekey(t, f))
		}
	}
	return out
}

func waitRekeys(t *testing.T, m *minion, n int) {
	t.Helper()
	waitFor(t, "the minion received its rekey frame(s)", func() bool {
		c := 0
		for _, f := range m.received() {
			if f["type"] == "rekey" {
				c++
			}
		}
		return c >= n
	})
}

// dialAgent opens /ws/agent with tok; on success the connection is returned (caller closes), else the
// HTTP status and body of the refusal.
func dialAgent(t *testing.T, n *node, tok string) (conn *websocket.Conn, status int, body string) {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + tok}}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 10 * time.Second}
	c, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err == nil {
		return c, http.StatusSwitchingProtocols, ""
	}
	if resp == nil {
		t.Fatalf("dial /ws/agent: %v", err)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return nil, resp.StatusCode, string(b)
}

func agentJTI(n *node, host string) string {
	s, _ := n.stateSection("agents")[host]["token_jti"].(string)
	return s
}

// (smoke) A minion with a short TTL receives >= 2 rekey frames; each carries a fresh agent JWT for
// the host (distinct JTI, later exp), the link is not cut, and neither token nor full JTI is logged (I5).
func TestSpec217_MinionWithShortTTLReceivesAtLeastTwoRekeys(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-two"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)

	waitRekeys(t, m, 2)
	jwts := rekeyJWTs(t, m)
	prev := claimsOf(t, original)
	seen := map[string]bool{jtiOf(prev): true}
	for i, raw := range jwts {
		c := claimsOf(t, raw)
		if c["sub"] != host || c["role"] != "agent" {
			t.Errorf("rekey %d: claims %v", i+1, c)
		}
		if seen[jtiOf(c)] {
			t.Errorf("rekey %d: JTI %q already used", i+1, jtiOf(c))
		}
		seen[jtiOf(c)] = true
		if expOf(c) <= expOf(prev) {
			t.Errorf("rekey %d: exp %d is not later than the previous %d", i+1, expOf(c), expOf(prev))
		}
		if d := expOf(c) - int64(c["iat"].(float64)); d < 5 || d > 7 {
			t.Errorf("rekey %d: lifetime %ds, want AGENT_JWT_TTL=6s", i+1, d)
		}
		prev = c
	}
	if code, ended := m.closeCode(200 * time.Millisecond); ended {
		t.Errorf("a renewal must keep the connection (link closed with %d)", code)
	}
	if got := agentJTI(n, host); got == "" || got == jtiOf(claimsOf(t, original)) {
		t.Errorf("the stored JTI %q must be one the relay issued by renewal, not the enrollment one", got)
	}
	// I5: nothing secret in the node's logs (the full JTI is not a secret but the journal truncates it)
	all := append([]string{original}, jwts...)
	assertNoSecrets(t, n.logs.String(), all...)
	for jti := range seen {
		if len(jti) >= 32 && n.logs.has(jti) {
			t.Errorf("I5: the full JTI %q is in the logs (truncate it)", jti)
		}
	}
}

// I2: the replaced JTI is refused (401 token_replaced) as soon as a rekey replaced it, while the
// connection of the live agent goes on; exactly one JTI is current per host.
func TestSpec217_I2_AReplacedJTIIsRefusedWith401TokenReplaced(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-replaced"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)
	waitRekeys(t, m, 2)
	jwts := rekeyJWTs(t, m)

	for name, tok := range map[string]string{"the enrollment JWT": original, "the first renewed JWT": jwts[0]} {
		conn, code, body := dialAgent(t, n, tok)
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("%s is replaced: it must be refused, got 101", name)
		}
		if code != http.StatusUnauthorized || !strings.Contains(body, "token_replaced") {
			t.Errorf("%s: %d %q, want 401 token_replaced", name, code, body)
		}
	}
	if _, ended := m.closeCode(100 * time.Millisecond); ended {
		t.Error("refusing an old token must not cut the live link")
	}
}

// I3 (the heart of #217, with the REAL minion binary): a minion connected for longer than the TTL
// whose relay restarts reconnects with its renewed JWT — WITHOUT enrollment token (its own is
// consumed: a re-enrollment would be refused and the minion would stop with code 78).
func TestSpec217_I3_RealMinionReconnectsAfterRelayRestartBeyondTTLWithoutEnrollment(t *testing.T) {
	parallel(t)
	const ttl, every = 16 * time.Second, "4s"
	addr := newNodeAddrs(t)
	n := startNode(t, nodeSpec{ID: "root", Env: append(addr.env(), renewalEnv(ttl.String(), every)...)})
	host := "renew-real"
	start := time.Now()
	m := startMinionProc(t, host, enrollmentToken(t, n, host), addr)
	m.waitConnections(1, "the minion is connected")

	// the file the minion persists changes at every renewal (mode 0600), exp moving forward
	var tokens []string
	waitFor(t, "the minion persisted >= 2 renewed JWTs", func() bool {
		b, err := os.ReadFile(m.jwtPath)
		if err != nil {
			return false
		}
		cur := strings.TrimSpace(string(b))
		if len(tokens) == 0 || tokens[len(tokens)-1] != cur {
			tokens = append(tokens, cur)
		}
		return len(tokens) >= 3
	})
	if st, err := os.Stat(m.jwtPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("token.jwt must be 0600: %v %v", st, err)
	}
	for i := 1; i < len(tokens); i++ {
		if expOf(claimsOf(t, tokens[i])) <= expOf(claimsOf(t, tokens[i-1])) {
			t.Errorf("persisted JWT %d does not extend the validity of the previous one", i)
		}
	}
	// stay connected beyond the lifetime of the ENROLLMENT JWT
	if rest := ttl + 2*time.Second - time.Since(start); rest > 0 {
		time.Sleep(rest)
	}
	if exp := expOf(claimsOf(t, tokens[0])); time.Now().Unix() <= exp {
		t.Fatalf("test precondition: the enrollment JWT must have expired (exp %d, now %d)", exp, time.Now().Unix())
	}

	n.restart()
	m.waitConnections(2, "the minion reconnected to the restarted relay")
	select {
	case <-m.exited:
		t.Fatalf("the minion stopped instead of reconnecting:\n%s", m.logs.String())
	default:
	}
	waitFor(t, "the relay serves the agent again", func() bool { return agentServed(n, host, 2) })
	if strings.Contains(strings.ToLower(m.logs.String()), "re-enroll") {
		t.Errorf("the minion must not re-enroll:\n%s", m.logs.String())
	}
}

// I3, protocol level (fake minion): the latest renewed JWT is accepted after a relay restart that
// happens when the enrollment JWT has expired; the enrollment JWT itself is not.
func TestSpec217_I3_LatestRenewedJWTIsAcceptedAfterRestartButTheExpiredOneIsNot(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv("16s", "4s")})
	host := "renew-restart"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)
	waitRekeys(t, m, 2)
	for time.Now().Unix() <= expOf(claimsOf(t, original)) {
		time.Sleep(200 * time.Millisecond)
	}
	waitRekeys(t, m, 3) // still renewing after the first token's death
	jwts := rekeyJWTs(t, m)
	latest := jwts[len(jwts)-1]

	n.restart()
	conn, code, body := dialAgent(t, n, latest)
	if conn == nil {
		t.Fatalf("the latest renewed JWT must reconnect without enrollment: %d %s", code, body)
	}
	_ = conn.Close()
	if conn, code, _ = dialAgent(t, n, original); conn != nil || code != http.StatusUnauthorized {
		t.Errorf("the expired enrollment JWT must be refused with 401, got %d", code)
	}
}

// I1 (critical): a revoked agent is never issued a JWT again. After the revocation its link is cut
// (4001), its stored JTI does not move over several renewal periods, and the last token it holds is
// refused.
func TestSpec217_I1_ARevokedAgentNeverReceivesAJWT(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-revoked"
	m := connectMinionWithToken(t, n, host, n.enrollAgent(host))
	waitRekeys(t, m, 1)

	if code, _ := n.admin("POST", "/api/admin/revoke/"+host, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, ended := m.closeCode(10 * time.Second); !ended || code != 4001 {
		t.Fatalf("the revoked link must be cut with 4001, got %d (ended=%v)", code, ended)
	}
	frames := len(m.received())
	jtiAtRevocation := agentJTI(n, host)
	last := rekeyJWTs(t, m)

	time.Sleep(3 * 2 * time.Second) // three renewal periods
	if got := agentJTI(n, host); got != jtiAtRevocation {
		t.Errorf("the stored JTI of a revoked agent moved (%q → %q): a token was issued", jtiAtRevocation, got)
	}
	if len(m.received()) != frames {
		t.Error("a frame reached a revoked agent")
	}
	conn, code, body := dialAgent(t, n, last[len(last)-1])
	if conn != nil {
		_ = conn.Close()
		t.Fatal("the last token of a revoked agent must be refused")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("revoked agent reconnection: %d %q, want 401", code, body)
	}
	// and it cannot re-enroll its way back with a standing authorization (#193)
	assertNoSecrets(t, n.logs.String(), last...)
}

// I7: key rotation (AdminRotateKeys) then periodic renewal: every frame is a distinct JTI, the LAST
// one is the single current one and reconnects; the one the rotation issued is refused once replaced.
func TestSpec217_I7_RotationAndRenewalDoNotConflictLastJTIWins(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-rotation"
	m := connectMinionWithToken(t, n, host, n.enrollAgent(host))
	waitRekeys(t, m, 1)

	before := len(rekeyJWTs(t, m))
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "1h"}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitRekeys(t, m, before+2) // the rotation's frame, then at least one renewal signed with the NEW secret
	jwts := rekeyJWTs(t, m)
	rotation := jwts[before]

	seen := map[string]bool{}
	for _, raw := range jwts {
		if j := jtiOf(claimsOf(t, raw)); seen[j] {
			t.Errorf("JTI %q issued twice", j)
		} else {
			seen[j] = true
		}
	}
	if conn, code, body := dialAgent(t, n, rotation); conn != nil || code != http.StatusUnauthorized || !strings.Contains(body, "token_replaced") {
		if conn != nil {
			_ = conn.Close()
		}
		t.Errorf("the token the rotation issued was replaced by a later renewal: %d %q, want 401 token_replaced", code, body)
	}
	// the latest frame wins (retry: a renewal may replace it between the read and the dial)
	waitFor(t, "the latest issued JWT reconnects", func() bool {
		all := rekeyJWTs(t, m)
		conn, _, _ := dialAgent(t, n, all[len(all)-1])
		if conn == nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}
