// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const (
	shortTTL      = "6s"
	shortInterval = "2s"
)

var (
	thBinOnce sync.Once
	thBinPath string
	thBinErr  error
)

// testHelpersNodeBinary builds (once) the node binary of the renewal tests: this package's test binary
// compiled with `-tags testhelpers`, the seam that lowers the minimum agent JWT lifetime to 2 s / 0.5 s
// (server/agent_jwt_testhelpers.go; never in a release binary). The tests below start nodes with a TTL
// of a few seconds through AGENT_JWT_TTL / AGENT_JWT_RENEW_INTERVAL, so that `go test ./...` and the CI
// need no extra flag. Not built with -race (the nodes of the load test must not be either).
func testHelpersNodeBinary(t *testing.T) string {
	t.Helper()
	thBinOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			thBinErr = err
			return
		}
		dir, err := os.MkdirTemp("", "secagent-th-node-")
		if err != nil {
			thBinErr = err
			return
		}
		thBinPath = filepath.Join(dir, "integration-testhelpers.test")
		cmd := exec.Command(goBin, "test", "-c", "-tags", "testhelpers", "-o", thBinPath, ".")
		cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			thBinErr = fmt.Errorf("building the node binary with -tags testhelpers: %v\n%s", err, out)
		}
	})
	if thBinErr != nil {
		t.Fatal(thBinErr)
	}
	return thBinPath
}

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

// lastRekeyJWT decrypts only the latest rekey frame ("" when none).
func lastRekeyJWT(t *testing.T, m *minion) string {
	t.Helper()
	fr := m.received()
	for i := len(fr) - 1; i >= 0; i-- {
		if fr[i]["type"] == "rekey" {
			return openRekey(t, fr[i])
		}
	}
	return ""
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

// replacedRefusals counts the journal lines saying that a connection of host was refused because its
// token was replaced: the 401 body is a bare {"error":"unauthorized"} (the reason is not revealed to the
// client, only logged — SECURITY.md).
func replacedRefusals(n *node, host string) int {
	c := 0
	for _, l := range strings.Split(plain(n.logs.String()), "\n") {
		if strings.Contains(l, "agent connection refused: hostname="+host) && strings.Contains(l, "token_replaced") {
			c++
		}
	}
	return c
}

func agentJTI(n *node, host string) string {
	s, _ := n.stateSection("agents")[host]["token_jti"].(string)
	return s
}

// (smoke) A minion with a short TTL receives >= 2 rekey frames; each carries a fresh agent JWT for
// the host (distinct JTI, later exp), the link is not cut, and neither token nor full JTI is logged (I5).
func TestSpec217_MinionWithShortTTLReceivesAtLeastTwoRekeys(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv(shortTTL, shortInterval)})
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

// I2: a JTI replaced TWICE (older than the predecessor, which stays valid until the current one is used: M1/M2) is refused (401 token_replaced), while the
// connection of the live agent goes on; exactly one JTI is current per host.
func TestSpec217_I2_AReplacedJTIIsRefusedWith401TokenReplaced(t *testing.T) {
	parallel(t)
	// The TTL is long compared with the three renewals awaited below (~12 s, more on a loaded runner): the replayed
	// tokens must still be UNEXPIRED when they are presented, otherwise they are refused as expired ("WS auth
	// rejected"), not as replaced, and no token_replaced line is journalized (flaky on CI with a 16 s TTL).
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv("90s", "4s")})
	host := "renew-replaced"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)
	waitRekeys(t, m, 3) // current = f3, predecessor = f2: the enrollment JWT and f1 are older
	jwts := rekeyJWTs(t, m)

	base := replacedRefusals(n, host)
	refused := 0
	for name, tok := range map[string]string{"the enrollment JWT": original, "the first renewed JWT": jwts[0]} {
		if exp := expOf(claimsOf(t, tok)); time.Now().Unix() >= exp-2 {
			t.Fatalf("%s expired before the replay (exp %d): the scenario needs a TTL longer than the time taken by the renewals", name, exp)
		}
		conn, code, body := dialAgent(t, n, tok)
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("%s is replaced: it must be refused, got 101", name)
		}
		refused++
		if code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, code)
		}
		if strings.Contains(body, "token_replaced") {
			t.Errorf("%s: the 401 body must not reveal the reason: %q", name, body)
		}
	}
	waitFor(t, "the refusals are journalized as token_replaced", func() bool { return replacedRefusals(n, host)-base >= refused })
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
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: append(addr.env(), renewalEnv(ttl.String(), every)...)})
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
	// stay connected until the ENROLLMENT JWT is really dead (its own exp, plus a margin for the clock
	// granularity of exp in seconds and the load of the machine)
	for exp := expOf(claimsOf(t, tokens[0])); time.Now().Unix() <= exp+3; {
		time.Sleep(200 * time.Millisecond)
	}
	_ = start

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
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv("16s", "4s")})
	host := "renew-restart"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)
	waitRekeys(t, m, 2)
	for time.Now().Unix() <= expOf(claimsOf(t, original))+2 {
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
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv(shortTTL, shortInterval)})
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
// one is the single current one and reconnects; the grace is bounded by the TTL (M5).
func TestSpec217_I7_RotationAndRenewalDoNotConflictLastJTIWins(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-rotation"
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("full node log:\n%s", n.logs.String())
		}
	})
	m := connectMinionWithToken(t, n, host, n.enrollAgent(host))
	// Rotate right after a renewal frame arrived: the next periodic one is ~2 s away, so the frame order is
	// deterministic: [... X signed by the OLD secret, R issued by the rotation (new secret), Y renewal (new)].
	// A token signed with the previous secret skips the JTI check during the grace window (M1 of the
	// security review, pre-existing), hence R and Y — both signed with the NEW secret — are the pair tested.
	waitRekeys(t, m, 1)
	first := len(m.received())
	waitFor(t, "a fresh renewal frame", func() bool { return len(m.received()) > first })
	before := 0
	for _, f := range m.received() {
		if f["type"] == "rekey" {
			before++
		}
	}
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "5s"}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitRekeys(t, m, before+2) // the rotation's frame, then at least one renewal signed with the NEW secret
	jwts := rekeyJWTs(t, m)

	seen := map[string]bool{}
	for _, raw := range jwts {
		if j := jtiOf(claimsOf(t, raw)); seen[j] {
			t.Errorf("JTI %q issued twice", j)
		} else {
			seen[j] = true
		}
	}
	// the latest frame wins (retry: a renewal may replace it between the read and the dial)
	waitFor(t, "the latest issued JWT reconnects", func() bool {
		conn, _, _ := dialAgent(t, n, lastRekeyJWT(t, m))
		if conn == nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}
