package integration

// #217 cycle 2 — M1 / M5 of the security review of the delivered code, on real nodes (-tags testhelpers
// binary, TTL 16 s / interval 4 s).
//
//	M1  a replaced JWT is refused 401 during a rotation grace period although signed with the previous
//	    secret, and its replay does NOT replace the live connection (this is the case I7 used to avoid)
//	M1  an agent that stayed offline during the rotation reconnects with its JWT signed by the previous secret
//	M1  the JTI replaced by the current one is valid until the current one served a handshake, then dead
//	M5  the rotation grace is bounded by AGENT_JWT_TTL

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	m1TTL      = "16s"
	m1Interval = "4s"
)

func m1Node(t *testing.T) *node { return m1NodeTTL(t, m1TTL) }

func m1NodeTTL(t *testing.T, ttl string) *node {
	t.Helper()
	return startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: renewalEnv(ttl, m1Interval)})
}

// m1ReplayTTL: the replay scenario needs JWTs issued at the start (enrollment, first frames) to be still valid
// when they are replayed, i.e. after ~4 frames (3 x the 4 s interval) plus a loaded machine. 16 s left no
// margin (the test used to skip itself when the enrollment JWT had expired); 40 s keeps > 20 s of margin. The
// rotation grace (10 s) stays below the TTL (M5).
const m1ReplayTTL = "40s"

func rekeyCount(m *minion) int {
	c := 0
	for _, f := range m.received() {
		if f["type"] == "rekey" {
			c++
		}
	}
	return c
}

// rotateRightAfterAFrame rotates the keys just after a renewal frame arrived (the next periodic one is
// ~4 s away): the frame order is then deterministic.
func rotateRightAfterAFrame(t *testing.T, n *node, m *minion, grace string) {
	t.Helper()
	first := rekeyCount(m)
	waitFor(t, "a fresh renewal frame", func() bool { return rekeyCount(m) > first })
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": grace}); code != http.StatusOK {
		t.Fatalf("rotate (grace %s): %d %v", grace, code, rot)
	}
}

// M1 (must FAIL with the code before PrevTokenJTI): during the grace period, replaying JWTs that were
// replaced — signed with the previous secret — is refused, and the live connection is untouched.
func TestSecM1_ReplayOfReplacedJWTsSignedWithThePreviousSecretIsRefusedDuringTheGrace(t *testing.T) {
	parallel(t)
	n := m1NodeTTL(t, m1ReplayTTL)
	host := "m1-replay"
	original := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, original)
	waitRekeys(t, m, 1)
	rotateRightAfterAFrame(t, n, m, "10s") // grace <= TTL
	// frames now: [f1 (old secret), f2 (old secret), R (rotation, new secret)] then Y a period later
	waitRekeys(t, m, 4)
	jwts := rekeyJWTs(t, m)
	current := jwts[len(jwts)-1]
	if exp := expOf(claimsOf(t, original)); time.Now().Unix() > exp-1 {
		t.Fatalf("the enrollment JWT expired before the replay (exp %d) although the TTL is %s: the scenario lost its margin", exp, m1ReplayTTL)
	}
	replacedSignedByOldSecret := append([]string{original}, jwts[:len(jwts)-2]...) // all older than the predecessor
	base := replacedRefusals(n, host)
	replayed := 0
	for i, tok := range replacedSignedByOldSecret {
		if time.Now().Unix() > expOf(claimsOf(t, tok))-1 {
			continue // expired by now: refused for another reason, not the case under test
		}
		replayed++
		conn, code, _ := dialAgent(t, n, tok)
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("M1: replayed replaced JWT #%d (signed with the previous secret, within the grace) was ACCEPTED", i)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("replayed JWT #%d: %d, want 401", i, code)
		}
	}
	if replayed < 2 {
		t.Fatalf("only %d replaced JWT(s) were still valid to replay: the scenario needs the enrollment JWT and a rekey JWT", replayed)
	}
	waitFor(t, "the replays are journalized as token_replaced", func() bool { return replacedRefusals(n, host) > base })
	// the live connection was not replaced
	if code, ended := m.closeCode(300 * time.Millisecond); ended {
		t.Errorf("M1: the replay closed the live connection (close %d)", code)
	}
	if n.logs.has(`Replacing stale WS for hostname: "` + host + `"`) {
		t.Error("M1: a replayed token replaced the live WebSocket")
	}
	// and the legitimate current JWT still reconnects
	waitFor(t, "the current JWT reconnects", func() bool {
		conn, _, _ := dialAgent(t, n, lastRekeyJWT(t, m))
		if conn == nil {
			return false
		}
		_ = conn.Close()
		return true
	})
	_ = current
}

// An agent offline during the rotation (it received no rekey): its JWT, signed with the previous secret and
// carrying the CURRENT JTI, is accepted within the grace, and the relay sends it a fresh one.
func TestSecM1_AnAgentOfflineDuringTheRotationReconnectsWithItsPreviousSecretJWT(t *testing.T) {
	parallel(t)
	n := m1Node(t)
	host := "m1-offline"
	m := connectMinionWithToken(t, n, host, n.enrollAgent(host))
	waitRekeys(t, m, 1)
	held := lastRekeyJWT(t, m) // current JTI, signed with the secret that is about to become the previous one
	_ = m.conn.Close()
	time.Sleep(time.Second) // the server noticed: no more renewals for this host
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "12s"}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	conn, code, body := dialAgent(t, n, held)
	if conn == nil {
		t.Fatalf("M1: the JWT of an agent offline during the rotation must be accepted within the grace: %d %s", code, body)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var f map[string]any
	for {
		if err := conn.ReadJSON(&f); err != nil {
			t.Fatalf("the relay must send a fresh JWT (rekey) to an agent that connected with the previous secret: %v", err)
		}
		if f["type"] == "rekey" {
			break
		}
	}
	fresh := openRekey(t, f)
	if jtiOf(claimsOf(t, fresh)) == jtiOf(claimsOf(t, held)) {
		t.Error("the rekey must carry a new JTI")
	}
}

// The JTI replaced by the current one stays valid until the current one is used by a handshake (the agent
// may never have received its new JWT, M2); the first handshake with the current JTI kills it.
func TestSecM1_ThePredecessorIsValidUntilTheCurrentJTIServedAHandshake(t *testing.T) {
	parallel(t)
	n := m1Node(t)

	// host A: the predecessor is accepted as long as the current JTI was not used
	hostA := "m1-prev-a"
	origA := n.enrollAgent(hostA)
	mA := connectMinionWithToken(t, n, hostA, origA)
	waitRekeys(t, mA, 1) // current = f1, predecessor = origA; the next frame is ~4 s away
	// N1: the predecessor is only accepted without a live connection: the agent lost its link
	down := n.logs.count(`Agent disconnected: hostname=` + hostA)
	_ = mA.conn.Close()
	waitFor(t, "the server noticed the disconnection", func() bool { return n.logs.count(`Agent disconnected: hostname=`+hostA) > down })
	if conn, code, body := dialAgent(t, n, origA); conn == nil {
		t.Errorf("the predecessor of a never-used current JTI must be accepted (agent that missed its new JWT): %d %s", code, body)
	} else {
		_ = conn.Close()
	}

	// host B: after a handshake with the current JTI the predecessor is dead
	hostB := "m1-prev-b"
	origB := n.enrollAgent(hostB)
	mB := connectMinionWithToken(t, n, hostB, origB)
	waitRekeys(t, mB, 1)
	currentB := lastRekeyJWT(t, mB)
	conn, code, body := dialAgent(t, n, currentB)
	if conn == nil {
		t.Fatalf("the current JWT must connect: %d %s", code, body)
	}
	defer func() { _ = conn.Close() }()
	if c2, code, _ := dialAgent(t, n, origB); c2 != nil || code != http.StatusUnauthorized {
		if c2 != nil {
			_ = c2.Close()
		}
		t.Errorf("after the first handshake with the current JTI, the predecessor must be refused 401, got %d", code)
	}
}

// M5: the rotation grace cannot outlive the agent JWTs it exists for. The implementation refuses (400) a
// grace above AGENT_JWT_TTL; a default (no grace given) is capped at the TTL.
func TestSecM5_TheRotationGraceIsBoundedByTheAgentJWTLifetime(t *testing.T) {
	parallel(t)
	n := m1Node(t) // TTL 16 s
	code, m := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "1h"})
	if code != http.StatusBadRequest {
		t.Fatalf("a 1 h grace above a 16 s TTL must be refused with 400, got %d %v", code, m)
	}
	if e, _ := m["error"].(string); !strings.Contains(e, "grace") {
		t.Errorf("the refusal must name the grace: %v", m)
	}
	code, m = n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "16s"})
	if code != http.StatusOK {
		t.Fatalf("a grace equal to the TTL must be accepted: %d %v", code, m)
	}
	assertDeadlineWithin(t, m, time.Now(), 16*time.Second)

	// default grace: capped at the TTL, not 24 h
	n2 := m1Node(t)
	code, m = n2.admin("POST", "/api/admin/keys/rotate", nil)
	if code != http.StatusOK {
		t.Fatalf("rotation with the default grace: %d %v", code, m)
	}
	assertDeadlineWithin(t, m, time.Now(), 16*time.Second)
}

// M5 with the production default TTL (24 h): 24 h is accepted, 25 h is refused.
func TestSecM5_WithTheDefault24hTTL25hOfGraceIsRefused(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	if code, m := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "25h"}); code != http.StatusBadRequest {
		t.Errorf("25 h of grace with a 24 h TTL: %d %v, want 400", code, m)
	}
	if code, m := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "24h"}); code != http.StatusOK {
		t.Errorf("24 h of grace with a 24 h TTL: %d %v, want 200", code, m)
	}
}

// assertDeadlineWithin: the deadline was computed by the server BEFORE `afterCall` (taken once the answer is
// back), so it cannot be later than afterCall + max (+1 s for the second granularity of RFC 3339).
func assertDeadlineWithin(t *testing.T, m map[string]any, afterCall time.Time, max time.Duration) {
	t.Helper()
	raw, _ := json.Marshal(m["deadline"])
	var s string
	_ = json.Unmarshal(raw, &s)
	d, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("deadline %q: %v", s, err)
	}
	if d.After(afterCall.Add(max + time.Second)) {
		t.Errorf("the grace deadline %s is beyond now + %s", d.Format(time.RFC3339), max)
	}
}

// N1 (review 2): the predecessor JTI (generation n-1) is only accepted when NO WebSocket is alive for the host
// (the agent that missed its new JWT, M2). While a connection is alive it is refused 401 (reason in the
// journal only) and the live connection is NOT replaced; once the connection is gone it is accepted again.
func TestSecN1_ThePredecessorIsRefusedWhileAConnectionIsAliveAndAcceptedWithoutOne(t *testing.T) {
	parallel(t)
	n := m1Node(t)
	host := "n1-prev"
	orig := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, orig)
	waitRekeys(t, m, 1) // current = f1 (never used at a handshake), predecessor = orig; the next frame is ~4 s away

	// 1. live connection: the predecessor is refused and nothing is replaced
	base := replacedRefusals(n, host)
	conn, code, body := dialAgent(t, n, orig)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("N1: the predecessor was ACCEPTED while a connection is alive")
	}
	if code != http.StatusUnauthorized || strings.Contains(body, "replaced") {
		t.Errorf("predecessor with a live connection: %d %q, want 401 without the reason in the body", code, body)
	}
	waitFor(t, "the refusal is journalized", func() bool {
		return replacedRefusals(n, host) > base || n.logs.has("agent connection refused: hostname="+host)
	})
	if c, ended := m.closeCode(300 * time.Millisecond); ended {
		t.Errorf("N1: the refused replay cut the live connection (close %d)", c)
	}
	if n.logs.has(`Replacing stale WS for hostname: "` + host + `"`) {
		t.Error("N1: the refused replay replaced the live WebSocket")
	}

	// 2. the connection is gone: the agent that never got f1 comes back with the predecessor (M2)
	disconnects := n.logs.count(`Agent disconnected: hostname=` + host)
	_ = m.conn.Close()
	waitFor(t, "the server noticed the disconnection", func() bool { return n.logs.count(`Agent disconnected: hostname=`+host) > disconnects })
	c2, code, body := dialAgent(t, n, orig)
	if c2 == nil {
		t.Fatalf("N1/M2: without a live connection the predecessor must be accepted: %d %s", code, body)
	}
	_ = c2.Close()
}
