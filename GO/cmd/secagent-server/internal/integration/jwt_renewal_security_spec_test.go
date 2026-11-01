package integration

// #217 H3 on real nodes — the renewal loop belongs to ONE connection: it ends when the link closes
// (disconnection, replacement by a reconnection of the same host) and never keeps issuing tokens for a
// host that is gone (reviewer: _work/reports/security-reviewer-lot1-amont-v305.md).

import (
	"regexp"
	"testing"
	"time"
)

func rekeysSentLogged(n *node, host string) int {
	return len(regexp.MustCompile(`Rekey sent to agent: hostname=`+regexp.QuoteMeta(host)+`( |$)`).FindAllString(plain(n.logs.String()), -1))
}

// A minion that disconnects stops being renewed: the count of "Rekey sent" for its host is frozen
// for several periods after the server noticed the disconnection.
func TestSecH3_NoRenewalIsIssuedAfterTheAgentDisconnected(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-gone"
	tok := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, tok)
	waitRekeys(t, m, 1)

	_ = m.conn.Close()
	time.Sleep(2 * time.Second) // the server notices the closed link and ends the loop
	frozen := rekeysSentLogged(n, host)
	jtiFrozen := agentJTI(n, host)
	time.Sleep(4 * 2 * time.Second) // four renewal periods
	if got := rekeysSentLogged(n, host); got != frozen {
		t.Errorf("H3: %d renewal(s) were issued for a disconnected host (loop outlived its connection)", got-frozen)
	}
	if got := agentJTI(n, host); got != jtiFrozen {
		t.Errorf("H3: the stored JTI moved after the disconnection (%q → %q)", jtiFrozen, got)
	}
}

// A reconnection of the same host REPLACES the connection: the old loop ends, only one loop issues
// tokens (a second would double the rate on the new link, since sends are addressed by hostname).
func TestSecH3_AReplacedConnectionDoesNotLeaveASecondLoopRunning(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-replaced-conn"
	first := n.enrollAgent(host)
	a := connectMinionWithToken(t, n, host, first)
	waitRekeys(t, a, 1)
	// the live token: the one of the latest frame (the enrollment one has been replaced by now)
	jwts := rekeyJWTs(t, a)
	b := connectMinionWithToken(t, n, host, jwts[len(jwts)-1])
	baseline := len(b.received())
	nodeBefore := rekeysSentLogged(n, host)

	window := 6 * time.Second // three periods of 2 s
	time.Sleep(window)
	issued := rekeysSentLogged(n, host) - nodeBefore
	// one loop: ~3 renewals in 3 periods (jitter ±10 %, restart of the cycle ⇒ at most 4); two loops would give ~6
	if issued > 4 {
		t.Errorf("H3: %d renewals in %s for ONE live connection (period 2 s): a loop of the replaced connection is still running", issued, window)
	}
	if issued < 1 {
		t.Errorf("the new connection must be renewed (%d renewals)", issued)
	}
	if got := len(b.received()) - baseline; got > 4 {
		t.Errorf("the new link received %d frames in %s", got, window)
	}
}

// H3 with the revocation close (4001): after the cut, the loop of that connection is gone — no renewal
// is logged for the host over several periods, and the stored JTI does not move.
func TestSecH3_The4001RevocationCloseEndsTheLoop(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: renewalEnv(shortTTL, shortInterval)})
	host := "renew-4001"
	m := connectMinionWithToken(t, n, host, n.enrollAgent(host))
	waitRekeys(t, m, 1)
	if code, _ := n.admin("POST", "/api/admin/revoke/"+host, nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, ended := m.closeCode(10 * time.Second); !ended || code != 4001 {
		t.Fatalf("expected close 4001, got %d (ended=%v)", code, ended)
	}
	time.Sleep(2 * time.Second)
	frozen, jti := rekeysSentLogged(n, host), agentJTI(n, host)
	time.Sleep(4 * 2 * time.Second)
	if got := rekeysSentLogged(n, host); got != frozen {
		t.Errorf("H3: %d renewal(s) issued after the 4001 close", got-frozen)
	}
	if got := agentJTI(n, host); got != jti {
		t.Errorf("H3: stored JTI moved after the 4001 close (%q → %q)", jti, got)
	}
}

// Start-up warning (plan: "aucun jeton d'enrôlement réutilisable actif"): logged when no reusable
// enrollment token is active, silent once one exists; the token value is never printed.
func TestSpec217_StartupWarnsWhenNoReusableEnrollmentTokenIsActive(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	n.logs.expectLog(t, "no reusable enrollment token is active", "a fresh state has no reusable enrollment token: the start must warn")

	code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "reusable": true, "hostname_pattern": ".*", "created_by": "test"})
	if code != 201 {
		t.Fatalf("reusable enrollment token: %d %v", code, m)
	}
	tok, _ := m["token"].(string)
	n.restart()
	before := n.logs.count("no reusable enrollment token is active")
	time.Sleep(500 * time.Millisecond)
	if n.logs.count("no reusable enrollment token is active") != before || before != 1 {
		t.Errorf("with a reusable token active the start must not warn again (warnings: %d, expected the single one of the first start)", n.logs.count("no reusable enrollment token is active"))
	}
	if tok != "" && n.logs.has(tok) {
		t.Error("the enrollment token is in the logs")
	}
}
