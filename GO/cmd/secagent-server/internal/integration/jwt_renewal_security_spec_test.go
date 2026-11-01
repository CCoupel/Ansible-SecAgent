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
