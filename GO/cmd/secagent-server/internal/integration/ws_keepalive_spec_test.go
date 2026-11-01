package integration

// #217 cycle 4 — keepalive of /ws/agent and the N1 probe, on real nodes (-tags testhelpers binary):
//
//	AGENT_WS_PING_INTERVAL  the relay pings every connection; no pong and no frame within 2 x interval ⇒
//	                        the connection is closed and unregistered
//	AGENT_WS_PROBE_TIMEOUT  the replayed predecessor JWT while a connection LOOKS alive: the relay pings it;
//	                        silence for this long ⇒ dead, closed, the JWT is accepted; an answer ⇒ 401
//
// Without it an agent cut during a rekey comes back with its previous JWT, is refused (N1) while the dead
// connection is still registered (TCP keepalive ≈ 150 s) and — without a reusable enrollment token —
// stops for good: the fleet-wide stop #217 exists to prevent.

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func keepaliveEnv(ping, probe string) []string {
	return []string{"AGENT_WS_PING_INTERVAL=" + ping, "AGENT_WS_PROBE_TIMEOUT=" + probe}
}

// silentAgent is a half-open peer: the TCP link is up, it reads (so it sees the rekey frames) but never
// answers a ping — the relay's pings are swallowed.
type silentAgent struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	frames []map[string]any
	closed chan error
}

func dialSilent(t *testing.T, n *node, tok string) *silentAgent {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + tok}}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 10 * time.Second}
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		t.Fatalf("silent agent dial: %v (resp %v)", err, resp)
	}
	conn.SetPingHandler(func(string) error { return nil }) // no pong, ever
	s := &silentAgent{conn: conn, closed: make(chan error, 1)}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		for {
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				s.closed <- err
				return
			}
			s.mu.Lock()
			s.frames = append(s.frames, msg)
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *silentAgent) rekeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := 0
	for _, f := range s.frames {
		if f["type"] == "rekey" {
			c++
		}
	}
	return c
}

func (s *silentAgent) waitClosed(t *testing.T, within time.Duration, why string) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(within):
		t.Fatalf("%s: the connection was not closed within %s", why, within)
	}
}

func disconnects(n *node, host string) int {
	return n.logs.count(`Agent disconnected: hostname=` + host)
}

// (1) A half-open connection (no pong) is closed and unregistered after the read deadline (2 x interval); a
// responsive one is kept far longer than that.
func TestSpec217_Keepalive_AHalfOpenConnectionIsUnregisteredAfterTheDelay(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: keepaliveEnv("1s", "1s")})

	live := connectMinionWithToken(t, n, "ka-live", n.enrollAgent("ka-live"))
	silent := dialSilent(t, n, n.enrollAgent("ka-silent"))
	start := time.Now()
	silent.waitClosed(t, 20*time.Second, "half-open agent")
	if el := time.Since(start); el < time.Second {
		t.Errorf("the silent connection was cut after %s: faster than the read deadline (2 x 1 s), the ping cannot have been given a chance", el)
	}
	waitFor(t, "the silent agent is unregistered", func() bool { return disconnects(n, "ka-silent") >= 1 })
	// the responsive agent answered every ping over the same period: still there
	time.Sleep(3 * time.Second)
	if c, ended := live.closeCode(100 * time.Millisecond); ended {
		t.Errorf("a responsive agent was cut (close %d)", c)
	}
	if disconnects(n, "ka-live") != 0 {
		t.Error("the responsive agent was unregistered")
	}
}

// (2) The agent comes back with its previous JWT (it never got the rekey: the link died during it) while the
// relay still holds the dead connection: once the connection has been silent for at least one ping interval
// (N2) and failed the probe, the old connection is dropped and the previous JWT is ACCEPTED — no
// re-enrollment, no loss of the agent.
func TestSpec217_Keepalive_APreviousJWTIsAcceptedOnceTheDeadConnectionWasProbed(t *testing.T) {
	parallel(t)
	// ping every 4 s (read deadline 8 s): after 4.5 s of silence the dead connection is still registered; probe 1 s
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: keepaliveEnv("4s", "1s")})
	host := "ka-return"
	orig := n.enrollAgent(host)
	connected := time.Now()
	dead := dialSilent(t, n, orig)
	// a rekey (key rotation) reaches the dying connection: the agent never saw it, `orig` is now the predecessor
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "30s"}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "the rekey was sent on the dying connection", func() bool { return dead.rekeys() >= 1 })
	time.Sleep(time.Until(connected.Add(4500 * time.Millisecond))) // more than one ping interval without any sign of life

	base := replacedRefusals(n, host)
	start := time.Now()
	conn, code, body := dialAgent(t, n, orig)
	if conn == nil {
		t.Fatalf("N1+probe: the previous JWT must be accepted once the dead connection failed the probe: %d %s", code, body)
	}
	defer func() { _ = conn.Close() }()
	if el := time.Since(start); el > 8*time.Second {
		t.Errorf("the handshake waited %s: bounded by the probe (1 s) plus the network", el)
	}
	dead.waitClosed(t, 5*time.Second, "the dead connection replaced by the returning agent")
	if got := replacedRefusals(n, host); got != base {
		t.Errorf("the returning agent was refused as replaced (%d refusals)", got-base)
	}
	// and it is served: the relay sends it a fresh JWT (it connected with the previous secret)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		var f map[string]any
		if err := conn.ReadJSON(&f); err != nil {
			t.Fatalf("the returning agent must be served (fresh JWT): %v", err)
		}
		if f["type"] == "rekey" {
			break
		}
	}
}

// N2: a connection that is silent for LESS than one ping interval is not declared dead, whatever the probe
// would say: the replayed predecessor gets 401 and the connection is kept (an attacker cannot evict a
// healthy but momentarily quiet agent by replaying its previous JWT).
func TestSpec217_Keepalive_AConnectionSilentForLessThanAPingIntervalIsNotDeclaredDead(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: keepaliveEnv("30s", "1s")})
	host := "ka-n2"
	orig := n.enrollAgent(host)
	quiet := dialSilent(t, n, orig) // answers no ping, but the last sign of life (the connection itself) is fresh
	if code, rot := n.admin("POST", "/api/admin/keys/rotate", map[string]any{"grace": "30s"}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "the rekey was sent", func() bool { return quiet.rekeys() >= 1 })

	base := replacedRefusals(n, host)
	conn, code, body := dialAgent(t, n, orig)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("N2: the predecessor was accepted although the connection was silent for less than one ping interval")
	}
	if code != http.StatusUnauthorized || strings.Contains(body, "replaced") || strings.Contains(body, "probe") {
		t.Errorf("replay against a recently-alive connection: %d %q, want 401 without the reason", code, body)
	}
	waitFor(t, "the refusal is journalized", func() bool { return replacedRefusals(n, host) > base })
	select {
	case err := <-quiet.closed:
		t.Errorf("N2: the quiet connection was dropped: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	if disconnects(n, host) != 0 {
		t.Error("N2: the quiet connection was unregistered")
	}
}

// (3) The same replay while the registered connection ANSWERS the probe: 401 (reason only in the journal)
// and the live connection is kept, not replaced.
func TestSpec217_Keepalive_APreviousJWTIsRefusedWhileTheLiveConnectionAnswersTheProbe(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: append(keepaliveEnv("6s", "1s"), renewalEnv("30s", "4s")...)})
	host := "ka-alive"
	orig := n.enrollAgent(host)
	m := connectMinionWithToken(t, n, host, orig)
	waitRekeys(t, m, 1) // current = f1 (unused), predecessor = orig

	base := replacedRefusals(n, host)
	conn, code, body := dialAgent(t, n, orig)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("the predecessor was accepted although the live connection answers")
	}
	if code != http.StatusUnauthorized || strings.Contains(body, "replaced") || strings.Contains(body, "probe") {
		t.Errorf("replay against a live connection: %d %q, want 401 without the reason", code, body)
	}
	waitFor(t, "the refusal is journalized", func() bool { return replacedRefusals(n, host) > base })
	if c, ended := m.closeCode(500 * time.Millisecond); ended {
		t.Errorf("the probe cut the live connection (close %d)", c)
	}
	if n.logs.has(`Replacing stale WS for hostname: "` + host + `"`) {
		t.Error("the live connection was replaced")
	}
	// it keeps being served afterwards
	before := rekeyCount(m)
	waitFor(t, "the live agent is still renewed", func() bool { return rekeyCount(m) > before })
}

// (4) A REVOKED agent (real minion binary) stops at once on the 4001 close: exit code 77, and the relay
// sees no endless retries (one connection ever, no refused handshake).
func TestSpec217_Keepalive_ARevokedRealMinionStopsWithoutRetryingForever(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NodeBinary: testHelpersNodeBinary(t), Env: keepaliveEnv("1s", "1s")})
	host := "ka-revoked"
	addr := nodeAddrs{api: strings.TrimPrefix(n.apiURL(), "https://"), ws: strings.TrimPrefix(n.wssURL(), "wss://")}
	m := startMinionProc(t, host, enrollmentToken(t, n, host), addr)
	m.waitConnections(1, "the minion is connected")
	waitFor(t, "the relay serves the agent", func() bool { return agentServed(n, host, 1) })

	if code, _ := n.admin("POST", "/api/admin/revoke/"+host, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	select {
	case <-m.exited:
	case <-time.After(30 * time.Second):
		t.Fatalf("a revoked minion must stop, it is still running:\n%s", m.logs.String())
	}
	if code := m.cmd.ProcessState.ExitCode(); code != 77 {
		t.Errorf("exit code %d, want 77 (revoked)", code)
	}
	time.Sleep(3 * time.Second)
	if c := n.logs.count("Agent connected: hostname=" + host); c != 1 {
		t.Errorf("the revoked minion connected %d times, want exactly 1 (no retry loop)", c)
	}
	if c := n.logs.count("agent connection refused: hostname=" + host); c != 0 {
		t.Errorf("the revoked minion hammered the relay: %d refused handshakes", c)
	}
}
