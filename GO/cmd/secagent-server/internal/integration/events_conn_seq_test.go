// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// #265 — host.up / host.reconnect decided by the X-SecAgent-Conn-Seq header of the minion
// (1 or absent or invalid ⇒ host.up ; > 1 ⇒ host.reconnect ; never both ; no server memory).

func TestConnSeq_HeaderDecidesHostUpOrHostReconnect(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	cases := []struct {
		name string
		seq  *string
		want string // event expected for this connection
	}{
		{"1", strp("1"), "host.up"},
		{"2", strp("2"), "host.reconnect"},
		{"7", strp("7"), "host.reconnect"},
		{"absent (minion v3.0.5)", nil, "host.up"},
		{"empty", strp(""), "host.up"},
		{"0", strp("0"), "host.up"},
		{"-1", strp("-1"), "host.up"},
		{"abc", strp("abc"), "host.up"},
		{"above 2^31", strp("2147483649"), "host.up"},
		{"huge", strp("99999999999999999999"), "host.up"},
		{"decimal", strp("2.5"), "host.up"},
	}
	for i, c := range cases {
		host := fmt.Sprintf("seq-host-%02d", i)
		dialAgentSeq(t, n, n.enrollAgent(host), c.seq)
		other := "host.reconnect"
		if c.want == "host.reconnect" {
			other = "host.up"
		}
		waitFor(t, c.name+": "+c.want+" for "+host, func() bool { return len(n.hostLines(c.want, host)) >= 1 })
		time.Sleep(100 * time.Millisecond) // the exclusive event would have been dispatched by now
		if got := len(n.hostLines(c.want, host)); got != 1 {
			t.Errorf("conn-seq %s: %d %s for %s, want exactly 1", c.name, got, c.want, host)
		}
		if got := len(n.hostLines(other, host)); got != 0 {
			t.Errorf("conn-seq %s: %d %s for %s, want 0 (up and reconnect are exclusive)", c.name, got, other, host)
		}
	}
}

// The variable SECAGENT_CONN_SEQ carries the announced value (valid values only), and the event has no relay id.
func TestConnSeq_EnvCarriesTheConnSeq(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	dialAgentSeq(t, n, n.enrollAgent("seq-env-r"), strp("7"))
	waitFor(t, "host.reconnect with seq=7", func() bool { return len(n.hostLines("host.reconnect", "seq-env-r")) == 1 })
	if l := n.hostLines("host.reconnect", "seq-env-r"); len(l) == 1 && !strings.Contains(l[0], " seq=7 ") {
		t.Errorf("SECAGENT_CONN_SEQ missing or wrong: %q", l[0])
	}
	dialAgentSeq(t, n, n.enrollAgent("seq-env-u"), strp("1"))
	waitFor(t, "host.up with seq=1", func() bool { return len(n.hostLines("host.up", "seq-env-u")) == 1 })
	if l := n.hostLines("host.up", "seq-env-u"); len(l) == 1 && !strings.Contains(l[0], " seq=1 ") {
		t.Errorf("SECAGENT_CONN_SEQ missing or wrong for host.up: %q", l[0])
	}
}

// A second connection of the SAME process (seq 2) to a node that has never seen the host gives host.reconnect:
// the server keeps no memory (this is what happens on the new master after a fail-over).
func TestConnSeq_NoServerMemory_ReconnectOnAFreshNode(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	dialAgentSeq(t, n, n.enrollAgent("fresh-host"), strp("2"))
	waitFor(t, "host.reconnect", func() bool { return len(n.hostLines("host.reconnect", "fresh-host")) == 1 })
	if got := len(n.hostLines("host.up", "fresh-host")); got != 0 {
		t.Errorf("%d host.up for a first-seen host announcing conn_seq 2", got)
	}
}

// REAL minion binary: first connection ⇒ host.up ; the node restarts, the same minion process reconnects ⇒
// host.reconnect and NO new host.up.
func TestConnSeq_RealMinion_RestartOfTheNodeGivesHostReconnect(t *testing.T) {
	parallel(t)
	addrs := newNodeAddrs(t)
	n := startNode(t, nodeSpec{ID: "root", Env: addrs.env(), Hooks: lifecycleHooks})
	m := startMinionProc(t, "real-seq", enrollmentToken(t, n, "real-seq"), addrs)
	m.waitConnections(1, "first connection of the minion")
	waitFor(t, "host.up on the first connection", func() bool { return len(n.hostLines("host.up", "real-seq")) == 1 })
	if l := n.hostLines("host.up", "real-seq"); !strings.Contains(l[0], " seq=1 ") {
		t.Errorf("first connection must announce conn_seq 1: %q", l[0])
	}
	n.restart()
	m.waitConnections(2, "the minion reconnects to the restarted node")
	waitFor(t, "host.reconnect after the reconnection", func() bool { return len(n.hostLines("host.reconnect", "real-seq")) >= 1 })
	if got := len(n.hostLines("host.up", "real-seq")); got != 1 {
		t.Errorf("%d host.up in total, want 1 (the reconnection of the same process is host.reconnect)", got)
	}
}

// Only SUCCESSFUL handshakes count: N failed dials (closed addresses) then the first successful connection
// announce conn_seq 1 ⇒ host.up, never host.reconnect.
func TestConnSeq_RealMinion_FailedDialsDoNotCount(t *testing.T) {
	parallel(t)
	live := newNodeAddrs(t)
	n := startNode(t, nodeSpec{ID: "root", Env: live.env(), Hooks: lifecycleHooks})
	dead1, dead2, dead3 := newNodeAddrs(t), newNodeAddrs(t), newNodeAddrs(t)
	m := startMinionProc(t, "dial-fail", enrollmentToken(t, n, "dial-fail"), dead1, dead2, dead3, live)
	m.waitConnections(1, "first successful connection after failed dials")
	waitFor(t, "host.up", func() bool { return len(n.hostLines("host.up", "dial-fail")) == 1 })
	if l := n.hostLines("host.up", "dial-fail"); !strings.Contains(l[0], " seq=1 ") {
		t.Errorf("first successful handshake after failed dials must announce conn_seq 1: %q", l[0])
	}
	time.Sleep(200 * time.Millisecond)
	if got := len(n.hostLines("host.reconnect", "dial-fail")); got != 0 {
		t.Errorf("%d host.reconnect after failed dials then a first success, want 0", got)
	}
}
