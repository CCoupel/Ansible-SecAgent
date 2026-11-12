// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"strings"
	"testing"
	"time"
)

// LOT-3.2 (#246b) — relay.converged: emitted ONCE by a node after its relay.failover, when every declared child relay
// is back (or at RELAY_CONVERGENCE_TIMEOUT), with exact counts. Contract: planner-lot32 §T17.
// RED on e0d1970: the event does not exist.

// convergedPair starts root a/b (lot32 hooks, RELAY_CONVERGENCE_TIMEOUT=5s), declares and starts `started` children
// among the `declared` ones, and returns the pair ready for a switch-over.
// ownConverged keeps the relay.converged of the root itself: the children emit theirs too and the root journals them.
var ownConverged = map[string]string{"relay": "root"}

func convergedPair(t *testing.T, declared []string, started int) (a, b *node) {
	t.Helper()
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a = startNode(t, nodeSpec{ID: "root", Env: append(addrA.env(), "RELAY_CONVERGENCE_TIMEOUT=5s"), Hooks: lot32Hooks})
	tokens := map[string]string{}
	for _, id := range declared {
		tokens[id] = a.registerChild(id)
	}
	b = a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	for i, id := range declared {
		if i >= started {
			break // declared, never started: the absent child
		}
		c := startNode(t, nodeSpec{ID: id, ParentURL: "wss://" + addrA.ws + ",wss://" + addrB.ws, ParentToken: tokens[id]})
		waitFor(t, id+" linked", func() bool { return c.upstreamState() == "connected" })
	}
	return a, b
}

func switchOver(t *testing.T, a, b *node) {
	t.Helper()
	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
}

// (8) two declared children, both reconnect: ONE relay.converged with exact counts, after relay.failover.
func TestRelayConverged_TwoChildrenBackGivesOneEventWithExactCounts(t *testing.T) {
	twoChildrenBack(t, settle)
}

// twoChildrenBack runs the scenario; `noSecond` is how long it waits to prove that no second event follows (the slow
// variant waits longer than RELAY_CONVERGENCE_TIMEOUT: the timer must not emit again).
func twoChildrenBack(t *testing.T, noSecond time.Duration) {
	t.Helper()
	parallel(t)
	a, b := convergedPair(t, []string{"relay1", "relay2"}, 2)
	before := len(b.eventsOf("relay.converged", ownConverged)) // a's own start already emitted one (0 child connected then)
	switchOver(t, a, b)

	waitFor(t, "relay.converged after the switch-over", func() bool { return len(b.eventsOf("relay.converged", ownConverged)) == before+1 })
	time.Sleep(noSecond)
	all := b.eventsOf("relay.converged", ownConverged)
	if len(all) != before+1 {
		t.Fatalf("%d relay.converged in total, want %d (exactly one per promotion)", len(all), before+1)
	}
	e := all[len(all)-1]
	for k, v := range map[string]string{"relay": "root", "rc": "2", "rm": "0", "hd": "0", "hr": "0", "dropped": "0", "host": ""} {
		if e[k] != v {
			t.Errorf("relay.converged %s = %q, want %q (%v)", k, e[k], v, e)
		}
	}
	// order in the journal of the new master: relay.failover (takeover) < relay.reconnect of the children < relay.converged
	lines := b.hookLines()
	fo, cv, lastRe := -1, -1, -1
	for i, l := range lines {
		switch ev, kv := parseLine(l); {
		case ev == "relay.failover" && kv["cause"] == "takeover":
			fo = i
		case ev == "relay.converged" && kv["relay"] == "root":
			cv = i
		case ev == "relay.reconnect" || ev == "relay.up":
			lastRe = i
		}
	}
	if fo < 0 || fo >= lastRe || lastRe >= cv {
		t.Errorf("order must be failover < children back < converged (%d, %d, %d):\n%s", fo, lastRe, cv, strings.Join(lines, "\n"))
	}
}

// (8) a node without any declared child emits it immediately after relay.failover: 0 connected, 0 missing.
func TestRelayConverged_NodeWithoutChildIsImmediate(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks, Env: []string{"RELAY_CONVERGENCE_TIMEOUT=60s"}})
	waitFor(t, "relay.converged right after the start (well before the 60s timeout)", func() bool { return len(root.eventsOf("relay.converged", ownConverged)) == 1 })
	e := root.eventsOf("relay.converged", ownConverged)[0]
	if e["rc"] != "0" || e["rm"] != "0" || e["relay"] != "root" {
		t.Errorf("relay.converged of a node without child: want relay=root rc=0 rm=0, got %v", e)
	}
	if fo, cv := root.firstIndex("relay.failover", nil), root.firstIndex("relay.converged", nil); fo < 0 || fo >= cv {
		t.Errorf("relay.failover must precede relay.converged (%d, %d):\n%v", fo, cv, root.hookLines())
	}
	time.Sleep(settle)
	if got := len(root.eventsOf("relay.converged", ownConverged)); got != 1 {
		t.Errorf("%d relay.converged, want 1", got)
	}
}
