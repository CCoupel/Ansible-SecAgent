// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// T34 (#266, user rule): a relay only reports events for the hosts of its OWN subtree. For every host kind
// a child sends, a host routed through another peer or connected here is refused (neither dispatched nor
// forwarded), and so is a host this node has no route for — except host.discover (precedes host.up) and
// host.conflict (concerns relays below the child), which accept an unrouted host.
func TestSubtreeRule_EveryHostKindIsRefusedOutsideTheSubtree(t *testing.T) {
	r := newEventRig(t, map[string]string{"mine": "dmz1", "deep": "zone-a", "theirs": "relay-other", "unrouted": ""})
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"}, 1)
	t.Cleanup(func() { UnregisterConnection("local-host") })

	mk := func(kind, host string) RelayMessage {
		m := RelayMessage{Event: kind, Hostname: host, RelayChain: []string{"dmz1"}}
		switch kind {
		case "host.down":
			m.Status = "disconnected"
		case "host.suspended":
			m.Status = "suspended"
		case "host.resumed":
			m.Status = "resumed"
		case "host.discover":
			m.Detail = hooks.Detail{FirstSeenAt: "2026-11-12T10:00:00Z"}
		case "host.removed":
			m.Detail = hooks.Detail{Cause: "deleted"}
		case "host.conflict":
			m.OldRelay, m.NewRelay = "zone-a", "dmz1"
		case "host.rerouted":
			m.OldRelay, m.NewRelay = "dmz1", "zone-a"
			m.Detail = hooks.Detail{Cause: "moved", OldChain: []string{"dmz1"}, NewChain: []string{"zone-a"}}
			m.RelayChain = []string{"zone-a", "dmz1"}
		}
		return m
	}
	type tc struct {
		kind string
		// unroutedOK: an unrouted host is accepted for this kind
		unroutedOK bool
		// dispatched locally (host.conflict goes through its own path)
		local bool
	}
	kinds := []tc{{"host.down", false, true}, {"host.discover", true, true}, {"host.removed", false, true},
		{"host.suspended", false, false}, {"host.resumed", false, false}, {"host.conflict", true, false}, {"host.rerouted", false, true}}
	for _, k := range kinds {
		r.local.mu.Lock()
		r.local.got = nil
		r.local.mu.Unlock()
		before := r.upstreamCount()
		refused := []string{"theirs", "local-host"}
		if !k.unroutedOK {
			refused = append(refused, "unrouted")
		}
		for _, h := range refused {
			r.send(mk(k.kind, h))
		}
		r.ready()
		if got := r.local.list(); len(got) != 0 {
			t.Errorf("%s: dispatched for refused hosts: %+v", k.kind, got)
		}
		if n := r.upstreamCount() - before; n != 0 {
			t.Errorf("%s: %d refused event(s) forwarded", k.kind, n)
		}
		// accepted: own host and a declared descendant's host (host.rerouted also needs matching chains: own route)
		for _, h := range []string{"mine", "deep"} {
			m := mk(k.kind, h)
			if k.kind == "host.rerouted" {
				continue // its chains are validated by T16b; the ownership part is the refusals above
			}
			r.send(m)
		}
		if k.unroutedOK {
			r.send(mk(k.kind, "unrouted"))
		}
		r.ready()
		want := 2
		if k.unroutedOK {
			want = 3
		}
		if k.kind == "host.rerouted" {
			want = 0
		}
		if n := r.upstreamCount() - before; n != want {
			t.Errorf("%s: %d event(s) forwarded for in-subtree hosts, want %d", k.kind, n, want)
		}
	}
}

// Replayed (late) events follow the same rule: a late host.down for a host of another peer is refused.
func TestSubtreeRule_LateEventsFollowTheSameRule(t *testing.T) {
	r := newEventRig(t, map[string]string{"mine": "dmz1", "theirs": "relay-other"})
	r.send(RelayMessage{Event: "host.down", Hostname: "theirs", Status: "disconnected", RelayChain: []string{"dmz1"}, Late: true})
	r.send(RelayMessage{Event: "host.down", Hostname: "mine", Status: "disconnected", RelayChain: []string{"dmz1"}, Late: true})
	r.ready()
	got := r.local.list()
	if len(got) != 1 || got[0].Hostname != "mine" {
		t.Errorf("dispatched = %+v, want only the late host.down of the host of the sender", got)
	}
}

// The alarm level: another peer / local = [SECURITY WARNING]; no route known = [RELAY]; aggregated once a minute.
func TestSubtreeRule_AlarmLevelsAndAggregation(t *testing.T) {
	rerouteRefuseAgg.Flush() // forget what the other tests refused (the counters are global)
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	r := newEventRig(t, map[string]string{"theirs": "relay-other"})
	for i := 0; i < 4; i++ {
		r.send(RelayMessage{Event: "host.down", Hostname: "theirs", Status: "disconnected", RelayChain: []string{"dmz1"}})
	}
	for i := 0; i < 3; i++ {
		r.send(RelayMessage{Event: "host.removed", Hostname: "nowhere", RelayChain: []string{"dmz1"}, Detail: hooks.Detail{Cause: "deleted"}})
	}
	r.ready()
	rerouteRefuseAgg.Flush()
	logs := out.String()
	if !strings.Contains(logs, "[SECURITY WARNING] event refused (dmz1: host.down: is routed through another relay): 4 event(s)") {
		t.Errorf("no aggregated alarm for the host of another peer:\n%s", logs)
	}
	if !strings.Contains(logs, "[RELAY] event refused (dmz1: host.removed: has no route): 3 event(s)") {
		t.Errorf("no aggregated [RELAY] line for the unknown route:\n%s", logs)
	}
}

// The "first occurrence is logged at once" table is bounded and purged: once full of live keys, new keys are
// only aggregated (no log line per event), and it is usable again once its entries are older than a minute.
func TestImmediateRefusalLog_IsBoundedAndPurged(t *testing.T) {
	rerouteImmediateMu.Lock()
	saved := rerouteImmediate
	rerouteImmediate = map[string]time.Time{}
	rerouteImmediateMu.Unlock()
	t.Cleanup(func() { rerouteImmediateMu.Lock(); rerouteImmediate = saved; rerouteImmediateMu.Unlock() })

	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < maxImmediateKeys; i++ {
		if !immediateRefusalLog(fmt.Sprintf("k%d", i), t0) {
			t.Fatalf("key %d must be logged at once", i)
		}
	}
	if immediateRefusalLog("k0", t0.Add(time.Second)) {
		t.Error("the same key twice inside the minute must be aggregated")
	}
	// full of live keys: a NEW key is not logged at once, however many come (200/s flood)
	for i := 0; i < 5000; i++ {
		if immediateRefusalLog(fmt.Sprintf("flood%d", i), t0.Add(2*time.Second)) {
			t.Fatalf("flood key %d logged at once while the table is full of live keys", i)
		}
	}
	if n := len(rerouteImmediate); n > maxImmediateKeys {
		t.Errorf("table grew to %d entries, bound %d", n, maxImmediateKeys)
	}
	// a minute later the old entries are purged and new keys are logged at once again
	if !immediateRefusalLog("after-the-minute", t0.Add(rerouteRefuseInterval+time.Second)) {
		t.Error("after the minute the table must be purged and usable again")
	}
	if n := len(rerouteImmediate); n > 1 {
		t.Errorf("%d entries left after the purge, want 1", n)
	}
}
