// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"github.com/gorilla/websocket"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

func TestSnapshotDiff(t *testing.T) {
	t.Parallel()
	before := map[string][]string{
		"dmz1": {"dmz1"},
		"dmz2": {"dmz1", "dmz2"},
		"dmz3": {"dmz1", "dmz3"},
		"gone": {"dmz1", "gone"},
	}
	after := map[string][]string{
		"dmz1": {"dmz1"},                 // unchanged
		"dmz2": {"dmz2"},                 // descendant of dmz1 -> direct peer
		"dmz3": {"dmz1", "dmz2", "dmz3"}, // moved under dmz2
		"new":  {"dmz1", "new"},          // never seen: a first route is not a re-route
		"nil":  nil,                      // no chain declared: ignored
	}
	got := snapshotDiff(before, after)
	want := []chainMove{
		{RelayID: "dmz2", Old: []string{"dmz1", "dmz2"}, New: []string{"dmz2"}},
		{RelayID: "dmz3", Old: []string{"dmz1", "dmz3"}, New: []string{"dmz1", "dmz2", "dmz3"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("snapshotDiff = %+v, want %+v", got, want)
	}
	if got := snapshotDiff(nil, after); len(got) != 0 {
		t.Errorf("nothing known before: %+v, want no move (failover a->b)", got)
	}
	if got := snapshotDiff(before, before); len(got) != 0 {
		t.Errorf("identical tables: %+v", got)
	}
}

// resetRerouteMemory empties the process memories (they are global): a test starts from a fresh process.
func resetRerouteMemory(t *testing.T) {
	t.Helper()
	clear := func() {
		rerouteMemMu.Lock()
		lastRoutes, recentlyLocal, leftCarriers = map[string]hostRoute{}, map[string]struct{}{}, map[string]leftCarrier{}
		rerouteMemMu.Unlock()
		relayChainMemMu.Lock()
		lastRelayChains = map[string][]string{}
		relayChainMemMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

func TestNoteRoute(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	cases := []struct {
		name      string
		seed      *hostRoute // route known before (nil: first route)
		local     bool
		relay     string
		chain     []string
		wantCause string
		wantOld   []string
	}{
		{"first route", nil, false, "dmz2", []string{"dmz1", "dmz2"}, "", nil},
		{"same route", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz2", []string{"dmz1", "dmz2"}, "", nil},
		{"moved to another relay under another peer", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz3", []string{"dmz9", "dmz3"}, "moved", []string{"dmz1", "dmz2"}},
		{"moved inside the same peer's subtree: its own event is trusted", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz3", []string{"dmz1", "dmz3"}, "", nil},
		{"same carrier, only the path above it changed (reparent): relay.rerouted, no host event", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz2", []string{"dmz2"}, "", nil},
		{"same carrier, reparented the other way", &hostRoute{"dmz2", []string{"dmz2"}}, false, "dmz2", []string{"dmz1", "dmz2"}, "", nil},
		{"snapshot route without chain, same owner", &hostRoute{"dmz2", nil}, false, "dmz2", []string{"dmz1", "dmz2"}, "", nil},
		{"snapshot route without chain, other owner", &hostRoute{"dmz9", nil}, false, "dmz2", []string{"dmz1", "dmz2"}, "moved", []string{"dmz9"}},
		{"back from local", nil, true, "dmz1", []string{"dmz1"}, "indirect", []string{"central"}},
		{"back from local, stale route", &hostRoute{"dmz1", []string{"dmz1"}}, true, "dmz1", []string{"dmz1"}, "indirect", []string{"central"}},
	}
	for i, c := range cases {
		host := "reroute-case-" + string(rune('a'+i))
		if c.seed != nil {
			noteSnapshotRoute(host, c.seed.relayID, c.seed.chain)
		}
		if c.local {
			noteLocalDisconnect(host)
		}
		cause, old := noteRoute(host, c.relay, c.chain)
		if cause != c.wantCause || !reflect.DeepEqual(old, c.wantOld) {
			t.Errorf("%s: cause=%q old=%v, want %q %v", c.name, cause, old, c.wantCause, c.wantOld)
		}
		if cause2, _ := noteRoute(host, c.relay, c.chain); cause2 != "" { // the same arrival again: nothing
			t.Errorf("%s: second identical arrival gave %q", c.name, cause2)
		}
	}
}

// The route memory is not the store: a host whose relay stopped listing it is still remembered, so
// that its arrival behind another relay is a move, not a first route.
func TestNoteRoute_SurvivesTheRouteRemovalFromTheStore(t *testing.T) {
	if cause, _ := noteRoute("memo-host", "relayA", []string{"relayA"}); cause != "" {
		t.Fatalf("first route gave %q", cause)
	}
	// relayA's next agent_list drops the host (the store forgets it); nothing is noted here
	cause, old := noteRoute("memo-host", "relayB", []string{"relayB"})
	if cause != "moved" || !reflect.DeepEqual(old, []string{"relayA"}) {
		t.Errorf("cause=%q old=%v, want moved from relayA", cause, old)
	}
}

// A host with a remembered relay route that connects here: host.rerouted direct, once.
func TestNoteLocalConnect_DirectOnce(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	var mu sync.Mutex
	var got []hooks.Event
	SetEventFunc(func(ev hooks.Event) { mu.Lock(); got = append(got, ev); mu.Unlock() })
	t.Cleanup(func() { SetEventFunc(nil) })
	noteSnapshotRoute("direct-host", "dmz2", []string{"dmz1", "dmz2"})

	noteLocalConnect("direct-host")
	noteLocalConnect("direct-host") // the route is no longer remembered: nothing more
	noteLocalConnect("plain-host")  // never routed: nothing
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d events, want 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Name != "host.rerouted" || ev.Hostname != "direct-host" || ev.Detail.Cause != "direct" ||
		!reflect.DeepEqual(ev.Detail.OldChain, []string{"dmz1", "dmz2"}) || !reflect.DeepEqual(ev.Detail.NewChain, []string{"central"}) ||
		ev.Detail.OldRelay() != "dmz2" || ev.Detail.NewRelay() != "central" {
		t.Errorf("event = %+v", ev)
	}
}

func TestHostsThrough(t *testing.T) {
	got := hostsThrough([]RelayAgentInfo{
		{Hostname: "a", RelayChain: []string{"F", "r2", "r3"}},
		{Hostname: "b", RelayChain: []string{"F", "r2", "r3"}},
		{Hostname: "c", RelayChain: []string{"F", "r1"}},
	})
	if got["F"] != 3 || got["r2"] != 2 || got["r3"] != 2 || got["r1"] != 1 {
		t.Errorf("hostsThrough = %v", got)
	}
}

type recEvents struct {
	mu  sync.Mutex
	evs []hooks.Event
}

func (r *recEvents) add(ev hooks.Event) { r.mu.Lock(); r.evs = append(r.evs, ev); r.mu.Unlock() }
func (r *recEvents) named(n string) []hooks.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []hooks.Event
	for _, e := range r.evs {
		if e.Name == n {
			out = append(out, e)
		}
	}
	return out
}

func waitEvents(t *testing.T, r *recEvents, name string, n int) []hooks.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.named(name); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d %s event(s) expected, got %d", n, name, len(r.named(name)))
	return nil
}

// Reparent seen from the ancestor: ONE relay.rerouted per moved relay, hosts_routed from the snapshot,
// NO host.rerouted per host; the first snapshot gives none.
func TestSnapshot_ReparentGivesOneRelayRerouted(t *testing.T) {
	resetRerouteMemory(t)
	rec := &recEvents{}
	SetEventFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil) })
	var cmu sync.Mutex
	chains := map[string][]string{}
	SetRelayChainFunc(func(id string, c []string) error {
		cmu.Lock()
		defer cmu.Unlock()
		if len(c) == 0 {
			delete(chains, id)
		} else {
			chains[id] = append([]string(nil), c...)
		}
		return nil
	})
	SetRelayChainsFunc(func() map[string][]string {
		cmu.Lock()
		defer cmu.Unlock()
		out := map[string][]string{}
		for k, v := range chains {
			out[k] = v
		}
		return out
	})
	t.Cleanup(func() { SetRelayChainFunc(nil); SetRelayChainsFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	agents := func(relay string, chain []string, n int) []RelayAgentInfo {
		var out []RelayAgentInfo
		for i := 0; i < n; i++ {
			out = append(out, RelayAgentInfo{Hostname: relay + "-h" + string(rune('a'+i)), RelayID: relay, RelayChain: chain})
		}
		return out
	}
	sendSnapshot(t, c, []RelayTopoEntry{
		{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}},
		{RelayID: "zone-b", RelayChain: []string{"dmz1", "zone-b"}},
	}, append(agents("zone-a", []string{"dmz1", "zone-a"}, 3), agents("zone-b", []string{"dmz1", "zone-b"}, 1)...))
	readMsg(t, c)
	if n := len(rec.named("relay.rerouted")); n != 0 {
		t.Fatalf("first snapshot: %d relay.rerouted, want 0 (first route)", n)
	}
	// reparent: zone-a now hangs under zone-b
	sendSnapshot(t, c, []RelayTopoEntry{
		{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-b", "zone-a"}},
		{RelayID: "zone-b", RelayChain: []string{"dmz1", "zone-b"}},
	}, append(agents("zone-a", []string{"dmz1", "zone-b", "zone-a"}, 3), agents("zone-b", []string{"dmz1", "zone-b"}, 1)...))
	readMsg(t, c)
	got := waitEvents(t, rec, "relay.rerouted", 1)
	if len(got) != 1 {
		t.Fatalf("%d relay.rerouted, want exactly 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.RelayID != "zone-a" || ev.Detail.HostsRouted != 3 ||
		!reflect.DeepEqual(ev.Detail.OldChain, []string{"dmz1", "zone-a"}) ||
		!reflect.DeepEqual(ev.Detail.NewChain, []string{"dmz1", "zone-b", "zone-a"}) ||
		!reflect.DeepEqual(ev.RelayChain, []string{"zone-a", "zone-b", "dmz1"}) || ev.Hostname != "" {
		t.Errorf("relay.rerouted = %+v", ev)
	}
	if n := len(rec.named("host.rerouted")); n != 0 {
		t.Errorf("%d host.rerouted on a snapshot, want 0", n)
	}
	// identical snapshot again: nothing
	sendSnapshot(t, c, []RelayTopoEntry{
		{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-b", "zone-a"}},
		{RelayID: "zone-b", RelayChain: []string{"dmz1", "zone-b"}},
	}, nil)
	readMsg(t, c)
	if n := len(rec.named("relay.rerouted")); n != 1 {
		t.Errorf("%d relay.rerouted after an identical snapshot, want still 1", n)
	}
}

// host.up of a host that moved between two PEERS of this node: ONE host.rerouted moved with both chains;
// the first route gives none; an identical re-announcement gives none.
func TestEventForward_HostMovedGivesOneRerouted(t *testing.T) {
	resetRerouteMemory(t)
	rec := &recEvents{}
	SetEventFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	c1 := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c1, "dmz1")
	sendSnapshot(t, c1, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, c1)
	c2 := dialRelay(t, srv, makeRelayJWT("dmz2", "relay"))
	handshake(t, c2, "dmz2")
	sendSnapshot(t, c2, []RelayTopoEntry{{RelayID: "zone-b", RelayChain: []string{"dmz2", "zone-b"}}}, nil)
	readMsg(t, c2)
	up := func(c *websocket.Conn, origin, peer string) {
		t.Helper()
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "mover", Status: "connected",
			RelayChain: []string{origin, peer}}); err != nil {
			t.Fatal(err)
		}
	}
	up(c1, "zone-a", "dmz1") // first route
	up(c1, "zone-a", "dmz1") // same route
	_ = c1.WriteJSON(RelayMessage{Type: "heartbeat"})
	readMsg(t, c1)           // the two events above are processed before the next link speaks
	up(c2, "zone-b", "dmz2") // moved across peers
	waitEvents(t, rec, "host.rerouted", 1)
	time.Sleep(100 * time.Millisecond) // nothing else must follow
	got := rec.named("host.rerouted")
	if len(got) != 1 {
		t.Fatalf("%d host.rerouted, want exactly 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Hostname != "mover" || ev.Detail.Cause != "moved" ||
		!reflect.DeepEqual(ev.Detail.OldChain, []string{"dmz1", "zone-a"}) || !reflect.DeepEqual(ev.Detail.NewChain, []string{"dmz2", "zone-b"}) ||
		ev.Detail.OldRelay() != "zone-a" || ev.Detail.NewRelay() != "zone-b" ||
		!reflect.DeepEqual(ev.RelayChain, []string{"zone-b", "dmz2"}) {
		t.Errorf("host.rerouted = %+v", ev)
	}
}

// T16b: what a child may announce. Negative cases of reroutedRefusal.
func TestReroutedRefusal(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	conn := &RelayConnection{RelayID: "dmz1", descendants: map[string]struct{}{"zone-a": {}, "zone-b": {}}}
	noteSnapshotRoute("known-host", "zone-a", []string{"dmz1", "zone-a"})

	host := func(mut func(*RelayMessage)) RelayMessage {
		m := RelayMessage{Event: "host.rerouted", Hostname: "known-host", RelayChain: []string{"zone-b", "dmz1"},
			OldRelay: "zone-a", NewRelay: "zone-b",
			Detail: hooks.Detail{Cause: "moved", OldChain: []string{"dmz1", "zone-a"}, NewChain: []string{"dmz1", "zone-b"}}}
		if mut != nil {
			mut(&m)
		}
		return m
	}
	rel := func(mut func(*RelayMessage)) RelayMessage {
		m := RelayMessage{Event: "relay.rerouted", RelayID: "zone-b", RelayChain: []string{"zone-b", "dmz1"},
			Detail: hooks.Detail{OldChain: []string{"dmz1", "zone-a", "zone-b"}, NewChain: []string{"dmz1", "zone-b"}, HostsRouted: 2}}
		if mut != nil {
			mut(&m)
		}
		return m
	}
	for name, c := range map[string]struct {
		m    RelayMessage
		want string
	}{
		"host ok":                         {host(nil), ""},
		"relay ok":                        {rel(nil), ""},
		"relay: new_chain not reversed":   {rel(func(m *RelayMessage) { m.NewChain = []string{"dmz1", "zone-a"} }), "reverse"},
		"relay: chain shorter":            {rel(func(m *RelayMessage) { m.NewChain = []string{"zone-b"} }), "reverse"},
		"host: element outside subtree":   {host(func(m *RelayMessage) { m.OldChain = []string{"dmz1", "elsewhere"}; m.OldRelay = "elsewhere" }), "outside"},
		"relay: element outside subtree":  {rel(func(m *RelayMessage) { m.OldChain = []string{"dmz1", "ghost", "zone-b"} }), "outside"},
		"host: unknown host":              {host(func(m *RelayMessage) { m.Hostname = "never-seen" }), "has no route"},
		"host: old_relay forged":          {host(func(m *RelayMessage) { m.OldRelay = "zone-b" }), "differ"},
		"host: new_relay forged":          {host(func(m *RelayMessage) { m.NewRelay = "dmz1" }), "differ"},
		"host: relays absent, chains set": {host(func(m *RelayMessage) { m.OldRelay, m.NewRelay = "", "" }), "differ"},
	} {
		if got := reroutedRefusal(conn, c.m); (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("%s: refusal %q, want %q", name, got, c.want)
		}
	}
}

// A refused re-route is neither dispatched nor forwarded, and logged once per period (aggregated).
func TestReroutedRefusal_IsAggregatedAndDropsTheEvent(t *testing.T) {
	rec := &recEvents{}
	SetEventFunc(rec.add)
	SetRelayEventLocalFunc(func(ev hooks.Event) { rec.add(ev) })
	t.Cleanup(func() { SetEventFunc(nil); SetRelayEventLocalFunc(nil) })
	var fwd sync.Mutex
	forwarded := 0
	setTreeHooks(t, "central", nil, nil, func(RelayMessage) { fwd.Lock(); forwarded++; fwd.Unlock() })
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, c)
	for i := 0; i < 5; i++ {
		_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.rerouted", Hostname: "invented", Status: "",
			RelayChain: []string{"zone-a", "dmz1"}, OldRelay: "zone-a", NewRelay: "zone-a",
			Detail: hooks.Detail{Cause: "moved", OldChain: []string{"dmz1", "zone-a"}, NewChain: []string{"dmz1", "zone-a"}}})
	}
	_ = c.WriteJSON(RelayMessage{Type: "heartbeat"})
	readMsg(t, c)
	if n := len(rec.named("host.rerouted")); n != 0 {
		t.Errorf("%d refused host.rerouted dispatched", n)
	}
	fwd.Lock()
	if forwarded != 0 {
		t.Errorf("%d refused events forwarded upstream", forwarded)
	}
	fwd.Unlock()
	rerouteRefuseAgg.Flush()
	if n := strings.Count(out.String(), "host.rerouted: has no route): 5 event(s)"); n != 1 {
		t.Errorf("want ONE aggregated line for 5 refusals:\n%s", out.String())
	}
}

// MAJEUR-1: one host.rerouted per change along the tree. Same direct peer on both routes: the change
// happened below it, its own event is trusted; different peers: this node is the common ancestor.
func TestNoteRoute_OneEventPerChangeAlongTheTree(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	noteSnapshotRoute("deep-1", "g1", []string{"P", "g1"})
	if cause, _ := noteRoute("deep-1", "g2", []string{"P", "g2"}); cause != "" {
		t.Errorf("move inside the subtree of P: cause %q, want none (P forwards its own host.rerouted)", cause)
	}
	// the memory was updated anyway
	if cause, _ := noteRoute("deep-1", "g2", []string{"P", "g2"}); cause != "" {
		t.Errorf("same route again: %q", cause)
	}
	noteSnapshotRoute("deep-2", "g1", []string{"P", "g1"})
	cause, old := noteRoute("deep-2", "h1", []string{"Q", "h1"})
	if cause != "moved" || !reflect.DeepEqual(old, []string{"P", "g1"}) {
		t.Errorf("move across two peers: cause=%q old=%v, want moved from [P g1]", cause, old)
	}
	// direct: from a grandchild to the peer itself (same first hop)
	noteSnapshotRoute("deep-3", "g1", []string{"P", "g1"})
	if cause, _ := noteRoute("deep-3", "P", []string{"P"}); cause != "" {
		t.Errorf("grandchild -> child: cause %q, want none (P emits direct)", cause)
	}
}

// Three levels at the intermediate node A: the host moves inside P's subtree. A receives host.up AND the
// host.rerouted P forwards: exactly ONE host.rerouted is dispatched at A, and ONE goes up.
func TestIntermediateNode_NoDuplicateHostRerouted(t *testing.T) {
	resetRerouteMemory(t)
	rec := &recEvents{}
	SetEventFunc(rec.add)
	SetRelayEventLocalFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil); SetRelayEventLocalFunc(nil) })
	var umu sync.Mutex
	up := 0
	setTreeHooks(t, "A", nil, nil, func(m RelayMessage) {
		if m.Event == "host.rerouted" {
			umu.Lock()
			up++
			umu.Unlock()
		}
	})
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("P", "relay"))
	handshake(t, c, "P")
	sendSnapshot(t, c, []RelayTopoEntry{
		{RelayID: "g1", RelayChain: []string{"P", "g1"}}, {RelayID: "g2", RelayChain: []string{"P", "g2"}},
	}, []RelayAgentInfo{{Hostname: "mover3", RelayID: "g1", RelayChain: []string{"P", "g1"}}})
	readMsg(t, c)
	// the host comes up behind g2 (moved inside P's subtree): host.up, then P's own host.rerouted
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "mover3", Status: "connected", RelayChain: []string{"g2", "P"}})
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.rerouted", Hostname: "mover3", RelayChain: []string{"g2", "P"},
		OldRelay: "g1", NewRelay: "g2", Detail: hooks.Detail{Cause: "moved", OldChain: []string{"P", "g1"}, NewChain: []string{"P", "g2"}}})
	_ = c.WriteJSON(RelayMessage{Type: "heartbeat"})
	readMsg(t, c)
	time.Sleep(100 * time.Millisecond)
	if n := len(rec.named("host.rerouted")); n != 1 {
		t.Errorf("%d host.rerouted dispatched at the intermediate node, want exactly 1", n)
	}
	umu.Lock()
	defer umu.Unlock()
	if up != 1 {
		t.Errorf("%d host.rerouted forwarded upstream, want exactly 1", up)
	}
}

// MAJEUR-2: a real reparent gives exactly ONE relay.rerouted whatever the order the two parents speak in.
// relayLink is a test child link.
type relayLink struct {
	t *testing.T
	c *websocket.Conn
}

func (l *relayLink) snapshot(relays []RelayTopoEntry, agents []RelayAgentInfo) {
	l.t.Helper()
	sendSnapshot(l.t, l.c, relays, agents)
	readMsg(l.t, l.c)
}

func reparentRig(t *testing.T) (*recEvents, func(id string) *relayLink) {
	t.Helper()
	rec := &recEvents{}
	SetEventFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil) })
	var cmu sync.Mutex
	chains := map[string][]string{}
	SetRelayChainFunc(func(id string, c []string) error {
		cmu.Lock()
		defer cmu.Unlock()
		if len(c) == 0 {
			delete(chains, id)
		} else {
			chains[id] = append([]string(nil), c...)
		}
		return nil
	})
	SetRelayChainsFunc(func() map[string][]string {
		cmu.Lock()
		defer cmu.Unlock()
		out := map[string][]string{}
		for k, v := range chains {
			out[k] = v
		}
		return out
	})
	t.Cleanup(func() { SetRelayChainFunc(nil); SetRelayChainsFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	t.Cleanup(srv.Close)
	return rec, func(id string) *relayLink {
		c := dialRelay(t, srv, makeRelayJWT(id, "relay"))
		handshake(t, c, id)
		return &relayLink{t, c}
	}
}

func TestReparent_OneRelayReroutedWhicheverOrder(t *testing.T) {
	resetRerouteMemory(t)
	for _, tc := range []struct {
		name      string
		oldFirst  bool
		moved     string
		oldParent string
	}{{"old parent retires first", true, "mv-a", "op-a"}, {"new link first", false, "mv-b", "op-b"}} {
		t.Run(tc.name, func(t *testing.T) {
			rec, dial := reparentRig(t)
			old := dial(tc.oldParent)
			old.snapshot([]RelayTopoEntry{{RelayID: tc.moved, RelayChain: []string{tc.oldParent, tc.moved}}}, nil)
			if n := len(rec.named("relay.rerouted")); n != 0 {
				t.Fatalf("first declaration: %d relay.rerouted", n)
			}
			if tc.oldFirst {
				old.snapshot(nil, nil) // the old parent retires the relay
				nw := dial(tc.moved)
				nw.snapshot(nil, nil) // the relay now connects directly
			} else {
				nw := dial(tc.moved)
				nw.snapshot(nil, nil)
				old.snapshot(nil, nil) // the old parent retires it afterwards
			}
			waitEvents(t, rec, "relay.rerouted", 1)
			time.Sleep(150 * time.Millisecond)
			got := rec.named("relay.rerouted")
			if len(got) != 1 {
				t.Fatalf("%d relay.rerouted, want exactly 1: %+v", len(got), got)
			}
			if got[0].RelayID != tc.moved || !reflect.DeepEqual(got[0].Detail.OldChain, []string{tc.oldParent, tc.moved}) ||
				!reflect.DeepEqual(got[0].Detail.NewChain, []string{tc.moved}) {
				t.Errorf("relay.rerouted = %+v", got[0])
			}
		})
	}
}

// T24: a replayed (late) host.up is history. It never rewrites a route nor raises a conflict; it is
// kept for the hooks when the host is still the sender's, refused when someone else owns it now.
func TestLateHostUp_IsHistoryOnly(t *testing.T) {
	resetRerouteMemory(t)
	rec := &recEvents{}
	SetEventFunc(rec.add)
	SetRelayEventLocalFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil); SetRelayEventLocalFunc(nil) })
	var mu sync.Mutex
	upserts := 0
	SetRelayRouteUpsertFunc(func(string, string, []string) error { mu.Lock(); upserts++; mu.Unlock(); return nil })
	SetRelayHostRouteFunc(func(h string) (string, error) {
		if h == "owned-elsewhere" {
			return "dmz2", nil
		}
		return "", nil
	})
	var conflicts int
	SetRelayConflictFunc(func(HostConflict, bool) { mu.Lock(); conflicts++; mu.Unlock() })
	t.Cleanup(func() { SetRelayRouteUpsertFunc(nil); SetRelayHostRouteFunc(nil); SetRelayConflictFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, nil, nil)
	readMsg(t, c)
	late := func(h string) {
		_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: h, Status: "connected", RelayChain: []string{"dmz1"},
			Timestamp: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), Late: true})
	}
	late("still-mine")
	late("owned-elsewhere")
	_ = c.WriteJSON(RelayMessage{Type: "heartbeat"})
	readMsg(t, c)
	time.Sleep(100 * time.Millisecond)
	got := rec.named("host.up")
	if len(got) != 1 || got[0].Hostname != "still-mine" {
		t.Errorf("host.up dispatched = %+v, want only still-mine", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if upserts != 0 {
		t.Errorf("%d route upserts for late events, want 0", upserts)
	}
	if conflicts != 0 || len(rec.named("host.rerouted")) != 0 {
		t.Errorf("late events raised %d conflicts / %d host.rerouted, want 0 / 0", conflicts, len(rec.named("host.rerouted")))
	}
}

// #266: host.discover is emitted at the FIRST handshake, BEFORE host.up, once; never on a reconnection.
func TestRegisterConnection_DiscoverBeforeUpOnlyOnce(t *testing.T) {
	resetState()
	rec := &recEvents{}
	SetEventFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil); SetFirstSeenFunc(nil) })
	seen := map[string]bool{}
	var mu sync.Mutex
	SetFirstSeenFunc(func(h string) (bool, time.Time, time.Time) {
		mu.Lock()
		defer mu.Unlock()
		if seen[h] {
			return false, time.Time{}, time.Time{}
		}
		seen[h] = true
		return true, time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	})
	RegisterConnection("disc-host", &AgentConnection{Hostname: "disc-host"}, 1)
	UnregisterConnection("disc-host")
	RegisterConnection("disc-host", &AgentConnection{Hostname: "disc-host"}, 2) // same process: host.reconnect
	UnregisterConnection("disc-host")
	rec.mu.Lock()
	var names []string
	for _, e := range rec.evs {
		names = append(names, e.Name)
	}
	first := rec.evs[0]
	rec.mu.Unlock()
	want := []string{"host.discover", "host.up", "host.down", "host.reconnect", "host.down"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("events = %v, want %v", names, want)
	}
	if first.Hostname != "disc-host" || first.Detail.FirstSeenAt != "2026-11-12T10:00:00Z" || first.EnrolledAt != "2026-11-01T09:00:00Z" {
		t.Errorf("host.discover = %+v", first)
	}
}

// #266: relay.discover at the FIRST snapshot of a declared relay, before relay.up; once; a replacing
// snapshot or a relay the store does not know gives nothing.
func TestRelayDiscover_BeforeUpOnlyOnceForADeclaredRelay(t *testing.T) {
	resetRerouteMemory(t)
	rec := &recEvents{}
	SetEventFunc(rec.add)
	var mu sync.Mutex
	declared := map[string]bool{"decl-relay": true}
	SetRelayFirstSeenFunc(func(id string) (bool, time.Time) {
		mu.Lock()
		defer mu.Unlock()
		if declared[id] {
			declared[id] = false
			return true, time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
		}
		return false, time.Time{}
	})
	t.Cleanup(func() { SetEventFunc(nil); SetRelayFirstSeenFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	c := dialRelay(t, srv, makeRelayJWT("decl-relay", "relay"))
	handshake(t, c, "decl-relay")
	sendSnapshot(t, c, nil, []RelayAgentInfo{{Hostname: "a1", RelayID: "decl-relay", RelayChain: []string{"decl-relay"}}})
	readMsg(t, c)
	sendSnapshot(t, c, nil, nil) // replacing snapshot: nothing
	readMsg(t, c)
	_ = c.Close()
	c2 := dialRelay(t, srv, makeRelayJWT("decl-relay", "relay")) // a reconnection: nothing
	handshake(t, c2, "decl-relay")
	sendSnapshot(t, c2, nil, nil)
	readMsg(t, c2)
	c3 := dialRelay(t, srv, makeRelayJWT("undeclared", "relay")) // not declared on this node: nothing
	handshake(t, c3, "undeclared")
	sendSnapshot(t, c3, nil, nil)
	readMsg(t, c3)
	time.Sleep(100 * time.Millisecond)

	rec.mu.Lock()
	var names []string
	var disc hooks.Event
	for _, e := range rec.evs {
		if e.RelayID == "decl-relay" || e.RelayID == "undeclared" {
			names = append(names, e.RelayID+":"+e.Name)
			if e.Name == "relay.discover" {
				disc = e
			}
		}
	}
	rec.mu.Unlock()
	if len(names) < 2 || names[0] != "decl-relay:relay.discover" || names[1] != "decl-relay:relay.up" {
		t.Fatalf("events = %v, want relay.discover then relay.up first", names)
	}
	n := 0
	for _, nm := range names {
		if nm == "decl-relay:relay.discover" || nm == "undeclared:relay.discover" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d relay.discover, want exactly 1: %v", n, names)
	}
	if disc.Detail.FirstSeenAt != "2026-11-12T10:00:00Z" || disc.Detail.HostsRouted != 1 || disc.Detail.Mode != "push" && disc.Detail.Mode != "pull" {
		t.Errorf("relay.discover = %+v", disc)
	}
}

// Q3 (#266): a replayed (late) event keeps its ORIGIN timestamp end to end: the hooks of the receiving node
// run with it, a malformed one is ignored.
func TestHookEvent_CarriesTheOriginTimestamp(t *testing.T) {
	m := RelayMessage{Event: "host.discover", Hostname: "h", RelayChain: []string{"dmz1"}, Timestamp: "2026-11-12T13:36:37+01:00", Late: true}
	if got := m.hookEvent().Timestamp; got != "2026-11-12T12:36:37Z" {
		t.Errorf("timestamp = %q, want the origin date normalized to UTC", got)
	}
	m.Timestamp = "yesterday\n{{secret}}"
	if got := m.hookEvent().Timestamp; got != "" {
		t.Errorf("a malformed timestamp must be ignored, got %q", got)
	}
	m.Timestamp = ""
	if got := m.hookEvent().Timestamp; got != "" {
		t.Errorf("no timestamp: got %q", got)
	}
}

func TestOriginTimestamp_Bounds(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	f := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, c := range []struct {
		name string
		ts   string
		late bool
		ok   bool
	}{
		{"now", f(0), false, true},
		{"4 min in the future (skew)", f(4 * time.Minute), false, true},
		{"6 min in the future", f(6 * time.Minute), false, false},
		{"6 min in the future, late", f(6 * time.Minute), true, false},
		{"6 days old", f(-6 * 24 * time.Hour), false, true},
		{"8 days old, live event", f(-8 * 24 * time.Hour), false, false},
		{"8 days old, replayed (late)", f(-8 * 24 * time.Hour), true, true},
		{"year 1970", "1970-01-01T00:00:00Z", false, false},
		{"malformed", "yesterday", false, false},
		{"empty", "", false, false},
	} {
		if _, ok := originTimestamp(c.ts, c.late, now); ok != c.ok {
			t.Errorf("%s: usable = %v, want %v", c.name, ok, c.ok)
		}
	}
}

// An out-of-bounds timestamp is replaced by the arrival time (hookEvent leaves it empty) and counted/logged.
func TestHookEvent_ClampsAnOutOfBoundsTimestamp(t *testing.T) {
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	timestampClampAgg.Flush()
	m := RelayMessage{Event: "host.down", Hostname: "h", RelayChain: []string{"dmz1"}, Timestamp: "2999-01-01T00:00:00Z"}
	if got := m.hookEvent().Timestamp; got != "" {
		t.Errorf("a far-future timestamp must be dropped, got %q", got)
	}
	timestampClampAgg.Flush()
	if !strings.Contains(out.String(), "host.down: 1 event(s) in the last minute had a timestamp out of bounds") {
		t.Errorf("no log:\n%s", out.String())
	}
}

// An agent_list REPLACES the routes of its relay; one built BEFORE a host.up it overtakes (here: empty, sent right
// after the event) must not wipe the route that event just created: it is completed with the hosts routed by an
// event less than the grace ago, and only after the grace is the host dropped if still unlisted.
func TestAgentList_DoesNotWipeARouteCreatedByARecentEvent(t *testing.T) {
	resetRerouteMemory(t)
	prev := recentEventRouteGrace
	recentEventRouteGrace = 400 * time.Millisecond
	t.Cleanup(func() { recentEventRouteGrace = prev })
	recentRoutesMu.Lock()
	recentEventRoutes = nil
	recentRoutesMu.Unlock()

	var mu sync.Mutex
	var lists [][]string
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if relayID == "dmz1" {
			mu.Lock()
			lists = append(lists, append([]string(nil), hostnames...))
			mu.Unlock()
		}
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, nil, nil)
	readMsg(t, c)
	last := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return lists[len(lists)-1]
	}
	agentList := func(hosts ...string) {
		t.Helper()
		var ag []RelayAgentInfo
		for _, h := range hosts {
			ag = append(ag, RelayAgentInfo{Hostname: h, Status: "connected"})
		}
		if err := c.WriteJSON(RelayMessage{Type: "agent_list", Agents: ag}); err != nil {
			t.Fatal(err)
		}
		readMsg(t, c) // agent_list_ack: processed
	}

	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.new", Hostname: "fresh", Status: "disconnected", RelayChain: []string{"dmz1"}})
	agentList() // stale: built before the agent connected
	if got := last(); len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("the stale empty agent_list wiped the route of the host an event had just routed: %v", got)
	}
	agentList("fresh", "other") // the truth, now complete
	if got := last(); len(got) != 2 {
		t.Errorf("a complete list must stay as it is: %v", got)
	}
	agentList("fresh", "other")
	time.Sleep(600 * time.Millisecond) // past the grace
	agentList()
	if got := last(); len(got) != 0 {
		t.Errorf("after the grace an unlisted host must be dropped again: %v", got)
	}
	// QUIET relay: no further list comes after a kept route; the grace itself must drop it (not the list interval)
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "quiet", Status: "connected", RelayChain: []string{"dmz1"}})
	agentList() // stale: keeps "quiet"
	if got := last(); len(got) != 1 || got[0] != "quiet" {
		t.Fatalf("kept route missing: %v", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := last(); len(got) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("a kept route outlived the grace although no further agent_list came: %v", last())
}

// A host reported DOWN by its relay is no longer protected: the kept route goes at once (a host that moves to
// another relay right after must not be taken for a conflict).
func TestAgentList_HostDownEndsTheProtection(t *testing.T) {
	resetRerouteMemory(t)
	prev := recentEventRouteGrace
	recentEventRouteGrace = 5 * time.Second // long: only the host.down can end it
	t.Cleanup(func() { recentEventRouteGrace = prev })
	recentRoutesMu.Lock()
	recentEventRoutes = nil
	recentRoutesMu.Unlock()
	var mu sync.Mutex
	var lists [][]string
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if relayID == "dmz1" {
			mu.Lock()
			lists = append(lists, append([]string(nil), hostnames...))
			mu.Unlock()
		}
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, nil, nil)
	readMsg(t, c)
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "leaving", Status: "connected", RelayChain: []string{"dmz1"}})
	_ = c.WriteJSON(RelayMessage{Type: "agent_list", Agents: nil})
	readMsg(t, c)
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.down", Hostname: "leaving", Status: "disconnected", RelayChain: []string{"dmz1"}})
	_ = c.WriteJSON(RelayMessage{Type: "heartbeat"})
	readMsg(t, c)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n := len(lists); n < 2 || len(lists[n-1]) != 0 {
		t.Errorf("lists = %v, want the kept route dropped as soon as the host.down arrived", lists)
	}
}
