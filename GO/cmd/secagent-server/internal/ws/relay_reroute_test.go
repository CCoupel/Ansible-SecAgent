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
		lastRoutes, recentlyLocal = map[string]hostRoute{}, map[string]struct{}{}
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
		{"same relay, new path through another peer", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz2", []string{"dmz2"}, "moved", []string{"dmz1", "dmz2"}},
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
		"host: unknown host":              {host(func(m *RelayMessage) { m.Hostname = "never-seen" }), "without known route"},
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
	if n := strings.Count(out.String(), "re-route event refused"); n != 1 || !strings.Contains(out.String(), "5 event(s)") {
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
