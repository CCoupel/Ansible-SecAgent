// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"reflect"
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
		{"moved to another relay", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz3", []string{"dmz1", "dmz3"}, "moved", []string{"dmz1", "dmz2"}},
		{"same relay, new path", &hostRoute{"dmz2", []string{"dmz1", "dmz2"}}, false, "dmz2", []string{"dmz2"}, "moved", []string{"dmz1", "dmz2"}},
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

// host.up of a host that moved from one relay to another: ONE host.rerouted moved with both chains;
// the first route gives none; an identical re-announcement gives none.
func TestEventForward_HostMovedGivesOneRerouted(t *testing.T) {
	rec := &recEvents{}
	SetEventFunc(rec.add)
	t.Cleanup(func() { SetEventFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, []RelayTopoEntry{
		{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}},
		{RelayID: "zone-b", RelayChain: []string{"dmz1", "zone-b"}},
	}, nil)
	readMsg(t, c)
	up := func(origin string) {
		t.Helper()
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "mover", Status: "connected",
			RelayChain: []string{origin, "dmz1"}}); err != nil {
			t.Fatal(err)
		}
	}
	up("zone-a") // first route
	up("zone-a") // same route
	up("zone-b") // moved
	waitEvents(t, rec, "host.rerouted", 1)
	time.Sleep(100 * time.Millisecond) // nothing else must follow
	got := rec.named("host.rerouted")
	if len(got) != 1 {
		t.Fatalf("%d host.rerouted, want exactly 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Hostname != "mover" || ev.Detail.Cause != "moved" ||
		!reflect.DeepEqual(ev.Detail.OldChain, []string{"dmz1", "zone-a"}) || !reflect.DeepEqual(ev.Detail.NewChain, []string{"dmz1", "zone-b"}) ||
		ev.Detail.OldRelay() != "zone-a" || ev.Detail.NewRelay() != "zone-b" ||
		!reflect.DeepEqual(ev.RelayChain, []string{"zone-b", "dmz1"}) {
		t.Errorf("host.rerouted = %+v", ev)
	}
}
