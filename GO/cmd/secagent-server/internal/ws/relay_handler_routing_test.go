package ws

import (
	"sync"
	"testing"
	"time"
)

// ── host.conflict, event-driven routes and snapshot chains (#127) ────────────

type conflictLog struct {
	mu   sync.Mutex
	list []HostConflict
	from []bool
}

func (c *conflictLog) get() []HostConflict {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]HostConflict(nil), c.list...)
}

func recordConflicts(t *testing.T) *conflictLog {
	t.Helper()
	c := &conflictLog{}
	SetRelayConflictFunc(func(h HostConflict, fromBelow bool) {
		c.mu.Lock()
		c.list = append(c.list, h)
		c.from = append(c.from, fromBelow)
		c.mu.Unlock()
	})
	t.Cleanup(func() { SetRelayConflictFunc(nil) })
	return c
}

type routeLog struct {
	mu     sync.Mutex
	routes map[string]RouteChainEntry
}

func recordRoutes(t *testing.T) *routeLog {
	t.Helper()
	r := &routeLog{routes: map[string]RouteChainEntry{}}
	SetRelayRouteUpsertFunc(func(h, relayID string, chain []string) error {
		r.mu.Lock()
		r.routes[h] = RouteChainEntry{Hostname: h, RelayID: relayID, Chain: chain}
		r.mu.Unlock()
		return nil
	})
	SetRelayRouteChainsFunc(func(entries []RouteChainEntry) error {
		r.mu.Lock()
		for _, e := range entries {
			r.routes[e.Hostname] = e
		}
		r.mu.Unlock()
		return nil
	})
	t.Cleanup(func() { SetRelayRouteUpsertFunc(nil); SetRelayRouteChainsFunc(nil) })
	return r
}

func (r *routeLog) get(h string) (RouteChainEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.routes[h]
	return e, ok
}

func sendAgentList(t *testing.T, c interface{ WriteJSON(any) error }, hosts ...string) {
	t.Helper()
	var ag []RelayAgentInfo
	for _, h := range hosts {
		ag = append(ag, RelayAgentInfo{Hostname: h})
	}
	if err := c.WriteJSON(RelayMessage{Type: "agent_list", Agents: ag}); err != nil {
		t.Fatal(err)
	}
}

func TestRouting_AgentListMoveEmitsHostConflict(t *testing.T) {
	cl := recordConflicts(t)
	setHostRoutes(t, map[string]string{"moved": "relay-a", "stays": "relay-b", "fresh-never-routed": ""})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")

	sendAgentList(t, b, "moved", "stays", "fresh-never-routed")
	if m := readMsg(t, b); m.Type != "agent_list_ack" {
		t.Fatalf("got %+v", m)
	}
	got := cl.get()
	if len(got) != 1 {
		t.Fatalf("conflicts = %+v, want exactly one (moved): same next hop and new hosts must stay silent", got)
	}
	if got[0].Hostname != "moved" || got[0].OldRelay != "relay-a" || got[0].NewRelay != "relay-b" {
		t.Errorf("conflict = %+v", got[0])
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.from[0] {
		t.Error("a conflict detected here is not 'fromBelow'")
	}
}

func TestRouting_AgentListLastArrivalStillWins(t *testing.T) {
	recordConflicts(t)
	setHostRoutes(t, map[string]string{"moved": "relay-a"})
	var mu sync.Mutex
	routed := map[string][]string{}
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		mu.Lock()
		routed[relayID] = hostnames
		mu.Unlock()
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	sendAgentList(t, b, "moved")
	readMsg(t, b)
	mu.Lock()
	defer mu.Unlock()
	if len(routed["relay-b"]) != 1 || routed["relay-b"][0] != "moved" {
		t.Errorf("route not re-pointed to relay-b (last arrival wins): %v", routed)
	}
}

func TestRouting_AgentListReconnectSameNextHopIsSilent(t *testing.T) {
	cl := recordConflicts(t)
	setHostRoutes(t, map[string]string{"h": "relay-b", "deep": "zone-x"})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	// zone-x is a declared descendant of relay-b: its host becoming direct under relay-b is not a conflict
	sendSnapshot(t, b, []RelayTopoEntry{{RelayID: "zone-x", RelayChain: []string{"relay-b", "zone-x"}}}, nil)
	readMsg(t, b)
	sendAgentList(t, b, "h", "deep")
	readMsg(t, b)
	if got := cl.get(); len(got) != 0 {
		t.Errorf("unexpected conflicts: %+v", got)
	}
}

func TestRouting_AgentListClaimOnLocalAgentIsConflict(t *testing.T) {
	cl := recordConflicts(t)
	setTreeHooks(t, "central", nil, nil, nil)
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"})
	t.Cleanup(func() { UnregisterConnection("local-host") })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	sendAgentList(t, b, "local-host")
	readMsg(t, b)
	got := cl.get()
	if len(got) != 1 || got[0].OldRelay != LocalOwner || got[0].NewRelay != "relay-b" {
		t.Errorf("conflicts = %+v, want old=%q new=relay-b", got, LocalOwner)
	}
}

func TestRouting_SnapshotRecordsTopDownChains(t *testing.T) {
	rl := recordRoutes(t)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c,
		[]RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}},
		[]RelayAgentInfo{
			{Hostname: "host-A", RelayID: "dmz1", RelayChain: []string{"dmz1"}},
			{Hostname: "host-B", RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}},
		})
	if m := readMsg(t, c); m.Type != "topology_ack" {
		t.Fatalf("got %+v", m)
	}
	b, ok := rl.get("host-B")
	if !ok || b.RelayID != "zone-a" || len(b.Chain) != 2 || b.Chain[0] != "dmz1" {
		t.Errorf("host-B route = %+v (next hop must be dmz1, the direct child)", b)
	}
}

func TestRouting_EventHostUpRoutesThroughPeer(t *testing.T) {
	rl := recordRoutes(t)
	cl := recordConflicts(t)
	var regMu sync.Mutex
	var registered []string
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, func(id string) error {
		regMu.Lock()
		registered = append(registered, id)
		regMu.Unlock()
		return nil
	}, func(m RelayMessage) { events <- m })
	setHostRoutes(t, map[string]string{})
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, c)

	// event chain: origin first, authenticated peer last
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.new", Status: "connected", Hostname: "late", RelayChain: []string{"zone-a", "dmz1"}}); err != nil {
		t.Fatal(err)
	}
	<-events // forwarded upstream after the route was recorded
	r, ok := rl.get("late")
	if !ok || r.RelayID != "zone-a" || len(r.Chain) != 2 || r.Chain[0] != "dmz1" || r.Chain[1] != "zone-a" {
		t.Errorf("route = %+v, want declared by zone-a via dmz1", r)
	}
	if got := cl.get(); len(got) != 0 {
		t.Errorf("a new host is not a conflict: %+v", got)
	}

	// host.down must not touch the route
	rl.mu.Lock()
	delete(rl.routes, "late")
	rl.mu.Unlock()
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.down", Status: "disconnected", Hostname: "late", RelayChain: []string{"zone-a", "dmz1"}}); err != nil {
		t.Fatal(err)
	}
	<-events
	if _, ok := rl.get("late"); ok {
		t.Error("host.down must not (re)create a route")
	}
}

func TestRouting_EventHostUpMovingFromOtherRelayIsConflict(t *testing.T) {
	recordRoutes(t)
	cl := recordConflicts(t)
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { events <- m })
	setHostRoutes(t, map[string]string{"h": "relay-other"})
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Status: "connected", Hostname: "h", RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	<-events
	got := cl.get()
	if len(got) != 1 || got[0].OldRelay != "relay-other" || got[0].NewRelay != "dmz1" {
		t.Errorf("conflicts = %+v", got)
	}
}

func TestRouting_ConflictReportedBelowReachesHooksAndUpstream(t *testing.T) {
	cl := recordConflicts(t)
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { events <- m })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.conflict", Hostname: "h",
		OldRelay: "x", NewRelay: "dmz1", RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-events:
		if m.Event != "host.conflict" || m.OldRelay != "x" {
			t.Errorf("forwarded event = %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("host.conflict not forwarded upstream")
	}
	got := cl.get()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(got) != 1 || !cl.from[0] {
		t.Errorf("conflict = %+v fromBelow=%v, want one fromBelow=true (hooks only, no re-emission)", got, cl.from)
	}
}
