package ws

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// ── event_forward: local dispatch, validation and subtree rules (#126) ───────

type localEvent struct {
	Event, Hostname, Status, EnrolledAt string
	Chain                               []string
}

type localSink struct {
	mu  sync.Mutex
	got []localEvent
}

func (s *localSink) list() []localEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]localEvent(nil), s.got...)
}

func recordLocalEvents(t *testing.T) *localSink {
	t.Helper()
	s := &localSink{}
	SetRelayEventLocalFunc(func(event, hostname, status, enrolledAt string, chain []string) {
		s.mu.Lock()
		s.got = append(s.got, localEvent{event, hostname, status, enrolledAt, chain})
		s.mu.Unlock()
	})
	t.Cleanup(func() { SetRelayEventLocalFunc(nil) })
	return s
}

type eventRig struct {
	t        *testing.T
	c        interface{ WriteJSON(any) error }
	local    *localSink
	upstream chan RelayMessage
	ready    func()
}

// newEventRig connects relay dmz1 (with a declared descendant zone-a) to a root node.
func newEventRig(t *testing.T, routes map[string]string) *eventRig {
	t.Helper()
	recordRoutes(t)
	recordConflicts(t)
	r := &eventRig{t: t, local: recordLocalEvents(t), upstream: make(chan RelayMessage, 32)}
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { r.upstream <- m })
	setHostRoutes(t, routes)
	srv := setupRelayTestServer(t)
	t.Cleanup(srv.Close)
	conn := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, conn, "dmz1")
	sendSnapshot(t, conn, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, conn)
	r.c = conn
	r.ready = func() { // barrier: all messages sent before were processed
		if err := conn.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
			t.Fatal(err)
		}
		readMsg(t, conn)
	}
	return r
}

func (r *eventRig) send(m RelayMessage) {
	r.t.Helper()
	m.Type = "event_forward"
	if err := r.c.WriteJSON(m); err != nil {
		r.t.Fatal(err)
	}
}

func (r *eventRig) upstreamCount() int { return len(r.upstream) }

func TestEvents_ValidatedEventIsDispatchedLocallyWithItsChainThenForwarded(t *testing.T) {
	r := newEventRig(t, map[string]string{})
	r.send(RelayMessage{Event: "host.up", Hostname: "host-A", Status: "connected", RelayChain: []string{"dmz1"}})                                         // 1 hop
	r.send(RelayMessage{Event: "host.down", Hostname: "host-B", Status: "disconnected", RelayChain: []string{"zone-a", "dmz1"}})                          // 2 hops
	r.send(RelayMessage{Event: "host.new", Hostname: "host-C", Status: "disconnected", EnrolledAt: "2026-10-05T09:00:00Z", RelayChain: []string{"dmz1"}}) // enrollment
	r.ready()

	got := r.local.list()
	if len(got) != 3 {
		t.Fatalf("local dispatches = %+v, want 3", got)
	}
	if got[0].Event != "host.up" || got[0].Hostname != "host-A" || strings.Join(got[0].Chain, ",") != "dmz1" {
		t.Errorf("1 hop: %+v", got[0])
	}
	if got[1].Event != "host.down" || strings.Join(got[1].Chain, ",") != "zone-a,dmz1" {
		t.Errorf("2 hops: the chain must be passed as received (origin first): %+v", got[1])
	}
	if got[2].Event != "host.new" || got[2].EnrolledAt != "2026-10-05T09:00:00Z" {
		t.Errorf("host.new: %+v", got[2])
	}
	if r.upstreamCount() != 3 {
		t.Errorf("forwarded %d events upstream, want 3", r.upstreamCount())
	}
}

func TestEvents_RejectedEventsAreNeitherDispatchedNorForwarded(t *testing.T) {
	r := newEventRig(t, map[string]string{})
	long := strings.Repeat("a", 300)
	bad := map[string]RelayMessage{
		"unsupported kind":           {Event: "host.revoked", Hostname: "h", Status: "connected", RelayChain: []string{"dmz1"}},
		"relay.up is not supported":  {Event: "relay.up", Hostname: "h", Status: "connected", RelayChain: []string{"dmz1"}},
		"empty hostname":             {Event: "host.up", Hostname: "", Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname with a space":      {Event: "host.up", Hostname: "my host", Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname with a newline":    {Event: "host.up", Hostname: "h\nx", Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname with shell chars":  {Event: "host.up", Hostname: "h;rm -rf /", Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname with a quote":      {Event: "host.up", Hostname: `h"$(id)`, Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname too long":          {Event: "host.up", Hostname: long, Status: "connected", RelayChain: []string{"dmz1"}},
		"hostname starting with dot": {Event: "host.up", Hostname: ".hidden", Status: "connected", RelayChain: []string{"dmz1"}},
		"missing status":             {Event: "host.up", Hostname: "h", RelayChain: []string{"dmz1"}},
		"unknown status":             {Event: "host.up", Hostname: "h", Status: "exploded", RelayChain: []string{"dmz1"}},
		"enrolled_at on host.up":     {Event: "host.up", Hostname: "h", Status: "connected", EnrolledAt: "2026-10-05T09:00:00Z", RelayChain: []string{"dmz1"}},
		"malformed enrolled_at":      {Event: "host.new", Hostname: "h", Status: "disconnected", EnrolledAt: "yesterday\n", RelayChain: []string{"dmz1"}},
		"conflict with bad relay id": {Event: "host.conflict", Hostname: "h", OldRelay: "a b", NewRelay: "dmz1", RelayChain: []string{"dmz1"}},
		"wrong sender in the chain":  {Event: "host.up", Hostname: "h", Status: "connected", RelayChain: []string{"zone-a"}},
		"undeclared relay in chain":  {Event: "host.up", Hostname: "h", Status: "connected", RelayChain: []string{"ghost", "dmz1"}},
	}
	for _, m := range bad {
		r.send(m)
	}
	r.ready()
	if got := r.local.list(); len(got) != 0 {
		t.Errorf("rejected events were dispatched locally: %+v", got)
	}
	if r.upstreamCount() != 0 {
		t.Errorf("rejected events were forwarded upstream (%d)", r.upstreamCount())
	}
}

// A child can only report the going down of a host of its own subtree.
func TestEvents_HostDownOutsideTheSenderSubtreeIsDropped(t *testing.T) {
	r := newEventRig(t, map[string]string{"mine": "dmz1", "deep": "zone-a", "theirs": "relay-other", "unrouted": ""})
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"})
	t.Cleanup(func() { UnregisterConnection("local-host") })

	for _, h := range []string{"mine", "deep", "unrouted"} { // allowed: own host, declared descendant's host, unknown host
		r.send(RelayMessage{Event: "host.down", Hostname: h, Status: "disconnected", RelayChain: []string{"dmz1"}})
	}
	r.send(RelayMessage{Event: "host.down", Hostname: "theirs", Status: "disconnected", RelayChain: []string{"dmz1"}})     // routed through another relay
	r.send(RelayMessage{Event: "host.down", Hostname: "local-host", Status: "disconnected", RelayChain: []string{"dmz1"}}) // connected here
	r.ready()

	var names []string
	for _, e := range r.local.list() {
		names = append(names, e.Hostname)
	}
	if strings.Join(names, ",") != "mine,deep,unrouted" {
		t.Errorf("dispatched host.down for %v, want mine,deep,unrouted only", names)
	}
	if r.upstreamCount() != 3 {
		t.Errorf("forwarded %d, want 3", r.upstreamCount())
	}
}

// A child claiming host.up for a host connected here neither gets a route nor is announced.
func TestEvents_HostUpForALocalAgentIsNotDispatchedNorForwarded(t *testing.T) {
	r := newEventRig(t, map[string]string{})
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"})
	t.Cleanup(func() { UnregisterConnection("local-host") })
	r.send(RelayMessage{Event: "host.up", Hostname: "local-host", Status: "connected", RelayChain: []string{"dmz1"}})
	r.ready()
	if len(r.local.list()) != 0 || r.upstreamCount() != 0 {
		t.Errorf("local=%+v upstream=%d: an event about a locally connected host must be dropped", r.local.list(), r.upstreamCount())
	}
}

// host.conflict reaches the hooks through the conflict path, not through the local dispatch (no duplicate).
func TestEvents_ConflictIsNotDispatchedTwice(t *testing.T) {
	r := newEventRig(t, map[string]string{})
	r.send(RelayMessage{Event: "host.conflict", Hostname: "h", OldRelay: "x", NewRelay: "dmz1", RelayChain: []string{"dmz1"}})
	r.ready()
	if got := r.local.list(); len(got) != 0 {
		t.Errorf("host.conflict must not use the local event dispatch: %+v", got)
	}
	select {
	case m := <-r.upstream:
		if m.Event != "host.conflict" {
			t.Errorf("forwarded %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Error("host.conflict must still be forwarded upstream")
	}
}

// Hello is required before any event: an unauthenticated-state peer cannot trigger hooks.
func TestEvents_BeforeHelloAreIgnored(t *testing.T) {
	local := recordLocalEvents(t)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "h", Status: "connected", RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, c)
	if got := local.list(); len(got) != 0 {
		t.Errorf("an event before relay_hello triggered hooks: %+v", got)
	}
}
