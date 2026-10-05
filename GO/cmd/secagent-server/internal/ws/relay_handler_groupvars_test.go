package ws

import (
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

// ── relay group vars (#139): hello, snapshot, relay.updated ──────────────────

type gvStore struct {
	mu   sync.Mutex
	vars map[string]string
}

func (s *gvStore) get(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vars[id]
	return v, ok
}

func (s *gvStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vars)
}

type gvRig struct {
	t        *testing.T
	srvURL   func() *websocket.Conn
	store    *gvStore
	upstream chan RelayMessage
}

func newGVRig(t *testing.T) *gvRig {
	t.Helper()
	recordRoutes(t)
	recordConflicts(t)
	r := &gvRig{t: t, store: &gvStore{vars: map[string]string{}}, upstream: make(chan RelayMessage, 64)}
	SetRelayGroupVarsFunc(func(relayID, groupVarsJSON string) error {
		r.store.mu.Lock()
		r.store.vars[relayID] = groupVarsJSON
		r.store.mu.Unlock()
		return nil
	})
	t.Cleanup(func() { SetRelayGroupVarsFunc(nil) })
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { r.upstream <- m })
	setHostRoutes(t, map[string]string{})
	srv := setupRelayTestServer(t)
	t.Cleanup(srv.Close)
	r.srvURL = func() *websocket.Conn { return dialRelay(t, srv, makeRelayJWT("dmz1", "relay")) }
	return r
}

// hello sends relay_hello (with the given vars) and returns the connection.
func (r *gvRig) hello(vars map[string]any) *websocket.Conn {
	r.t.Helper()
	c := r.srvURL()
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: "dmz1", Version: "3.0", GroupVars: vars}); err != nil {
		r.t.Fatal(err)
	}
	return c
}

func barrier(t *testing.T, c *websocket.Conn) {
	t.Helper()
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	for {
		if m := readMsg(t, c); m.Type == "heartbeat_ack" {
			return
		}
	}
}

func (r *gvRig) updates() []RelayMessage {
	var out []RelayMessage
	for {
		select {
		case m := <-r.upstream:
			if m.Event == "relay.updated" {
				out = append(out, m)
			}
		default:
			return out
		}
	}
}

func TestGroupVars_HelloStoresThemAndTellsTheParent(t *testing.T) {
	r := newGVRig(t)
	c := r.hello(map[string]any{"env": "staging", "datacenter": "paris", "ansible_python_interpreter": "/usr/bin/python3", "n": 3.0})
	barrier(t, c)
	got, ok := r.store.get("dmz1")
	if !ok || got != `{"ansible_python_interpreter":"/usr/bin/python3","datacenter":"paris","env":"staging","n":3}` {
		t.Fatalf("stored = %q (canonical JSON expected)", got)
	}
	up := r.updates()
	if len(up) != 1 || up[0].RelayID != "dmz1" || strings.Join(up[0].RelayChain, ",") != "dmz1" || up[0].GroupVars["env"] != "staging" {
		t.Errorf("relay.updated forwarded upstream = %+v (origin-first chain ends with the peer; the uplink appends our id)", up)
	}
}

func TestGroupVars_HelloWithoutVarsStoresNothing(t *testing.T) {
	r := newGVRig(t)
	c := r.hello(nil)
	barrier(t, c)
	if r.store.size() != 0 || len(r.updates()) != 0 {
		t.Errorf("nothing expected: %v", r.store.vars)
	}
}

func TestGroupVars_InvalidVarsInHelloAreRefusedAsAWhole(t *testing.T) {
	bad := map[string]map[string]any{
		"jinja expression":   {"x": "{{ lookup('pipe','id') }}"},
		"ansible_connection": {"ansible_connection": "local"},
		"ansible_become":     {"ansible_become_pass": "x"},
		"secagent namespace": {"secagent_status": "x"},
		"bad key":            {"my-var": 1.0},
		"control character":  {"x": "a\nb"},
		"valid + invalid":    {"ok": "fine", "ansible_user": "root"},
	}
	for name, vars := range bad {
		t.Run(name, func(t *testing.T) {
			r := newGVRig(t)
			c := r.hello(vars)
			if code := expectClose(t, c); code != WSRelayCloseRetry {
				t.Errorf("close code = %d, want 4012", code)
			}
			if r.store.size() != 0 || len(r.updates()) != 0 {
				t.Errorf("invalid vars were stored or forwarded: %v", r.store.vars)
			}
		})
	}
}

func TestGroupVars_SnapshotCarriesOwnAndDescendantVars(t *testing.T) {
	r := newGVRig(t)
	c := r.hello(nil)
	if m := readMsg(t, c); m.Type != "relay_ack" {
		t.Fatalf("got %+v", m)
	}
	sendSnapshotMsg(t, c, RelayMessage{
		GroupVars: map[string]any{"env": "dmz"},
		Relays: []RelayTopoEntry{
			{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}, GroupVars: map[string]any{"env": "zone"}},
			{RelayID: "zone-b", RelayChain: []string{"dmz1", "zone-b"}}, // no vars
		}})
	if m := readMsg(t, c); m.Type != "topology_ack" {
		t.Fatalf("snapshot: %+v", m)
	}
	if v, _ := r.store.get("dmz1"); v != `{"env":"dmz"}` {
		t.Errorf("dmz1 = %q", v)
	}
	if v, _ := r.store.get("zone-a"); v != `{"env":"zone"}` {
		t.Errorf("zone-a = %q", v)
	}
	if _, ok := r.store.get("zone-b"); ok {
		t.Error("a descendant without vars must not get an entry")
	}
	chains := map[string]string{}
	for _, u := range r.updates() {
		chains[u.RelayID] = strings.Join(u.RelayChain, ",")
	}
	if chains["dmz1"] != "dmz1" || chains["zone-a"] != "zone-a,dmz1" {
		t.Errorf("relay.updated chains = %v (origin first, ending with the authenticated peer)", chains)
	}
}

func sendSnapshotMsg(t *testing.T, c *websocket.Conn, m RelayMessage) {
	t.Helper()
	m.Type = "topology_snapshot"
	if err := c.WriteJSON(m); err != nil {
		t.Fatal(err)
	}
}

func TestGroupVars_InvalidDescendantVarsRefuseTheWholeSnapshot(t *testing.T) {
	r := newGVRig(t)
	c := r.hello(nil)
	readMsg(t, c) // ack
	sendSnapshotMsg(t, c, RelayMessage{
		GroupVars: map[string]any{"env": "ok"},
		Relays:    []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}, GroupVars: map[string]any{"x": "{{ 7*7 }}"}}},
		Agents:    []RelayAgentInfo{{Hostname: "h", RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}},
	})
	if code := expectClose(t, c); code != WSRelayCloseRetry {
		t.Errorf("close code = %d, want 4012", code)
	}
	if r.store.size() != 0 {
		t.Errorf("nothing may be stored from a refused snapshot (not even the valid part): %v", r.store.vars)
	}
}

func TestGroupVars_RelayUpdatedEvents(t *testing.T) {
	r := newGVRig(t)
	c := r.hello(nil)
	readMsg(t, c) // ack
	sendSnapshotMsg(t, c, RelayMessage{Relays: []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}})
	readMsg(t, c) // topology_ack
	send := func(m RelayMessage) {
		t.Helper()
		m.Type = "event_forward"
		m.Event = "relay.updated"
		if err := c.WriteJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	good := map[string]any{"env": "prod"}
	send(RelayMessage{RelayID: "dmz1", GroupVars: good, RelayChain: []string{"dmz1"}})                                       // the peer itself
	send(RelayMessage{RelayID: "zone-a", GroupVars: good, RelayChain: []string{"zone-a", "dmz1"}})                           // a declared descendant
	send(RelayMessage{RelayID: "ghost", GroupVars: good, RelayChain: []string{"ghost", "dmz1"}})                             // not declared: refused by the chain check
	send(RelayMessage{RelayID: "zone-a", GroupVars: good, RelayChain: []string{"dmz1"}})                                     // chain does not start with the relay
	send(RelayMessage{RelayID: "dmz1", GroupVars: map[string]any{"ansible_host": "10.0.0.9"}, RelayChain: []string{"dmz1"}}) // reserved key
	send(RelayMessage{RelayID: "a b", GroupVars: good, RelayChain: []string{"a b", "dmz1"}})                                 // malformed id
	barrier(t, c)
	if v, _ := r.store.get("dmz1"); v != `{"env":"prod"}` {
		t.Errorf("dmz1 = %q", v)
	}
	if v, _ := r.store.get("zone-a"); v != `{"env":"prod"}` {
		t.Errorf("zone-a = %q", v)
	}
	if r.store.size() != 2 {
		t.Errorf("only the peer and its declared descendant may be updated: %v", r.store.vars)
	}
	if n := len(r.updates()); n != 2 {
		t.Errorf("forwarded %d relay.updated, want 2", n)
	}

	// clearing: an event without vars empties them
	send(RelayMessage{RelayID: "dmz1", RelayChain: []string{"dmz1"}})
	barrier(t, c)
	if v, _ := r.store.get("dmz1"); v != "" {
		t.Errorf("cleared vars = %q", v)
	}
}

func TestGroupVars_RelayUpdatedBeforeHelloIsIgnored(t *testing.T) {
	r := newGVRig(t)
	c := r.srvURL()
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "relay.updated", RelayID: "dmz1",
		GroupVars: map[string]any{"env": "x"}, RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	barrier(t, c)
	if r.store.size() != 0 {
		t.Errorf("an event before relay_hello changed the group vars: %v", r.store.vars)
	}
}
