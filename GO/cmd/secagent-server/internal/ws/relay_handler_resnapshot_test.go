package ws

import (
	"log"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeRouting is a replace-semantics relay_routing: BulkUpsert(relay, hosts) rewrites the relay's
// hosts, nil clears them (the same contract as the real store).
type fakeRouting struct {
	mu     sync.Mutex
	hosts  map[string][]string
	writes int
}

func newFakeRouting(t *testing.T) *fakeRouting {
	t.Helper()
	f := &fakeRouting{hosts: map[string][]string{}}
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.writes++
		for _, h := range hostnames { // hostname is the primary key: last writer wins
			for id, hs := range f.hosts {
				var keep []string
				for _, x := range hs {
					if x != h {
						keep = append(keep, x)
					}
				}
				f.hosts[id] = keep
			}
		}
		if len(hostnames) == 0 {
			delete(f.hosts, relayID)
		} else {
			f.hosts[relayID] = append([]string(nil), hostnames...)
		}
		return nil
	})
	return f
}

func (f *fakeRouting) get(relayID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := append([]string(nil), f.hosts[relayID]...)
	sort.Strings(h)
	return h
}

func (f *fakeRouting) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// eventSink records the events forwarded upstream.
type eventSink struct {
	mu  sync.Mutex
	got []RelayMessage
}

func (e *eventSink) add(m RelayMessage) { e.mu.Lock(); e.got = append(e.got, m); e.mu.Unlock() }
func (e *eventSink) count() int         { e.mu.Lock(); defer e.mu.Unlock(); return len(e.got) }

func hostUp(t *testing.T, c interface{ WriteJSON(any) error }, host string, chain ...string) {
	t.Helper()
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: host, Status: "connected", RelayChain: chain}); err != nil {
		t.Fatal(err)
	}
}

func ownerOf(id string) string {
	descOwnerMu.Lock()
	defer descOwnerMu.Unlock()
	return descendantOwner[id]
}

func expectAck(t *testing.T, m RelayMessage) {
	t.Helper()
	if m.Type != "topology_ack" || m.Status != "ok" {
		t.Fatalf("expected topology_ack ok, got %+v", m)
	}
}

// A relay that joins a link ALREADY established below us is unknown until its parent sends a new
// snapshot: its events are refused, then accepted once the replacement snapshot declares it.
func TestResnapshot_LateRelayBecomesKnown(t *testing.T) {
	fr := newFakeRouting(t)
	sink := &eventSink{}
	setTreeHooks(t, "central", nil, nil, sink.add)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c, nil, nil)
	expectAck(t, readMsg(t, c))

	hostUp(t, c, "deep-host", "relay2", "relay1")
	barrier(t, c)
	if sink.count() != 0 {
		t.Fatal("an event from a relay not declared in any snapshot must be refused")
	}

	sendSnapshot(t, c,
		[]RelayTopoEntry{{RelayID: "relay2", RelayChain: []string{"relay1", "relay2"}}},
		[]RelayAgentInfo{{Hostname: "h2", RelayID: "relay2", RelayChain: []string{"relay1", "relay2"}}})
	expectAck(t, readMsg(t, c))
	hostUp(t, c, "deep-host", "relay2", "relay1")
	barrier(t, c)
	if sink.count() != 1 {
		t.Errorf("forwarded %d events after the replacement snapshot, want 1", sink.count())
	}
	if got := fr.get("relay2"); len(got) != 1 || got[0] != "h2" {
		t.Errorf("routes of relay2 = %v", got)
	}
	if ownerOf("relay2") != "relay1" {
		t.Errorf("owner of relay2 = %q", ownerOf("relay2"))
	}
}

// A replacement snapshot that no longer lists a relay (or one of its hosts) cleans their routes,
// releases the relay for other peers and makes its events unknown again.
func TestResnapshot_ReplacementRemovesRelaysHostsAndOwnership(t *testing.T) {
	fr := newFakeRouting(t)
	sink := &eventSink{}
	setTreeHooks(t, "central", nil, nil, sink.add)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c,
		[]RelayTopoEntry{
			{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}},
			{RelayID: "zone-b", RelayChain: []string{"relay1", "zone-b"}}},
		[]RelayAgentInfo{
			{Hostname: "own", RelayID: "relay1", RelayChain: []string{"relay1"}},
			{Hostname: "a1", RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}},
			{Hostname: "a2", RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}},
			{Hostname: "b1", RelayID: "zone-b", RelayChain: []string{"relay1", "zone-b"}}})
	expectAck(t, readMsg(t, c))
	if len(fr.get("zone-a")) != 2 || len(fr.get("zone-b")) != 1 || len(fr.get("relay1")) != 1 {
		t.Fatalf("initial routing a=%v b=%v r1=%v", fr.get("zone-a"), fr.get("zone-b"), fr.get("relay1"))
	}

	// zone-b gone, zone-a lost a2, relay1 lost its own host
	sendSnapshot(t, c,
		[]RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}},
		[]RelayAgentInfo{{Hostname: "a1", RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}})
	expectAck(t, readMsg(t, c))
	if got := fr.get("zone-a"); len(got) != 1 || got[0] != "a1" {
		t.Errorf("zone-a hosts = %v, want [a1]", got)
	}
	if got := fr.get("zone-b"); len(got) != 0 {
		t.Errorf("zone-b routes not cleaned: %v", got)
	}
	if got := fr.get("relay1"); len(got) != 0 {
		t.Errorf("relay1 own routes not cleaned: %v", got)
	}
	if ownerOf("zone-b") != "" || ownerOf("zone-a") != "relay1" {
		t.Errorf("ownership zone-a=%q zone-b=%q", ownerOf("zone-a"), ownerOf("zone-b"))
	}
	hostUp(t, c, "b1", "zone-b", "relay1")
	barrier(t, c)
	if sink.count() != 0 {
		t.Error("an event from a relay removed by the replacement must be refused")
	}
}

// A refused replacement must not leave partial state: relays freshly claimed by the refused
// snapshot are given back, nothing is written, and the link is closed (correctable code).
func TestResnapshot_RefusedReplacementLeavesNoPartialState(t *testing.T) {
	fr := newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	// "taken" is routed through another relay: a snapshot declaring it under relay1 conflicts
	setHostRoutes(t, map[string]string{"taken": "other-relay"})
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c,
		[]RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}},
		[]RelayAgentInfo{{Hostname: "a1", RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}})
	expectAck(t, readMsg(t, c))
	before := fr.writeCount()

	sendSnapshot(t, c,
		[]RelayTopoEntry{
			{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}},
			{RelayID: "fresh", RelayChain: []string{"relay1", "fresh"}}},
		[]RelayAgentInfo{{Hostname: "taken", RelayID: "fresh", RelayChain: []string{"relay1", "fresh"}}})
	if code := expectClose(t, c); code != WSRelayCloseRetry {
		t.Errorf("close code = %d, want %d", code, WSRelayCloseRetry)
	}
	if ownerOf("fresh") != "" {
		t.Errorf("relay claimed by the refused snapshot is still owned by %q", ownerOf("fresh"))
	}
	// the only writes after the refusal are the link-close cleanup (nil), never the refused content
	for _, h := range fr.get("fresh") {
		t.Errorf("refused snapshot wrote route %q", h)
	}
	_ = before
	waitUntil(t, "link cleanup releases the previous state", func() bool { return ownerOf("zone-a") == "" })
}

// Replacement snapshots are rate limited per link.
func TestResnapshot_RateLimited(t *testing.T) {
	fr := newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	prevL, prevW := snapshotReplaceLimit, snapshotReplaceWindow
	snapshotReplaceLimit, snapshotReplaceWindow = 3, time.Minute
	t.Cleanup(func() { snapshotReplaceLimit, snapshotReplaceWindow = prevL, prevW })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c, nil, nil) // the first snapshot is not a replacement
	expectAck(t, readMsg(t, c))
	for i := 0; i < 3; i++ {
		sendSnapshot(t, c, nil, nil)
		expectAck(t, readMsg(t, c))
	}
	writes := fr.writeCount()
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "zone-x", RelayChain: []string{"relay1", "zone-x"}}}, nil)
	if code := expectClose(t, c); code != WSRelayCloseRetry {
		t.Errorf("close code = %d, want %d", code, WSRelayCloseRetry)
	}
	if got := fr.get("zone-x"); len(got) != 0 {
		t.Errorf("a rate-limited snapshot was applied: %v", got)
	}
	_ = writes
}

// The snapshot validates every relay id / hostname it carries: control characters, spaces,
// overlong or empty values refuse the WHOLE snapshot (log / env / file-log injection).
// A refusal reason quoting a hostile value must still reach the peer as a proper close frame.
func TestCloseReason_FitsACloseFrame(t *testing.T) {
	for _, in := range []string{strings.Repeat("x", 500), strings.Repeat("é", 200), "bad\xff\xfeutf8", "short"} {
		out := closeReason(in)
		if len(out) > 110 || !utf8.ValidString(out) {
			t.Errorf("closeReason(%q...) = %d bytes valid=%v", in[:min(len(in), 8)], len(out), utf8.ValidString(out))
		}
	}
	if closeReason("short") != "short" {
		t.Error("short reasons are kept as is")
	}
}

func TestResnapshot_ShapeValidation(t *testing.T) {
	bad := map[string]string{
		"newline":     "zone\nINJECT",
		"space":       "zone a",
		"empty":       "",
		"too long":    strings.Repeat("a", 64),
		"unicode NEL": "zone\u0085x",
		"unicode LS":  "zone x",
		"cr":          "zone\rx",
		"nul":         "zone\x00x",
	}
	for name, id := range bad {
		for _, where := range []string{"relay", "relay chain", "agent relay", "agent chain", "hostname"} {
			t.Run(name+"/"+where, func(t *testing.T) {
				fr := newFakeRouting(t)
				setTreeHooks(t, "central", nil, nil, nil)
				srv := setupRelayTestServer(t)
				defer srv.Close()
				c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
				handshake(t, c, "relay1")
				good := []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}}
				var relays []RelayTopoEntry
				var agents []RelayAgentInfo
				switch where {
				case "relay":
					relays = []RelayTopoEntry{{RelayID: id, RelayChain: []string{"relay1", id}}}
				case "relay chain":
					relays = []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"relay1", id, "zone-a"}}}
				case "agent relay":
					relays = good
					agents = []RelayAgentInfo{{Hostname: "h", RelayID: id, RelayChain: []string{"relay1", id}}}
				case "agent chain":
					relays = good
					agents = []RelayAgentInfo{{Hostname: "h", RelayID: "zone-a", RelayChain: []string{"relay1", id, "zone-a"}}}
				case "hostname":
					if name == "too long" {
						id = strings.Repeat("h", 254) // hostnames may be up to 253 chars
					}
					relays = good
					agents = []RelayAgentInfo{{Hostname: id, RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}}}
				}
				sendSnapshot(t, c, relays, agents)
				if code := expectClose(t, c); code != WSRelayCloseRetry {
					t.Fatalf("close code = %d, want %d", code, WSRelayCloseRetry)
				}
				if fr.writeCount() != 0 && len(fr.hosts) != 0 {
					t.Errorf("a refused snapshot wrote routes: %v", fr.hosts)
				}
				if ownerOf(id) != "" && id != "" {
					t.Errorf("invalid relay id %q became owned", id)
				}
			})
		}
	}
}

// The parent is told when the set of relays below changes (snapshot accepted, link closed).
func TestResnapshot_TopologyChangedNotified(t *testing.T) {
	newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	var mu sync.Mutex
	n := 0
	SetRelayTopologyChangedFunc(func() { mu.Lock(); n++; mu.Unlock() })
	t.Cleanup(func() { SetRelayTopologyChangedFunc(nil) })
	count := func() int { mu.Lock(); defer mu.Unlock(); return n }
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c, nil, nil)
	expectAck(t, readMsg(t, c))
	if count() != 1 {
		t.Errorf("notifications after first snapshot = %d, want 1", count())
	}
	sendSnapshot(t, c, nil, nil)
	expectAck(t, readMsg(t, c))
	if count() != 2 {
		t.Errorf("notifications after replacement = %d, want 2", count())
	}
	_ = c.Close()
	waitUntil(t, "link end notified", func() bool { return count() >= 3 })
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

type nopWriter struct{}

func (nopWriter) WriteJSON(any) error { return nil }

// Deterministic: a refused replacement gives back ONLY what it freshly claimed; the relays of the
// previous (still valid) snapshot stay owned by the peer and nothing is written.
func TestResnapshot_RefusedReplacementKeepsPreviousOwnership(t *testing.T) {
	fr := newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	setHostRoutes(t, map[string]string{"taken": "other-relay"})
	descOwnerMu.Lock()
	descendantOwner["zone-a"] = "relay1"
	descOwnerMu.Unlock()
	t.Cleanup(func() {
		descOwnerMu.Lock()
		delete(descendantOwner, "zone-a")
		delete(descendantOwner, "fresh")
		descOwnerMu.Unlock()
	})
	conn := &RelayConnection{RelayID: "relay1", Conn: nopWriter{}, helloDone: true, snapshotDone: true,
		descendants: map[string]struct{}{"zone-a": {}}}

	handleTopologySnapshot(conn, RelayMessage{Type: "topology_snapshot",
		Relays: []RelayTopoEntry{
			{RelayID: "zone-a", RelayChain: []string{"relay1", "zone-a"}},
			{RelayID: "fresh", RelayChain: []string{"relay1", "fresh"}}},
		Agents: []RelayAgentInfo{{Hostname: "taken", RelayID: "fresh", RelayChain: []string{"relay1", "fresh"}}}})

	if conn.reject == nil || conn.reject.code != WSRelayCloseRetry {
		t.Fatalf("the conflicting replacement must be refused, got %+v", conn.reject)
	}
	if ownerOf("zone-a") != "relay1" {
		t.Errorf("the previous state was damaged: zone-a owner = %q", ownerOf("zone-a"))
	}
	if ownerOf("fresh") != "" {
		t.Errorf("relay claimed by the refused snapshot is still owned by %q", ownerOf("fresh"))
	}
	if _, ok := conn.descendants["zone-a"]; !ok || len(conn.descendants) != 1 {
		t.Errorf("conn.descendants changed: %v", conn.descendants)
	}
	if fr.writeCount() != 0 {
		t.Errorf("a refused snapshot wrote routing %d times", fr.writeCount())
	}
}

// Deterministic regression test for the host.conflict storm: whatever the path (agent_list rounds,
// uncontested rounds in between, host.up events), ONE host.conflict is emitted per owner change.
// An uncontested round used to erase the "already reported" memory and the next flip was reported
// again (a 3rd emission for two relays alternating on one host).
func TestConflict_OneReportPerOwnerChangeWhateverThePath(t *testing.T) {
	fr := newFakeRouting(t)
	cl := recordConflicts(t)
	setTreeHooks(t, "central", nil, nil, nil)
	SetRelayHostRouteFunc(func(h string) (string, error) {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		for id, hosts := range fr.hosts {
			for _, x := range hosts {
				if x == h {
					return id, nil
				}
			}
		}
		return "", nil
	})
	t.Cleanup(func() { SetRelayHostRouteFunc(nil) })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	a := dialRelay(t, srv, makeRelayJWT("relayA", "relay"))
	handshake(t, a, "relayA")
	b := dialRelay(t, srv, makeRelayJWT("relayB", "relay"))
	handshake(t, b, "relayB")
	round := func(name string) {
		switch name {
		case "A":
			sendAgentList(t, a, "roamer")
			readMsg(t, a)
		case "B":
			sendAgentList(t, b, "roamer")
			readMsg(t, b)
		case "upA": // an uncontested host.up of the current owner
			hostUp(t, a, "roamer", "relayA")
			barrier(t, a)
		case "upB":
			hostUp(t, b, "roamer", "relayB")
			barrier(t, b)
		}
	}
	for _, step := range []string{"A", "B", "A", "A", "upA", "B", "upB", "A", "B", "A", "B", "A"} {
		round(step)
	}
	if got := len(cl.get()); got != 2 {
		t.Errorf("host.conflict emitted %d times for two relays alternating on one host, want 2 (one per direction)", got)
	}
}

// The real path to each relay below the peer is handed to the chain store (it feeds OUR snapshot
// to OUR parent); a relay that leaves the subtree, or a closed link, clears it.
func TestResnapshot_RelayChainsAreStoredAndCleared(t *testing.T) {
	newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	var mu sync.Mutex
	chains := map[string][]string{}
	SetRelayChainFunc(func(id string, chain []string) error {
		mu.Lock()
		defer mu.Unlock()
		if chain == nil {
			delete(chains, id)
		} else {
			chains[id] = chain
		}
		return nil
	})
	t.Cleanup(func() { SetRelayChainFunc(nil) })
	get := func(id string) string { mu.Lock(); defer mu.Unlock(); return strings.Join(chains[id], ",") }
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendSnapshot(t, c,
		[]RelayTopoEntry{
			{RelayID: "r2", RelayChain: []string{"relay1", "r2"}},
			{RelayID: "r3", RelayChain: []string{"relay1", "r2", "r3"}}}, nil)
	expectAck(t, readMsg(t, c))
	if get("relay1") != "relay1" || get("r2") != "relay1,r2" || get("r3") != "relay1,r2,r3" {
		t.Fatalf("chains = %v", chains)
	}
	// r3 leaves the subtree
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "r2", RelayChain: []string{"relay1", "r2"}}}, nil)
	expectAck(t, readMsg(t, c))
	if get("r3") != "" || get("r2") != "relay1,r2" {
		t.Errorf("after replacement chains = %v, want r3 cleared and r2 kept", chains)
	}
	_ = c.Close()
	waitUntil(t, "link end clears the chains below", func() bool { return get("r2") == "" })
}

// A token whose sub is not a well-formed relay_id is refused at the upgrade (fail closed), and the
// raw value is never written to the logs.
func TestRelayAuth_MalformedSubRefusedWithoutEcho(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	var sink strings.Builder
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return sink.Write(p) }))
	t.Cleanup(func() { log.SetOutput(prev) })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	for _, sub := range []string{"a b", "a/b", "..", "a\n[SECURITY WARNING] forged", strings.Repeat("a", 64), "-x", "é"} {
		if code := dialRelayExpectFail(t, srv, makeRelayJWT(sub, "relay")); code != 401 {
			t.Errorf("sub %q: status %d, want 401", sub, code)
		}
		if code := dialRelayExpectFail(t, srv, makeRelayJWT(sub, "relay-parent")); code != 401 {
			t.Errorf("relay-parent sub %q: status %d, want 401", sub, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(sink.String(), "\n[SECURITY WARNING] forged") || strings.Contains(sink.String(), "a b") {
		t.Errorf("the raw sub was echoed in the logs:\n%s", sink.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// agent_list hostnames are shaped like every other identifier: a malformed one is ignored (never
// written to relay_routing) and reported with the value quoted.
func TestAgentList_MalformedHostnameIgnored(t *testing.T) {
	fr := newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("relay1", "relay"))
	handshake(t, c, "relay1")
	sendAgentList(t, c, "good-host", "bad\nhost", "bad host", "x;rm")
	readMsg(t, c)
	if got := fr.get("relay1"); len(got) != 1 || got[0] != "good-host" {
		t.Errorf("routes = %v, want only good-host", got)
	}
}
