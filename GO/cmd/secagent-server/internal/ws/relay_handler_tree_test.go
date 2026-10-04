package ws

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// setTreeHooks installs the tree hooks for one test and resets them on cleanup.
func setTreeHooks(t *testing.T, local string, ancestors []string,
	register func(string) error, upstream func(RelayMessage)) {
	t.Helper()
	SetRelayLocalIDFunc(func() string { return local })
	SetRelayAncestorsFunc(func() []string { return ancestors })
	SetRelayNodeRegisterFunc(register)
	SetRelayEventUpstreamFunc(upstream)
	t.Cleanup(func() {
		SetRelayLocalIDFunc(nil)
		SetRelayAncestorsFunc(nil)
		SetRelayNodeRegisterFunc(nil)
		SetRelayEventUpstreamFunc(nil)
	})
}

// expectClose reads until the server closes and returns the WS close code (-1 if not a close error).
func expectClose(t *testing.T, c *websocket.Conn) int {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		var m RelayMessage
		if err := c.ReadJSON(&m); err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return ce.Code
			}
			t.Fatalf("expected a close frame, got %v", err)
		}
	}
}

func readMsg(t *testing.T, c *websocket.Conn) RelayMessage {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var m RelayMessage
	if err := c.ReadJSON(&m); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	return m
}

func helloAs(t *testing.T, c *websocket.Conn, id string) {
	t.Helper()
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: id, Version: "3.0"}); err != nil {
		t.Fatal(err)
	}
}

// handshake performs hello+ack for child and returns the ack.
func handshake(t *testing.T, c *websocket.Conn, child string) RelayMessage {
	t.Helper()
	helloAs(t, c, child)
	ack := readMsg(t, c)
	if ack.Type != "relay_ack" {
		t.Fatalf("expected relay_ack, got %+v", ack)
	}
	return ack
}

// ── hello: identity, loop, ack, auto-registration ────────────────────────────

func TestTree_HelloIDMustMatchJWTSub(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	helloAs(t, c, "someone-else")
	if code := expectClose(t, c); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
}

func TestTree_AckCarriesParentIdentityAndAncestors(t *testing.T) {
	setTreeHooks(t, "dmz1", []string{"central"}, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("zone-a", "relay"))
	ack := handshake(t, c, "zone-a")
	if ack.RelayID != "dmz1" || ack.Status != "ok" {
		t.Errorf("ack = %+v, want relay_id=dmz1", ack)
	}
	if len(ack.Ancestors) != 2 || ack.Ancestors[0] != "dmz1" || ack.Ancestors[1] != "central" {
		t.Errorf("ack.ancestors = %v, want [dmz1 central]", ack.Ancestors)
	}
}

func TestTree_LoopRefused(t *testing.T) {
	tests := []struct {
		name      string
		local     string
		ancestors []string
		child     string
		refused   bool
	}{
		{"child is the parent itself", "dmz1", nil, "dmz1", true},
		{"child is an ancestor of the parent", "zone-a", []string{"dmz1", "central"}, "central", true},
		{"child is the direct parent of the parent", "zone-a", []string{"dmz1", "central"}, "dmz1", true},
		{"unrelated child accepted", "dmz1", []string{"central"}, "zone-b", false},
		{"root with no ancestors accepts any other id", "central", nil, "dmz1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setTreeHooks(t, tt.local, tt.ancestors, nil, nil)
			srv := setupRelayTestServer(t)
			defer srv.Close()
			c := dialRelay(t, srv, makeRelayJWT(tt.child, "relay"))
			if tt.refused {
				// refused at upgrade time, without waiting for any hello
				if code := expectClose(t, c); code != WSRelayCloseRevoked {
					t.Errorf("close code = %d, want 4010", code)
				}
				if IsRelayConnected(tt.child) {
					t.Error("refused relay must not be registered")
				}
				return
			}
			if ack := handshake(t, c, tt.child); ack.Status != "ok" {
				t.Errorf("ack = %+v", ack)
			}
		})
	}
}

func TestTree_HelloAutoRegistrationIsIdempotent(t *testing.T) {
	var mu sync.Mutex
	var registered []string
	setTreeHooks(t, "central", nil, func(id string) error {
		mu.Lock()
		registered = append(registered, id)
		mu.Unlock()
		return nil
	}, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	for i := 0; i < 2; i++ { // second pass = reconnection
		c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
		handshake(t, c, "dmz1")
		_ = c.Close()
		if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("dmz1") }) {
			t.Fatal("relay still connected after close")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(registered) != 2 || registered[0] != "dmz1" || registered[1] != "dmz1" {
		t.Errorf("register calls = %v (the hook itself is idempotent; one call per hello)", registered)
	}
}

// ── topology_snapshot ────────────────────────────────────────────────────────

func sendSnapshot(t *testing.T, c *websocket.Conn, relays []RelayTopoEntry, agents []RelayAgentInfo) {
	t.Helper()
	if err := c.WriteJSON(RelayMessage{Type: "topology_snapshot", Relays: relays, Agents: agents}); err != nil {
		t.Fatal(err)
	}
}

func TestTree_SnapshotValidAppliedToRouting(t *testing.T) {
	var mu sync.Mutex
	routing := map[string][]string{}
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		mu.Lock()
		routing[relayID] = hostnames
		mu.Unlock()
		return nil
	})
	var regMu sync.Mutex
	var registered []string
	setTreeHooks(t, "central", nil, func(id string) error {
		regMu.Lock()
		registered = append(registered, id)
		regMu.Unlock()
		return nil
	}, nil)
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
	if m := readMsg(t, c); m.Type != "topology_ack" || m.Status != "ok" {
		t.Fatalf("expected topology_ack, got %+v", m)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(routing["dmz1"]) != 1 || routing["dmz1"][0] != "host-A" ||
		len(routing["zone-a"]) != 1 || routing["zone-a"][0] != "host-B" {
		t.Errorf("routing = %v", routing)
	}
	regMu.Lock()
	defer regMu.Unlock()
	found := false
	for _, r := range registered {
		if r == "zone-a" {
			found = true
		}
	}
	if !found {
		t.Errorf("descendant zone-a not registered in relay_nodes: %v", registered)
	}
}

func TestTree_SnapshotRejected(t *testing.T) {
	ok := func(h string) RelayAgentInfo {
		return RelayAgentInfo{Hostname: h, RelayID: "dmz1", RelayChain: []string{"dmz1"}}
	}
	tests := []struct {
		name   string
		relays []RelayTopoEntry
		agents []RelayAgentInfo
	}{
		{"duplicate hostname", nil, []RelayAgentInfo{ok("h"), ok("h")}},
		{"chain contains the parent (cycle)", nil,
			[]RelayAgentInfo{{Hostname: "h", RelayID: "dmz1", RelayChain: []string{"dmz1", "central"}}}},
		{"descendant chain contains an ancestor", []RelayTopoEntry{{RelayID: "x", RelayChain: []string{"dmz1", "root-anc", "x"}}}, nil},
		{"chain repeats an id", []RelayTopoEntry{{RelayID: "x", RelayChain: []string{"dmz1", "x", "dmz1", "x"}}}, nil},
		{"chain does not start with the child", nil,
			[]RelayAgentInfo{{Hostname: "h", RelayID: "dmz1", RelayChain: []string{"other", "dmz1"}}}},
		{"chain does not end with declaring relay", nil,
			[]RelayAgentInfo{{Hostname: "h", RelayID: "dmz1", RelayChain: []string{"dmz1", "zzz"}}}},
		{"agent on undeclared relay", nil,
			[]RelayAgentInfo{{Hostname: "h", RelayID: "ghost", RelayChain: []string{"dmz1", "ghost"}}}},
		{"duplicate descendant relay", []RelayTopoEntry{
			{RelayID: "x", RelayChain: []string{"dmz1", "x"}}, {RelayID: "x", RelayChain: []string{"dmz1", "x"}}}, nil},
		{"agent without hostname", nil, []RelayAgentInfo{{RelayID: "dmz1", RelayChain: []string{"dmz1"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setTreeHooks(t, "central", []string{"root-anc"}, nil, nil)
			srv := setupRelayTestServer(t)
			defer srv.Close()
			c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
			handshake(t, c, "dmz1")
			sendSnapshot(t, c, tt.relays, tt.agents)
			if code := expectClose(t, c); code != WSRelayCloseRevoked {
				t.Errorf("close code = %d, want 4010", code)
			}
		})
	}
}

func TestTree_SnapshotLimits(t *testing.T) {
	t.Setenv("MAX_SNAPSHOT_HOSTS", "2")
	t.Setenv("MAX_SNAPSHOT_RELAYS", "1")
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	t.Run("too many hosts", func(t *testing.T) {
		c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
		handshake(t, c, "dmz1")
		var ag []RelayAgentInfo
		for _, h := range []string{"a", "b", "c"} {
			ag = append(ag, RelayAgentInfo{Hostname: h, RelayID: "dmz1", RelayChain: []string{"dmz1"}})
		}
		sendSnapshot(t, c, nil, ag)
		if code := expectClose(t, c); code != WSRelayCloseRevoked {
			t.Errorf("close code = %d", code)
		}
	})
	t.Run("too many relays", func(t *testing.T) {
		c := dialRelay(t, srv, makeRelayJWT("dmz2", "relay"))
		handshake(t, c, "dmz2")
		sendSnapshot(t, c, []RelayTopoEntry{
			{RelayID: "x", RelayChain: []string{"dmz2", "x"}}, {RelayID: "y", RelayChain: []string{"dmz2", "y"}}}, nil)
		if code := expectClose(t, c); code != WSRelayCloseRevoked {
			t.Errorf("close code = %d", code)
		}
	})
}

func TestTree_SecondSnapshotRefused(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, nil, nil)
	if m := readMsg(t, c); m.Type != "topology_ack" {
		t.Fatalf("got %+v", m)
	}
	sendSnapshot(t, c, nil, nil)
	if code := expectClose(t, c); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d", code)
	}
}

func TestTree_RoutingClearedForDescendantsOnDisconnect(t *testing.T) {
	var mu sync.Mutex
	cleared := map[string]bool{}
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if hostnames == nil {
			mu.Lock()
			cleared[relayID] = true
			mu.Unlock()
		}
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, c)
	_ = c.Close()
	if !awaitCondition(3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cleared["zone-a"] && cleared["dmz1"]
	}) {
		t.Errorf("routing not cleared for descendants: %v", cleared)
	}
}

// ── event_forward ────────────────────────────────────────────────────────────

func TestTree_EventForwardValidation(t *testing.T) {
	var mu sync.Mutex
	var got []RelayMessage
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	})
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, c)

	send := func(chain ...string) {
		t.Helper()
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "h", RelayChain: chain}); err != nil {
			t.Fatal(err)
		}
	}
	send("dmz1")            // valid
	send("zone-a", "dmz1")  // valid: zone-a is a declared descendant, last == peer
	send("dmz1", "zone-a")  // last != peer → rejected
	send("ghost", "dmz1")   // unknown descendant → rejected
	send("central", "dmz1") // contains local id → rejected
	send()                  // empty → rejected
	send("zone-a", "dmz1")  // valid: third forwarded event
	if !awaitCondition(3*time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 3 }) {
		t.Fatalf("expected 3 forwarded events, got %d", len(got))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Errorf("forwarded %d events, want 3: %+v", len(got), got)
	}
}

func TestTree_EventForwardRateLimited(t *testing.T) {
	var n int
	var mu sync.Mutex
	setTreeHooks(t, "central", nil, nil, func(RelayMessage) { mu.Lock(); n++; mu.Unlock() })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	for i := 0; i < maxEventsPerSecond*3; i++ {
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", RelayChain: []string{"dmz1"}}); err != nil {
			t.Fatal(err)
		}
	}
	// A heartbeat round-trip proves all previous messages were processed.
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if m := readMsg(t, c); m.Type != "heartbeat_ack" {
		t.Fatalf("got %+v", m)
	}
	mu.Lock()
	defer mu.Unlock()
	if n == 0 || n > maxEventsPerSecond*2 { // window may roll once on a slow machine
		t.Errorf("forwarded %d events out of %d (limit %d/s)", n, maxEventsPerSecond*3, maxEventsPerSecond)
	}
}

// ── message size ─────────────────────────────────────────────────────────────

func TestTree_MessageSizeLimit(t *testing.T) {
	t.Setenv("MAX_WS_MESSAGE_SIZE_RELAY", "1024")
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	big := make([]RelayAgentInfo, 200)
	for i := range big {
		big[i] = RelayAgentInfo{Hostname: "host-with-a-rather-long-name-" + string(rune('a'+i%26)), Status: "connected"}
	}
	if err := c.WriteJSON(RelayMessage{Type: "agent_list", Agents: big}); err != nil {
		t.Fatal(err)
	}
	if code := expectClose(t, c); code != websocket.CloseMessageTooBig {
		t.Errorf("close code = %d, want %d", code, websocket.CloseMessageTooBig)
	}
}

// ── fail-closed authentication (HAUT-2) ──────────────────────────────────────

func TestRelayAuth_FailClosedWithoutJWTSecretsFunc(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()
	JWTSecretsFunc = nil // setupRelayTestServer's cleanup restores the previous value

	tests := []struct {
		name  string
		query string
		token string
	}{
		{"no credentials", "", ""},
		{"relay_id query param", "?relay_id=dmz1", ""},
		{"unverified bearer", "", makeRelayJWT("dmz1", "relay")},
		{"unverified bearer + relay_id", "?relay_id=dmz1&is_proxy=true", makeRelayJWT("dmz1", "relay")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/relay" + tt.query
			h := http.Header{}
			if tt.token != "" {
				h.Set("Authorization", "Bearer "+tt.token)
			}
			_, resp, err := websocket.DefaultDialer.Dial(url, h)
			if err == nil {
				t.Fatal("connection must be refused")
			}
			if resp == nil || resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("response = %v, want 401", resp)
			}
			if IsRelayConnected("dmz1") {
				t.Error("relay registered despite refusal")
			}
		})
	}
}

// ── JTI blacklist at upgrade (HAUT-1) ────────────────────────────────────────

func setBlacklist(t *testing.T, fn func(string) (bool, error)) {
	t.Helper()
	SetRelayJTIBlacklistFunc(fn)
	t.Cleanup(func() { SetRelayJTIBlacklistFunc(defaultNoBlacklist) })
}

func TestRelayAuth_RevokedTokenRefused(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()
	setBlacklist(t, func(jti string) (bool, error) { return jti == "test-jti-dmz1", nil })

	if code := dialRelayExpectFail(t, srv, makeRelayJWT("dmz1", "relay")); code != http.StatusUnauthorized {
		t.Errorf("revoked token: status %d, want 401", code)
	}
	// another relay (other jti) still connects
	c := dialRelay(t, srv, makeRelayJWT("dmz2", "relay"))
	if !awaitRelayConnected(t, "dmz2", 2*time.Second) {
		t.Error("non-revoked relay should connect")
	}
	_ = c
}

func TestRelayAuth_BlacklistErrorFailsClosed(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()
	setBlacklist(t, func(string) (bool, error) { return false, errors.New("db down") })
	if code := dialRelayExpectFail(t, srv, makeRelayJWT("dmz1", "relay")); code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", code)
	}
}

// ── route hijack via topology_snapshot (HAUT-3) ──────────────────────────────

func setHostRoutes(t *testing.T, routes map[string]string) {
	t.Helper()
	SetRelayHostRouteFunc(func(h string) (string, error) { return routes[h], nil })
	t.Cleanup(func() { SetRelayHostRouteFunc(nil) })
}

func TestTree_SnapshotCannotHijackConnectedRelay(t *testing.T) {
	var mu sync.Mutex
	var upserts []string
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		mu.Lock()
		if hostnames != nil {
			upserts = append(upserts, relayID)
		}
		mu.Unlock()
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	if !awaitRelayConnected(t, "relay-b", 2*time.Second) {
		t.Fatal("relay-b not connected")
	}

	a := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
	handshake(t, a, "relay-a")
	sendSnapshot(t, a,
		[]RelayTopoEntry{{RelayID: "relay-b", RelayChain: []string{"relay-a", "relay-b"}}},
		[]RelayAgentInfo{{Hostname: "fake", RelayID: "relay-b", RelayChain: []string{"relay-a", "relay-b"}}})
	if code := expectClose(t, a); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range upserts {
		if id == "relay-b" {
			t.Errorf("routing of relay-b was overwritten: %v", upserts)
		}
	}
}

func TestTree_SnapshotCannotRedeclareRelayOwnedByAnotherPeer(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	a := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
	handshake(t, a, "relay-a")
	sendSnapshot(t, a, []RelayTopoEntry{{RelayID: "zone-x", RelayChain: []string{"relay-a", "zone-x"}}}, nil)
	if m := readMsg(t, a); m.Type != "topology_ack" {
		t.Fatalf("A's snapshot should be accepted, got %+v", m)
	}

	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	sendSnapshot(t, b, []RelayTopoEntry{{RelayID: "zone-x", RelayChain: []string{"relay-b", "zone-x"}}}, nil)
	if code := expectClose(t, b); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}

	// once A is gone, the relay can be declared elsewhere
	_ = a.Close()
	if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("relay-a") }) {
		t.Fatal("relay-a still connected")
	}
	// release is deferred in the handler goroutine; wait until a new claim succeeds
	if !awaitCondition(2*time.Second, func() bool {
		descOwnerMu.Lock()
		defer descOwnerMu.Unlock()
		_, held := descendantOwner["zone-x"]
		return !held
	}) {
		t.Error("descendant ownership not released after owner disconnect")
	}
}

func TestTree_SnapshotCannotHijackHostRoutedElsewhere(t *testing.T) {
	setHostRoutes(t, map[string]string{"victim": "relay-b"})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	a := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
	handshake(t, a, "relay-a")
	sendSnapshot(t, a, nil, []RelayAgentInfo{{Hostname: "victim", RelayID: "relay-a", RelayChain: []string{"relay-a"}}})
	if code := expectClose(t, a); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
}

func TestTree_SnapshotAllowsOwnExistingRoutes(t *testing.T) {
	setHostRoutes(t, map[string]string{"h1": "relay-a", "h2": "zone-x"})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	a := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
	handshake(t, a, "relay-a")
	sendSnapshot(t, a,
		[]RelayTopoEntry{{RelayID: "zone-x", RelayChain: []string{"relay-a", "zone-x"}}},
		[]RelayAgentInfo{
			{Hostname: "h1", RelayID: "relay-a", RelayChain: []string{"relay-a"}},
			{Hostname: "h2", RelayID: "zone-x", RelayChain: []string{"relay-a", "zone-x"}},
		})
	if m := readMsg(t, a); m.Type != "topology_ack" {
		t.Errorf("reconnect re-declaring its own routes must be accepted, got %+v", m)
	}
}

// ── state machine (MOYEN-2) and chain bound (BAS-1) ──────────────────────────

func TestTree_SnapshotBeforeHelloRefused(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	sendSnapshot(t, c, nil, []RelayAgentInfo{{Hostname: "h", RelayID: "dmz1", RelayChain: []string{"dmz1"}}})
	if code := expectClose(t, c); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
}

func TestTree_SnapshotChainTooLong(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	chain := []string{"dmz1"}
	for i := 0; i < maxRelayChainLen; i++ {
		chain = append(chain, "n"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	sendSnapshot(t, c, []RelayTopoEntry{{RelayID: chain[len(chain)-1], RelayChain: chain}}, nil)
	if code := expectClose(t, c); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
}

func TestRelayAuth_BlacklistNotConfiguredFailsClosed(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()
	SetRelayJTIBlacklistFunc(nil)
	t.Cleanup(func() { SetRelayJTIBlacklistFunc(defaultNoBlacklist) })
	if code := dialRelayExpectFail(t, srv, makeRelayJWT("dmz1", "relay")); code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 when the blacklist hook is not wired", code)
	}
}

// ── targeted tests for QA mutations ──────────────────────────────────────────

// A chain of maxRelayChainLen+1 DISTINCT declared descendants: every other check
// (peer last, declared intermediates, no local id, no repetition) passes, so only
// the length bound can refuse it.
func TestTree_EventChainTooLongDropped(t *testing.T) {
	var n int
	var mu sync.Mutex
	setTreeHooks(t, "central", nil, nil, func(RelayMessage) { mu.Lock(); n++; mu.Unlock() })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")

	// declare maxRelayChainLen distinct descendants (a snapshot chain can reach the bound itself)
	var relays []RelayTopoEntry
	var ids []string
	for i := 0; i < maxRelayChainLen; i++ {
		ids = append(ids, "d"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		relays = append(relays, RelayTopoEntry{RelayID: ids[i], RelayChain: []string{"dmz1", ids[i]}})
	}
	sendSnapshot(t, c, relays, nil)
	if m := readMsg(t, c); m.Type != "topology_ack" {
		t.Fatalf("snapshot: %+v", m)
	}
	send := func(chain []string) {
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", RelayChain: chain}); err != nil {
			t.Fatal(err)
		}
	}
	atBound := append(append([]string{}, ids[:maxRelayChainLen-1]...), "dmz1") // len == maxRelayChainLen: accepted
	tooLong := append(append([]string{}, ids...), "dmz1")                      // len == maxRelayChainLen+1: refused
	send(atBound)
	send(tooLong)
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, c)
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Errorf("forwarded %d events, want exactly 1 (the one at the bound)", n)
	}
}

func TestTree_EventBeforeHelloIgnored(t *testing.T) {
	var n int
	var mu sync.Mutex
	setTreeHooks(t, "central", nil, nil, func(RelayMessage) { mu.Lock(); n++; mu.Unlock() })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	// chain [dmz1] is otherwise valid; hello was not sent
	if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, c)
	mu.Lock()
	defer mu.Unlock()
	if n != 0 {
		t.Errorf("event before relay_hello was forwarded %d times", n)
	}
}
