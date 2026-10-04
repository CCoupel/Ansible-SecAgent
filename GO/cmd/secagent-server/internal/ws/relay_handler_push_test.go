package ws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── accepted parent link (this node = child, parent dialed us) ───────────────

type parentLinkCall struct {
	ancestors []string
	acked     bool
}

// setParentLink installs the parent-link hook for one test; serve runs after the ack.
func setParentLink(t *testing.T, serve func(conn *websocket.Conn, ancestors []string) error, calls chan<- parentLinkCall) {
	t.Helper()
	SetRelayParentLinkFunc(func(ctx context.Context, conn *websocket.Conn, ancestors []string, ack func() error) error {
		if err := ack(); err != nil {
			return err
		}
		if calls != nil {
			calls <- parentLinkCall{ancestors: ancestors, acked: true}
		}
		return serve(conn, ancestors)
	})
	t.Cleanup(func() { SetRelayParentLinkFunc(nil) })
}

func parentHello(t *testing.T, c *websocket.Conn, id string, ancestors []string) {
	t.Helper()
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: id, Ancestors: ancestors, Version: "3.0"}); err != nil {
		t.Fatal(err)
	}
}

func TestPush_ParentLinkHandshake(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	calls := make(chan parentLinkCall, 1)
	release := make(chan struct{})
	setParentLink(t, func(conn *websocket.Conn, _ []string) error { <-release; return nil }, calls)
	t.Cleanup(func() { close(release) })
	srv := setupRelayTestServer(t)
	defer srv.Close()

	c := dialRelay(t, srv, makeRelayJWT("central", "relay-parent"))
	parentHello(t, c, "central", []string{"root"})
	ack := readMsg(t, c)
	if ack.Type != "relay_ack" || ack.RelayID != "dmz1" || ack.Status != "ok" {
		t.Fatalf("ack = %+v, want relay_ack from dmz1", ack)
	}
	select {
	case call := <-calls:
		if len(call.ancestors) != 2 || call.ancestors[0] != "central" || call.ancestors[1] != "root" {
			t.Errorf("ancestors = %v, want [central root]", call.ancestors)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parent link hook not called")
	}
	if IsRelayConnected("central") {
		t.Error("a parent must not be registered as a child relay connection")
	}
}

func TestPush_ParentLinkRefusals(t *testing.T) {
	tests := []struct {
		name      string
		hook      bool
		tokenSub  string
		helloID   string
		ancestors []string
		busy      bool
		code      int
	}{
		{"hook not wired (e.g. node has a pull parent)", false, "central", "central", nil, false, WSRelayCloseRevoked},
		{"hello relay_id != jwt.sub", true, "central", "other", nil, false, WSRelayCloseRevoked},
		{"parent is ourselves", true, "dmz1", "dmz1", nil, false, WSRelayCloseRevoked},
		{"we are an ancestor of the parent", true, "central", "central", []string{"root", "dmz1"}, false, WSRelayCloseRevoked},
		{"single-parent slot busy (retryable)", true, "central", "central", nil, true, WSRelayCloseRetry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setTreeHooks(t, "dmz1", nil, nil, nil)
			if tt.hook {
				SetRelayParentLinkFunc(func(_ context.Context, _ *websocket.Conn, _ []string, ack func() error) error {
					if tt.busy {
						return errors.New("a parent link is already active")
					}
					return ack()
				})
				t.Cleanup(func() { SetRelayParentLinkFunc(nil) })
			}
			srv := setupRelayTestServer(t)
			defer srv.Close()
			c := dialRelay(t, srv, makeRelayJWT(tt.tokenSub, "relay-parent"))
			parentHello(t, c, tt.helloID, tt.ancestors)
			if code := expectClose(t, c); code != tt.code {
				t.Errorf("close code = %d, want %d (no relay_ack must be sent)", code, tt.code)
			}
		})
	}
}

func TestPush_ParentLinkRequiresHelloFirst(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	setParentLink(t, func(*websocket.Conn, []string) error { return nil }, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("central", "relay-parent"))
	if err := c.WriteJSON(RelayMessage{Type: "task_forward", TaskID: "t", Hostname: "h", Cmd: "id"}); err != nil {
		t.Fatal(err)
	}
	if code := expectClose(t, c); code != WSRelayCloseRetry {
		t.Errorf("close code = %d, want 4012", code)
	}
}

func TestPush_RevokedParentTokenRefused(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	setParentLink(t, func(*websocket.Conn, []string) error { return nil }, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	setBlacklist(t, func(jti string) (bool, error) { return jti == "test-jti-central", nil })
	if code := dialRelayExpectFail(t, srv, makeRelayJWT("central", "relay-parent")); code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", code)
	}
}

func TestPush_UnknownRoleRefused(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	for _, role := range []string{"agent", "admin", "relay-child", ""} {
		if code := dialRelayExpectFail(t, srv, makeRelayJWT("central", role)); code != http.StatusUnauthorized {
			t.Errorf("role %q: status %d, want 401", role, code)
		}
	}
}

// ── dialed child (this node = parent, we opened the link) ────────────────────

// dialedPeer serves a connection with ServeDialedRelay, like the parent's dialer does
// after relay_hello/relay_ack.
func dialedPeer(t *testing.T, peerID string, result chan<- error) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		err = ServeDialedRelay(context.Background(), c, peerID)
		if result != nil {
			result <- err
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialPlain(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial("ws"+srv.URL[len("http"):], nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPush_DialedChildSnapshotRoutingAndTask(t *testing.T) {
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
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, func(id string) error {
		regMu.Lock()
		registered = append(registered, id)
		regMu.Unlock()
		return nil
	}, func(m RelayMessage) { events <- m })

	srv := dialedPeer(t, "dmz1", nil)
	child := dialPlain(t, srv)
	if !awaitRelayConnected(t, "dmz1", 3*time.Second) {
		t.Fatal("dialed child not registered")
	}

	// the child sends its snapshot first (no relay_hello from the child in push mode)
	sendSnapshot(t, child,
		[]RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}},
		[]RelayAgentInfo{
			{Hostname: "host-A", RelayID: "dmz1", RelayChain: []string{"dmz1"}},
			{Hostname: "host-B", RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}},
		})
	if m := readMsg(t, child); m.Type != "topology_ack" {
		t.Fatalf("expected topology_ack, got %+v", m)
	}
	mu.Lock()
	if len(routing["dmz1"]) != 1 || routing["dmz1"][0] != "host-A" || len(routing["zone-a"]) != 1 {
		t.Errorf("routing = %v", routing)
	}
	mu.Unlock()

	// agent_list refreshes the child's direct agents
	if err := child.WriteJSON(RelayMessage{Type: "agent_list", Agents: []RelayAgentInfo{{Hostname: "host-A2"}}}); err != nil {
		t.Fatal(err)
	}
	if m := readMsg(t, child); m.Type != "agent_list_ack" {
		t.Fatalf("expected agent_list_ack, got %+v", m)
	}

	// event_forward goes up through the same validation as in pull mode
	if err := child.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "host-A2", RelayChain: []string{"dmz1"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-events:
		if m.Hostname != "host-A2" {
			t.Errorf("event = %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event_forward not propagated")
	}

	// task_forward is dispatched to the dialed child and its result comes back
	ch, err := DispatchToRelay("dmz1", RelayMessage{Type: "task_forward", TaskID: "t1", Hostname: "host-A2", Cmd: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if m := readMsg(t, child); m.Type != "task_forward" || m.TaskID != "t1" {
		t.Fatalf("child got %+v", m)
	}
	if err := child.WriteJSON(RelayMessage{Type: "task_result", TaskID: "t1", RC: 0, Stdout: "ok"}); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-ch:
		if res.Stdout != "ok" || res.Error != "" {
			t.Errorf("result = %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("task result not delivered")
	}
}

func TestPush_DialedChildSnapshotHijackRefused(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	setHostRoutes(t, map[string]string{"victim": "relay-b"})
	srv := dialedPeer(t, "dmz1", nil)
	child := dialPlain(t, srv)
	if !awaitRelayConnected(t, "dmz1", 3*time.Second) {
		t.Fatal("not registered")
	}
	sendSnapshot(t, child, nil, []RelayAgentInfo{{Hostname: "victim", RelayID: "dmz1", RelayChain: []string{"dmz1"}}})
	if code := expectClose(t, child); code != WSRelayCloseRetry {
		t.Errorf("close code = %d, want 4012", code)
	}
}

func TestPush_DialedChildDisconnectClearsState(t *testing.T) {
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
	result := make(chan error, 1)
	srv := dialedPeer(t, "dmz1", result)
	child := dialPlain(t, srv)
	if !awaitRelayConnected(t, "dmz1", 3*time.Second) {
		t.Fatal("not registered")
	}
	sendSnapshot(t, child, []RelayTopoEntry{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}}}, nil)
	readMsg(t, child)
	_ = child.Close()
	select {
	case <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("ServeDialedRelay did not return")
	}
	if IsRelayConnected("dmz1") {
		t.Error("child still registered after disconnect")
	}
	mu.Lock()
	defer mu.Unlock()
	if !cleared["dmz1"] || !cleared["zone-a"] {
		t.Errorf("routing not cleared: %v", cleared)
	}
}

func TestPush_DialedRelayAlreadyConnectedRefused(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	result := make(chan error, 2)
	srv := dialedPeer(t, "dmz1", result)
	first := dialPlain(t, srv)
	if !awaitRelayConnected(t, "dmz1", 3*time.Second) {
		t.Fatal("not registered")
	}
	second := dialPlain(t, srv)
	select {
	case err := <-result:
		if !errors.Is(err, ErrRelayAlreadyConnected) {
			t.Errorf("err = %v, want ErrRelayAlreadyConnected", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second link not refused")
	}
	_ = second
	if !IsRelayConnected("dmz1") {
		t.Error("the first link must stay registered")
	}
	_ = first
}

func TestPush_DialedContextCancelClosesLink(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		result <- ServeDialedRelay(ctx, c, "dmz1")
	}))
	defer srv.Close()
	dialPlain(t, srv)
	if !awaitRelayConnected(t, "dmz1", 3*time.Second) {
		t.Fatal("not registered")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("link not closed on context cancel")
	}
}

func TestPush_RelayWouldLoopAndIdentity(t *testing.T) {
	setTreeHooks(t, "dmz1", []string{"central", "root"}, nil, nil)
	id, anc := RelayIdentity()
	if id != "dmz1" || len(anc) != 2 {
		t.Errorf("identity = %q %v", id, anc)
	}
	for child, want := range map[string]bool{"dmz1": true, "central": true, "root": true, "zone-a": false} {
		if got := RelayWouldLoop(child); got != want {
			t.Errorf("RelayWouldLoop(%q) = %v, want %v", child, got, want)
		}
	}
}

// A relay-parent token must never open a CHILD link: even a hello + agent_list from it
// registers nothing and updates no routing.
func TestPush_ParentRoleNeverOpensChildLink(t *testing.T) {
	var mu sync.Mutex
	routed := false
	setRoutingHook(t, func(string, []string) error { mu.Lock(); routed = true; mu.Unlock(); return nil })
	setTreeHooks(t, "dmz1", nil, nil, nil)
	setParentLink(t, func(conn *websocket.Conn, _ []string) error {
		// drain: the parent link only reads what the uplink would read
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return err
			}
		}
	}, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("central", "relay-parent"))
	parentHello(t, c, "central", nil)
	readMsg(t, c) // relay_ack
	if err := c.WriteJSON(RelayMessage{Type: "agent_list", Agents: []RelayAgentInfo{{Hostname: "h"}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	time.Sleep(50 * time.Millisecond) // negative check: give a wrong implementation time to act
	mu.Lock()
	defer mu.Unlock()
	if routed || IsRelayConnected("central") {
		t.Errorf("relay-parent token acted as a child (routed=%v connected=%v)", routed, IsRelayConnected("central"))
	}
}

// Revoking a relay-parent token cuts the live parent link with the permanent code 4010 (#150).
func TestPush_RevokeRelayParentLinkClosesWith4010(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	linked := make(chan struct{}, 1)
	setParentLink(t, func(conn *websocket.Conn, _ []string) error {
		linked <- struct{}{}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return err
			}
		}
	}, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("central", "relay-parent"))
	parentHello(t, c, "central", nil)
	readMsg(t, c) // relay_ack
	<-linked

	if RevokeRelayParentLink("some-other-jti") {
		t.Error("an unknown jti must not close anything")
	}
	if !RevokeRelayParentLink("test-jti-central") {
		t.Fatal("the live link of this token must be closed")
	}
	if code := expectClose(t, c); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
	if RevokeRelayParentLink("test-jti-central") {
		t.Error("a second revocation finds no live link")
	}
}
