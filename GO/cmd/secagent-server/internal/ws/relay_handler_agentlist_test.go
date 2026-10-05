package ws

import (
	"fmt"
	"sync"
	"testing"
)

// ── agent_list bound (MAX_AGENT_LIST_HOSTS), conflict de-duplication, local precedence ──

func hostNames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	return out
}

func TestAgentList_BoundedByMaxAgentListHosts(t *testing.T) {
	t.Setenv("MAX_AGENT_LIST_HOSTS", "5")
	recordConflicts(t)
	setHostRoutes(t, map[string]string{})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	t.Run("exactly the limit is accepted", func(t *testing.T) {
		c := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
		handshake(t, c, "relay-a")
		sendAgentList(t, c, hostNames("ok", 5)...)
		if m := readMsg(t, c); m.Type != "agent_list_ack" || m.Count != 5 {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("limit+1 is refused before any lookup or routing write", func(t *testing.T) {
		var mu sync.Mutex
		routed := false
		setRoutingHook(t, func(_ string, hosts []string) error {
			if hosts != nil { // nil = disconnect cleanup, not a routing write
				mu.Lock()
				routed = true
				mu.Unlock()
			}
			return nil
		})
		lookups := 0
		SetRelayHostRouteFunc(func(string) (string, error) { mu.Lock(); lookups++; mu.Unlock(); return "", nil })
		t.Cleanup(func() { SetRelayHostRouteFunc(nil) })

		c := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
		handshake(t, c, "relay-b")
		sendAgentList(t, c, hostNames("flood", 6)...)
		if code := expectClose(t, c); code != WSRelayCloseRetry {
			t.Errorf("close code = %d, want 4012", code)
		}
		mu.Lock()
		defer mu.Unlock()
		if routed || lookups != 0 {
			t.Errorf("an over-limit agent_list must cost nothing: routed=%v lookups=%d", routed, lookups)
		}
	})
}

func TestAgentList_DefaultLimitMatchesSnapshot(t *testing.T) {
	if maxAgentListHosts() != 10000 || maxSnapshotHosts() != 10000 {
		t.Errorf("defaults = %d / %d, want 10000 / 10000", maxAgentListHosts(), maxSnapshotHosts())
	}
}

// A relay repeating the same claim every 30 s must produce ONE host.conflict, not a storm;
// a new owner change is a new event.
func TestAgentList_RepeatedClaimEmitsConflictOnce(t *testing.T) {
	cl := recordConflicts(t)
	setHostRoutes(t, map[string]string{"moved": "relay-a"})
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	for i := 0; i < 4; i++ {
		sendAgentList(t, b, "moved")
		readMsg(t, b)
	}
	if got := cl.get(); len(got) != 1 {
		t.Fatalf("conflicts = %d, want exactly 1 for a repeated declaration: %+v", len(got), got)
	}
	// the claim ends (host no longer declared) and starts again: a new conflict
	sendAgentList(t, b)
	readMsg(t, b)
	sendAgentList(t, b, "moved")
	readMsg(t, b)
	if got := cl.get(); len(got) != 2 {
		t.Errorf("conflicts after the claim restarted = %d, want 2", len(got))
	}
}

// A live local agent is never re-routed: the claiming relay gets no routing row for it
// (so no task_forward / stdin can ever be sent there, nor after the agent disconnects), and
// host.conflict fires once.
func TestAgentList_ClaimOnLocalAgentCreatesNoRoute(t *testing.T) {
	cl := recordConflicts(t)
	var mu sync.Mutex
	declared := map[string][]string{}
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		mu.Lock()
		declared[relayID] = hostnames
		mu.Unlock()
		return nil
	})
	setTreeHooks(t, "central", nil, nil, nil)
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"})
	t.Cleanup(func() { UnregisterConnection("local-host") })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	handshake(t, b, "relay-b")
	for i := 0; i < 3; i++ {
		sendAgentList(t, b, "local-host", "other-host")
		readMsg(t, b)
	}
	mu.Lock()
	defer mu.Unlock()
	got := declared["relay-b"]
	if len(got) != 1 || got[0] != "other-host" {
		t.Errorf("routed hosts = %v, want only other-host (the live local agent must not be routed to relay-b)", got)
	}
	if conflicts := cl.get(); len(conflicts) != 1 || conflicts[0].OldRelay != LocalOwner {
		t.Errorf("conflicts = %+v, want exactly one with old=%q", conflicts, LocalOwner)
	}
}

func TestEvent_HostUpOnLocalAgentCreatesNoRoute(t *testing.T) {
	rl := recordRoutes(t)
	cl := recordConflicts(t)
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { events <- m })
	RegisterConnection("local-host", &AgentConnection{Hostname: "local-host"})
	t.Cleanup(func() { UnregisterConnection("local-host") })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	for i := 0; i < 2; i++ {
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Status: "connected", Hostname: "local-host", RelayChain: []string{"dmz1"}}); err != nil {
			t.Fatal(err)
		}
	}
	// barrier: everything sent above was processed once the heartbeat is answered
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, c)
	select {
	case m := <-events:
		t.Errorf("an event about a locally connected host must not be forwarded upstream: %+v", m)
	default:
	}
	if _, ok := rl.get("local-host"); ok {
		t.Error("a live local agent must not get a route through a relay")
	}
	if got := cl.get(); len(got) != 1 {
		t.Errorf("conflicts = %d, want 1", len(got))
	}
}
