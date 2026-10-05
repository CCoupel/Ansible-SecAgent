package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── event propagation on REAL nodes (#126) ───────────────────────────────────

// readEvent reads messages until an event_forward arrives (agent_list / snapshot are skipped).
func readEvent(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			t.Fatalf("waiting for an event_forward: %v", err)
		}
		if m["type"] == "event_forward" {
			return m
		}
	}
}

func chainOf(m map[string]any) string {
	var parts []string
	for _, v := range m["relay_chain"].([]any) {
		parts = append(parts, v.(string))
	}
	return strings.Join(parts, ",")
}

// A node whose parent opened the link (push) publishes the local events of its agents upstream,
// with its own id added to relay_chain.
func TestEvents_LocalAgentEventsAreForwardedToTheParent(t *testing.T) {
	t.Setenv("REPEATER_ID", "dmz1") // this node's identity
	_, _, admin, wsAddr := startNode(t, nil)

	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{
		"role": "relay-parent", "sub": "central", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, body)
	}
	var tok struct{ Token string }
	_ = json.Unmarshal(body, &tok)

	c, _, err := dialRelayWS(wsAddr, tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack map[string]any
	if err := c.ReadJSON(&ack); err != nil || ack["type"] != "relay_ack" {
		t.Fatalf("ack: %v %v", ack, err)
	}
	// the uplink is serving once it has sent its snapshot
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			t.Fatal(err)
		}
		if m["type"] == "agent_list" {
			break
		}
	}

	ws.RegisterConnection("host-A", &ws.AgentConnection{Hostname: "host-A"}) // an agent connects here
	up := readEvent(t, c)
	if up["event"] != "host.up" || up["hostname"] != "host-A" || up["status"] != "connected" || chainOf(up) != "dmz1" {
		t.Errorf("host.up event = %v", up)
	}
	ws.UnregisterConnection("host-A")
	down := readEvent(t, c)
	if down["event"] != "host.down" || down["hostname"] != "host-A" || down["status"] != "disconnected" || chainOf(down) != "dmz1" {
		t.Errorf("host.down event = %v", down)
	}

	// enrollment (host.new) carries enrolled_at; kinds that are not propagated do not go up
	hooks.GlobalDispatcher.Dispatch("host.revoked", "host-R", "revoked", "")
	hooks.GlobalDispatcher.Dispatch("host.new", "host-N", "disconnected", "2026-10-05T09:00:00Z")
	nw := readEvent(t, c)
	if nw["event"] != "host.new" || nw["hostname"] != "host-N" || nw["enrolled_at"] != "2026-10-05T09:00:00Z" {
		t.Errorf("host.new event = %v (host.revoked must not have been forwarded before it)", nw)
	}
}

// An event received from a child runs this node's hooks with the received relay_chain and makes
// a deep host routable at once, without waiting for a new topology_snapshot.
func TestEvents_ReceivedEventRunsHooksAndRoutesTheDeepHost(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	hooksFile := filepath.Join(dir, "hooks.json")
	cfg := `{"hooks":[
	 {"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"UP {{hostname}} status={{status}} chain={{relay_chain}} origin={{relay_origin}}\n"}]},
	 {"event":"host.down","filter":{"relay_chain_contains":"zone-a"},"actions":[{"type":"file","path":"` + out + `","append":"DOWN-MATCH {{hostname}}\n"}]},
	 {"event":"host.new","filter":{"relay_chain_contains":"dmz9"},"actions":[{"type":"file","path":"` + out + `","append":"NEW-NOMATCH {{hostname}}\n"}]}
	]}`
	if err := os.WriteFile(hooksFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	n, _, admin, wsAddr := startNode(t, func(*Config) { t.Setenv("RELAY_HOOKS_CONFIG", hooksFile) })

	token, _ := registerRelay(t, admin, "dmz1")
	c, _, err := dialRelayWS(wsAddr, token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	send := func(m map[string]any) {
		t.Helper()
		if err := c.WriteJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	send(map[string]any{"type": "relay_hello", "relay_id": "dmz1", "version": "3.0"})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack map[string]any
	if err := c.ReadJSON(&ack); err != nil {
		t.Fatal(err)
	}
	send(map[string]any{"type": "topology_snapshot", "agents": []any{},
		"relays": []any{map[string]any{"relay_id": "zone-a", "relay_chain": []string{"dmz1", "zone-a"}}}})
	if err := c.ReadJSON(&ack); err != nil || ack["type"] != "topology_ack" {
		t.Fatalf("snapshot: %v %v", ack, err)
	}

	// no route yet for the deep host
	if hop, _ := n.store.GetNextHopForHostname("deep-host"); hop != "" {
		t.Fatalf("unexpected route %q", hop)
	}
	send(map[string]any{"type": "event_forward", "event": "host.up", "hostname": "deep-host", "status": "connected",
		"relay_chain": []string{"zone-a", "dmz1"}})
	send(map[string]any{"type": "event_forward", "event": "host.down", "hostname": "deep-host", "status": "disconnected",
		"relay_chain": []string{"zone-a", "dmz1"}})
	send(map[string]any{"type": "event_forward", "event": "host.new", "hostname": "other-host", "status": "disconnected",
		"enrolled_at": "2026-10-05T09:00:00Z", "relay_chain": []string{"dmz1"}})

	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(out)
		got = string(b)
		if strings.Contains(got, "UP deep-host") && strings.Contains(got, "DOWN-MATCH deep-host") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(got, "UP deep-host status=connected chain=zone-a,dmz1 origin=zone-a") {
		t.Errorf("host.up hook output = %q (relay_chain and origin must come from the event)", got)
	}
	if !strings.Contains(got, "DOWN-MATCH deep-host") {
		t.Errorf("a filter that matches the relay_chain must fire: %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if b, _ := os.ReadFile(out); strings.Contains(string(b), "NEW-NOMATCH") {
		t.Error("a filter that does not match the relay_chain must not fire")
	}

	// the deep host is routable through the direct child, without any new snapshot
	if hop, err := n.store.GetNextHopForHostname("deep-host"); err != nil || hop != "dmz1" {
		t.Errorf("next hop of deep-host = %q (%v), want dmz1", hop, err)
	}
	route, _ := n.store.GetRelayRoute("deep-host")
	if route == nil || route.RelayID != "zone-a" || strings.Join(route.RelayChain, ",") != "dmz1,zone-a" {
		t.Errorf("route = %+v, want declared by zone-a via dmz1", route)
	}
}

// A hooks file with an invalid filter does not load: the node starts with no hook (fail closed).
func TestEvents_InvalidHooksFilterDisablesHooksAtStartup(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	hooksFile := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(hooksFile, []byte(`{"hooks":[{"event":"host.up","filter":{},"actions":[{"type":"file","path":"`+out+`","append":"X\n"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	n, _, _, _ := startNode(t, func(*Config) { t.Setenv("RELAY_HOOKS_CONFIG", hooksFile) })
	_ = n
	hooks.GlobalDispatcher.Dispatch("host.up", "h", "connected", "")
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(out); err == nil {
		t.Error("an invalid hooks file must not be partially applied")
	}
}
