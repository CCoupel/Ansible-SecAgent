package server

import (
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/repeater"
)

// readSnapshot reads until the next topology_snapshot (other messages are skipped).
func readSnapshot(t *testing.T, c *websocket.Conn, what string) map[string]any {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if m["type"] == "topology_snapshot" {
			return m
		}
	}
}

func snapshotHas(m map[string]any, key, field, want string) bool {
	items, _ := m[key].([]any)
	for _, it := range items {
		if e, _ := it.(map[string]any); e != nil && e[field] == want {
			return true
		}
	}
	return false
}

// A relay joining a link that is ALREADY established below a node makes that node send its parent
// a new full topology_snapshot (and again when the child link ends): ancestors learn about late
// relays without waiting for a reconnection (#126).
func TestResnapshot_LateChildRelayIsPublishedToTheParent(t *testing.T) {
	t.Setenv("REPEATER_ID", "relay1")
	root, nodeID := newTestRoot(t), "relay1"
	_, _, _, wsAddr := startNode(t, root.anchored(func(c *Config) {
		c.Tune = func(o *repeater.Options, _ *repeater.DialerOptions) {
			o.TopologyDebounce, o.TopologyMinGap = 20*time.Millisecond, 50*time.Millisecond
		}
	}))

	tok := struct{ Token string }{root.token(t, "relay-parent", "central", nodeID)}
	parent, _, err := dialRelayWS(wsAddr, tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	if err := parent.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	first := readSnapshot(t, parent, "the first snapshot")
	if snapshotHas(first, "relays", "relay_id", "relay2") {
		t.Fatal("relay2 is not linked yet")
	}

	// relay2 joins AFTER the parent link is established
	token := root.token(t, "relay-child", "relay2", nodeID)
	child, _, err := dialRelayWS(wsAddr, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := child.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "relay2", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	_ = child.SetReadDeadline(time.Now().Add(5 * time.Second))
	var m map[string]any
	if err := child.ReadJSON(&m); err != nil || m["type"] != "relay_ack" {
		t.Fatalf("ack: %v %v", m, err)
	}
	if err := child.WriteJSON(map[string]any{"type": "topology_snapshot", "relays": []any{},
		"agents": []any{map[string]any{"hostname": "deep-host", "relay_id": "relay2", "relay_chain": []string{"relay2"}}}}); err != nil {
		t.Fatal(err)
	}
	second := readSnapshot(t, parent, "the snapshot published after relay2 joined")
	if !snapshotHas(second, "relays", "relay_id", "relay2") || !snapshotHas(second, "agents", "hostname", "deep-host") {
		t.Errorf("replacement snapshot lacks the late relay or its host: %v", second)
	}

	// the child link ends: its hosts disappear from the next snapshot
	_ = child.Close()
	third := readSnapshot(t, parent, "the snapshot published after relay2 left")
	if snapshotHas(third, "agents", "hostname", "deep-host") {
		t.Errorf("a host of a relay that left is still published: %v", third)
	}
}
