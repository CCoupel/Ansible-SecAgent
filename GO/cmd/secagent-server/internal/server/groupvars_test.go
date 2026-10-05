package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ── group vars on REAL nodes (#139) ──────────────────────────────────────────

// A child relay publishes its RELAY_GROUP_VARS to its parent in the topology_snapshot (also the
// channel of a push link, where the parent opens the connection).
func TestGroupVars_ChildPublishesItsVarsInTheSnapshot(t *testing.T) {
	t.Setenv("REPEATER_ID", "dmz1")
	_, _, admin, wsAddr := startNode(t, func(c *Config) { c.GroupVars = map[string]any{"env": "staging", "datacenter": "paris"} })

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
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			t.Fatal(err)
		}
		if m["type"] != "topology_snapshot" {
			continue
		}
		gv, ok := m["group_vars"].(map[string]any)
		if !ok || gv["env"] != "staging" || gv["datacenter"] != "paris" {
			t.Errorf("snapshot group_vars = %v", m["group_vars"])
		}
		return
	}
}

// A parent receiving a child's vars (hello, snapshot, relay.updated) serves them in the inventory.
func TestGroupVars_ReceivedVarsAreServedInTheInventory(t *testing.T) {
	_, api, admin, wsAddr := startNode(t, nil)
	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{"role": "plugin", "description": "inv"})
	if code != http.StatusCreated {
		t.Fatalf("plugin token: %d %s", code, body)
	}
	var pt struct{ Token string }
	_ = json.Unmarshal(body, &pt)

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
	send(map[string]any{"type": "relay_hello", "relay_id": "dmz1", "version": "3.0",
		"group_vars": map[string]any{"env": "staging", "datacenter": "paris"}})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var m map[string]any
	if err := c.ReadJSON(&m); err != nil {
		t.Fatal(err)
	}
	send(map[string]any{"type": "topology_snapshot",
		"relays": []any{map[string]any{"relay_id": "zone-a", "relay_chain": []string{"dmz1", "zone-a"}, "group_vars": map[string]any{"env": "zone"}}},
		"agents": []any{map[string]any{"hostname": "host-2", "relay_id": "zone-a", "relay_chain": []string{"dmz1", "zone-a"}}}})
	if err := c.ReadJSON(&m); err != nil || m["type"] != "topology_ack" {
		t.Fatalf("snapshot: %v %v", m, err)
	}
	// a later update of the deep relay's vars, as an event
	send(map[string]any{"type": "event_forward", "event": "relay.updated", "relay_id": "zone-a",
		"group_vars": map[string]any{"env": "zone", "tier": 2}, "relay_chain": []string{"zone-a", "dmz1"}})

	fetch := func() map[string]json.RawMessage {
		req, _ := http.NewRequest("GET", "http://"+api+"/api/inventory", nil)
		req.Header.Set("Authorization", "Bearer "+pt.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(raw, &doc)
		return doc
	}
	var doc map[string]json.RawMessage
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doc = fetch()
		if strings.Contains(string(doc["zone-a"]), `"tier"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var dmz1, zoneA struct {
		Vars map[string]json.RawMessage `json:"vars"`
	}
	_ = json.Unmarshal(doc["dmz1"], &dmz1)
	_ = json.Unmarshal(doc["zone-a"], &zoneA)
	if string(dmz1.Vars["env"]) != `"staging"` || string(dmz1.Vars["datacenter"]) != `"paris"` {
		t.Errorf("dmz1 vars = %v (from relay_hello)", dmz1.Vars)
	}
	if string(zoneA.Vars["env"]) != `"zone"` || string(zoneA.Vars["tier"]) != `2` {
		t.Errorf("zone-a vars = %v (from the snapshot, then updated by relay.updated)", zoneA.Vars)
	}
}

// A relay sending a template (or a reserved key) cannot get it into the inventory: the link is
// refused and nothing is stored.
func TestGroupVars_HostileVarsNeverReachTheInventory(t *testing.T) {
	n, api, admin, wsAddr := startNode(t, nil)
	_ = api
	token, _ := registerRelay(t, admin, "dmz1")
	for name, vars := range map[string]map[string]any{
		"template":   {"x": "{{ lookup('pipe','id') }}"},
		"connection": {"ansible_connection": "local"},
	} {
		c, _, err := dialRelayWS(wsAddr, token)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "dmz1", "version": "3.0", "group_vars": vars}); err != nil {
			t.Fatal(err)
		}
		if got := readUntilClose(t, c); got != 4012 {
			t.Errorf("%s: close code %d, want 4012", name, got)
		}
		_ = c.Close()
	}
	stored, err := n.store.ListRelayGroupVars()
	if err != nil || len(stored) != 0 {
		t.Errorf("stored group vars = %v (%v), want none", stored, err)
	}
}

// This node's own RELAY_GROUP_VARS are served as the vars of its own relay group.
func TestGroupVars_NodesOwnVarsAreServedInItsInventory(t *testing.T) {
	t.Setenv("REPEATER_ID", "central")
	_, api, admin, _ := startNode(t, func(c *Config) { c.GroupVars = map[string]any{"env": "prod", "tier": 1.0} })
	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{"role": "plugin", "description": "inv"})
	if code != http.StatusCreated {
		t.Fatalf("plugin token: %d %s", code, body)
	}
	var pt struct{ Token string }
	_ = json.Unmarshal(body, &pt)
	req, _ := http.NewRequest("GET", "http://"+api+"/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+pt.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]json.RawMessage
	_ = json.Unmarshal(raw, &doc)
	var central struct {
		Vars map[string]json.RawMessage `json:"vars"`
	}
	_ = json.Unmarshal(doc["central"], &central)
	if string(central.Vars["env"]) != `"prod"` || string(central.Vars["tier"]) != `1` {
		t.Errorf("central group = %s", doc["central"])
	}
}
