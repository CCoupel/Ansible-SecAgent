package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A deep host announced by an event shows up in the hierarchical inventory of the REAL node
// (relay groups, origin-first chain, direct child as next hop), also through the admin port.
func TestInventory_HierarchyBuiltFromRelayEventsOnARealNode(t *testing.T) {
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
	send(map[string]any{"type": "relay_hello", "relay_id": "dmz1", "version": "3.0"})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var m map[string]any
	if err := c.ReadJSON(&m); err != nil {
		t.Fatal(err)
	}
	send(map[string]any{"type": "topology_snapshot",
		"relays": []any{map[string]any{"relay_id": "zone-a", "relay_chain": []string{"dmz1", "zone-a"}}},
		"agents": []any{
			map[string]any{"hostname": "host-1", "relay_id": "dmz1", "relay_chain": []string{"dmz1"}},
			map[string]any{"hostname": "host-2", "relay_id": "zone-a", "relay_chain": []string{"dmz1", "zone-a"}},
		}})
	if err := c.ReadJSON(&m); err != nil || m["type"] != "topology_ack" {
		t.Fatalf("snapshot: %v %v", m, err)
	}
	// a host that comes up AFTER the snapshot (event), deeper in the tree
	send(map[string]any{"type": "event_forward", "event": "host.up", "hostname": "late-host", "status": "connected",
		"relay_chain": []string{"zone-a", "dmz1"}})

	get := func(addr, path, token string) (int, map[string]json.RawMessage) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(raw, &doc)
		return resp.StatusCode, doc
	}
	var doc map[string]json.RawMessage
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, doc = get(api, "/api/inventory", pt.Token)
		if strings.Contains(string(doc["all"]), "late-host") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var all struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}
	_ = json.Unmarshal(doc["all"], &all)
	if len(all.Children) != 1 || all.Children[0] != "dmz1" || len(all.Hosts) != 3 {
		t.Fatalf("all = %+v (late-host must be listed as soon as its host.up event arrived)\n%v", all, doc)
	}
	var dmz1, zoneA struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}
	_ = json.Unmarshal(doc["dmz1"], &dmz1)
	_ = json.Unmarshal(doc["zone-a"], &zoneA)
	if len(dmz1.Hosts) != 1 || dmz1.Hosts[0] != "host-1" || len(dmz1.Children) != 1 || dmz1.Children[0] != "zone-a" {
		t.Errorf("dmz1 = %+v", dmz1)
	}
	if len(zoneA.Hosts) != 2 {
		t.Errorf("zone-a = %+v, want host-2 and late-host", zoneA)
	}
	var meta struct {
		Hostvars map[string]struct {
			Chain   []string `json:"secagent_relay_chain"`
			NextHop string   `json:"secagent_next_hop"`
		} `json:"hostvars"`
	}
	_ = json.Unmarshal(doc["_meta"], &meta)
	late := meta.Hostvars["late-host"]
	if strings.Join(late.Chain, ",") != "zone-a,dmz1" || late.NextHop != "dmz1" {
		t.Errorf("late-host hostvars = %+v, want chain zone-a,dmz1 (origin first) via dmz1", late)
	}

	// scoped to a subtree, through the admin port
	code, scoped := get(admin, "/api/inventory?relay=zone-a", testAdminToken)
	var sc struct {
		Hosts []string `json:"hosts"`
	}
	_ = json.Unmarshal(scoped["all"], &sc)
	if code != http.StatusOK || len(sc.Hosts) != 2 {
		t.Errorf("relay=zone-a: %d %v", code, scoped)
	}
	if code, _ := get(admin, "/api/inventory?relay=bad%20id", testAdminToken); code != http.StatusBadRequest {
		t.Errorf("malformed scope: %d, want 400", code)
	}
}
