package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── hierarchical inventory (#128) ────────────────────────────────────────────

func seedNode(t *testing.T, s *storage.Store, id, status string) {
	t.Helper()
	now := time.Now().Unix()
	if err := s.UpsertRelayNode(storage.RelayNode{ID: "u-" + id, RelayID: id, Mode: "pull", Status: status, CreatedAt: now, LastSeen: &now}); err != nil {
		t.Fatal(err)
	}
}

// route declares host as attached to `declaring`, reached through topDown (direct child first).
func route(t *testing.T, s *storage.Store, host, declaring string, topDown ...string) {
	t.Helper()
	if _, err := s.UpsertRelayRoute(host, declaring, topDown); err != nil {
		t.Fatal(err)
	}
}

func getInv(t *testing.T, withAuth func(*http.Request) *http.Request, query string) (int, InventoryResponse) {
	t.Helper()
	req := withAuth(httptest.NewRequest("GET", "/api/inventory"+query, nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)
	var resp InventoryResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v\n%s", err, w.Body.String())
		}
	}
	return w.Code, resp
}

// assertValidAnsibleInventory checks what `ansible-inventory --list` needs: every child group
// exists, no cycle, every group host has hostvars, no group shadows a reserved name.
func assertValidAnsibleInventory(t *testing.T, inv InventoryResponse) {
	t.Helper()
	for _, h := range inv.All.Hosts {
		if _, ok := inv.Meta.Hostvars[h]; !ok {
			t.Errorf("host %q has no hostvars", h)
		}
	}
	for name, g := range inv.Groups {
		if name == "all" || name == "ungrouped" || name == "_meta" {
			t.Errorf("a group clobbers the reserved name %q", name)
		}
		for _, h := range g.Hosts {
			if _, ok := inv.Meta.Hostvars[h]; !ok {
				t.Errorf("group %s lists %q without hostvars", name, h)
			}
		}
		for _, c := range g.Children {
			if _, ok := inv.Groups[c]; !ok {
				t.Errorf("group %s has an undefined child %q", name, c)
			}
		}
	}
	for _, c := range inv.All.Children {
		if _, ok := inv.Groups[c]; !ok {
			t.Errorf("all has an undefined child %q", c)
		}
	}
	// acyclic
	state := map[string]int{}
	var visit func(string) bool
	visit = func(n string) bool {
		if state[n] == 1 {
			return false
		}
		if state[n] == 2 {
			return true
		}
		state[n] = 1
		for _, c := range inv.Groups[n].Children {
			if !visit(c) {
				return false
			}
		}
		state[n] = 2
		return true
	}
	for n := range inv.Groups {
		if !visit(n) {
			t.Fatalf("cycle in the group tree: %+v", inv.Groups)
		}
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func eq(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	g, w := sorted(got), sorted(want)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s = %v, want %v", what, g, w)
	}
}

// The topology of the issue: minion-A/B on dmz1 which hangs under zone2; minion-C on zone2.
func seedIssueTopology(t *testing.T, s *storage.Store) {
	t.Helper()
	seedNode(t, s, "zone2", "connected")
	seedNode(t, s, "dmz1", "connected")
	route(t, s, "minion-A", "dmz1", "zone2", "dmz1")
	route(t, s, "minion-B", "dmz1", "zone2", "dmz1")
	route(t, s, "minion-C", "zone2", "zone2")
}

func TestInventoryHierarchy_GroupsFollowTheRelayChain(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	code, inv := getInv(t, withAuth, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	assertValidAnsibleInventory(t, inv)
	eq(t, "all.children", inv.All.Children, "zone2")
	eq(t, "zone2.hosts", inv.Groups["zone2"].Hosts, "minion-C")
	eq(t, "zone2.children", inv.Groups["zone2"].Children, "dmz1")
	eq(t, "dmz1.hosts", inv.Groups["dmz1"].Hosts, "minion-A", "minion-B")
	eq(t, "dmz1.children", inv.Groups["dmz1"].Children)
	eq(t, "all.hosts (flat view kept)", inv.All.Hosts, "minion-A", "minion-B", "minion-C")

	a := inv.Meta.Hostvars["minion-A"]
	if strings.Join(a.RelayChain, ",") != "dmz1,zone2" || a.NextHop != "zone2" || a.RelayID != "dmz1" || a.AnsibleConnection != "relay" {
		t.Errorf("minion-A hostvars = %+v (relay_chain is origin first, next hop is the direct child)", a)
	}
	c := inv.Meta.Hostvars["minion-C"]
	if strings.Join(c.RelayChain, ",") != "zone2" || c.NextHop != "zone2" {
		t.Errorf("minion-C hostvars = %+v", c)
	}
}

func TestInventoryHierarchy_JSONIsAFlatAnsibleDocument(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	req := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"_meta", "all", "zone2", "dmz1"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("top-level key %q missing: %s", k, w.Body.String())
		}
	}
	if len(doc) != 4 {
		t.Errorf("unexpected top-level keys: %v", doc)
	}
	var meta struct {
		Hostvars map[string]map[string]any `json:"hostvars"`
	}
	_ = json.Unmarshal(doc["_meta"], &meta)
	if _, ok := meta.Hostvars["minion-A"]["secagent_relay_chain"]; !ok {
		t.Error("secagent_relay_chain missing from hostvars")
	}
	if meta.Hostvars["minion-A"]["secagent_next_hop"] != "zone2" {
		t.Errorf("secagent_next_hop = %v", meta.Hostvars["minion-A"]["secagent_next_hop"])
	}
}

func TestInventoryHierarchy_DirectAgentsAndTheNodesOwnGroup(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	if err := s.UpsertAgent(context.Background(), "direct-host", "PUBKEY", "jti-direct"); err != nil {
		t.Fatal(err)
	}

	// standalone root (no REPEATER_ID): a direct agent is in `all` only, relay_chain [], no next hop
	_, inv := getInv(t, withAuth, "")
	d := inv.Meta.Hostvars["direct-host"]
	if d.RelayChain == nil || len(d.RelayChain) != 0 || d.NextHop != "" {
		t.Errorf("direct host hostvars = %+v, want relay_chain [] and no next hop", d)
	}
	eq(t, "all.children (root without id)", inv.All.Children, "zone2")
	for name, g := range inv.Groups {
		for _, h := range g.Hosts {
			if h == "direct-host" {
				t.Errorf("a direct agent must not be placed in the relay group %s", name)
			}
		}
	}
	raw, _ := json.Marshal(d)
	if !strings.Contains(string(raw), `"secagent_relay_chain":[]`) {
		t.Errorf("the empty chain must serialize as [] (not null): %s", raw)
	}

	// with a REPEATER_ID the node has its own group: direct agents + the top-level relays
	ws.SetRelayLocalIDFunc(func() string { return "central" })
	t.Cleanup(func() { ws.SetRelayLocalIDFunc(nil) })
	_, inv = getInv(t, withAuth, "")
	assertValidAnsibleInventory(t, inv)
	eq(t, "all.children", inv.All.Children, "central")
	eq(t, "central.hosts", inv.Groups["central"].Hosts, "direct-host")
	eq(t, "central.children", inv.Groups["central"].Children, "zone2")
}

func TestInventoryHierarchy_DeepChainAndLegacyRow(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	for _, id := range []string{"r1", "r2", "r3", "legacy"} {
		seedNode(t, s, id, "connected")
	}
	route(t, s, "deep", "r3", "r1", "r2", "r3") // 3 levels
	// a row from before #127: empty chain => attached to its declaring relay
	if err := s.BulkUpsertRelayRouting("legacy", []string{"old-host"}); err != nil {
		t.Fatal(err)
	}
	_, inv := getInv(t, withAuth, "")
	assertValidAnsibleInventory(t, inv)
	eq(t, "all.children", inv.All.Children, "r1", "legacy")
	eq(t, "r1.children", inv.Groups["r1"].Children, "r2")
	eq(t, "r2.children", inv.Groups["r2"].Children, "r3")
	eq(t, "r3.hosts", inv.Groups["r3"].Hosts, "deep")
	if hv := inv.Meta.Hostvars["deep"]; strings.Join(hv.RelayChain, ",") != "r3,r2,r1" || hv.NextHop != "r1" {
		t.Errorf("deep hostvars = %+v", hv)
	}
	eq(t, "legacy.hosts", inv.Groups["legacy"].Hosts, "old-host")
	if hv := inv.Meta.Hostvars["old-host"]; hv.NextHop != "legacy" || strings.Join(hv.RelayChain, ",") != "legacy" {
		t.Errorf("old-host hostvars = %+v", hv)
	}
}

func TestInventoryHierarchy_OnlyConnectedUsesTheNextHopStatus(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedNode(t, s, "up", "connected")
	seedNode(t, s, "down", "disconnected")
	seedNode(t, s, "deep", "connected")
	route(t, s, "h-up", "up", "up")
	route(t, s, "h-down", "down", "down")
	route(t, s, "h-behind-down", "deep", "down", "deep") // its declaring relay is fine, the next hop is down
	_, all := getInv(t, withAuth, "")
	eq(t, "all hosts", all.All.Hosts, "h-up", "h-down", "h-behind-down")
	_, conn := getInv(t, withAuth, "?only_connected=true")
	assertValidAnsibleInventory(t, conn)
	eq(t, "only connected", conn.All.Hosts, "h-up")
	eq(t, "groups of the connected inventory", keys(conn.Groups), "up")
}

func keys(m map[string]InventoryGroup) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInventoryHierarchy_ScopedToARelaySubtree(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	seedNode(t, s, "other", "connected")
	route(t, s, "minion-X", "other", "other")
	if err := s.UpsertAgent(context.Background(), "direct-host", "PUBKEY", "jti-direct"); err != nil {
		t.Fatal(err)
	}

	_, dmz1 := getInv(t, withAuth, "?relay=dmz1")
	assertValidAnsibleInventory(t, dmz1)
	eq(t, "relay=dmz1 hosts", dmz1.All.Hosts, "minion-A", "minion-B")
	eq(t, "relay=dmz1 groups", keys(dmz1.Groups), "dmz1")
	eq(t, "relay=dmz1 all.children", dmz1.All.Children, "dmz1")
	if _, ok := dmz1.Meta.Hostvars["minion-C"]; ok {
		t.Error("hostvars of hosts outside the scope must not be disclosed")
	}

	_, zone2 := getInv(t, withAuth, "?relay=zone2")
	assertValidAnsibleInventory(t, zone2)
	eq(t, "relay=zone2 hosts", zone2.All.Hosts, "minion-A", "minion-B", "minion-C")
	eq(t, "relay=zone2 groups", keys(zone2.Groups), "zone2", "dmz1")

	_, none := getInv(t, withAuth, "?relay=nonexistent")
	if len(none.All.Hosts) != 0 || len(none.Groups) != 0 || len(none.Meta.Hostvars) != 0 {
		t.Errorf("an unknown relay scope must be empty: %+v", none)
	}

	for _, bad := range []string{"?relay=a%20b", "?relay=../x", "?relay=x%0Ay", "?relay=" + strings.Repeat("a", 70)} {
		if code, _ := getInv(t, withAuth, bad); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, code)
		}
	}
}

func TestInventoryHierarchy_StaleCyclicRoutesNeverProduceACycle(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedNode(t, s, "a", "connected")
	seedNode(t, s, "b", "connected")
	route(t, s, "h1", "b", "a", "b") // a -> b
	route(t, s, "h2", "a", "b", "a") // b -> a : inconsistent with the row above
	_, inv := getInv(t, withAuth, "")
	assertValidAnsibleInventory(t, inv) // fails on any cycle
	eq(t, "hosts", inv.All.Hosts, "h1", "h2")
}

func TestInventoryHierarchy_ReservedRelayNamesNeverClobberAnsibleGroups(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedNode(t, s, "all", "connected")
	route(t, s, "h", "all", "all")
	_, inv := getInv(t, withAuth, "")
	assertValidAnsibleInventory(t, inv)
	if _, ok := inv.Groups["all"]; ok {
		t.Error("a relay named 'all' must not become a group")
	}
	eq(t, "hosts", inv.All.Hosts, "h")
}

func TestInventoryResponse_GroupsRoundTrip(t *testing.T) {
	in := InventoryResponse{Groups: map[string]InventoryGroup{"dmz1": {Hosts: []string{"a"}}, "zone2": {Children: []string{"dmz1"}}}}
	in.All.Hosts = []string{"a"}
	in.All.Children = []string{"zone2"}
	in.Meta.Hostvars = map[string]HostVars{"a": {AnsibleConnection: "relay", RelayChain: []string{"dmz1", "zone2"}, NextHop: "zone2"}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out InventoryResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Groups) != 2 || out.Groups["zone2"].Children[0] != "dmz1" || out.All.Children[0] != "zone2" ||
		out.Meta.Hostvars["a"].NextHop != "zone2" {
		t.Errorf("round trip lost data: %+v", out)
	}
}

func TestInventoryHierarchy_AdminEndpointServesTheSameHierarchy(t *testing.T) {
	s, _ := setupProxyTest(t)
	seedIssueTopology(t, s)
	w := httptest.NewRecorder()
	AdminGetInventory(w, adminReq("GET", "/api/inventory?relay=dmz1", nil))
	var inv InventoryResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &inv) != nil {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	eq(t, "admin scoped hosts", inv.All.Hosts, "minion-A", "minion-B")
}

// ── group vars per relay group (#139) ────────────────────────────────────────

func setStoredVars(t *testing.T, s *storage.Store, relayID, json string) {
	t.Helper()
	if ok, err := s.SetRelayGroupVars(relayID, json); err != nil || !ok {
		t.Fatalf("SetRelayGroupVars(%s): %v %v", relayID, ok, err)
	}
}

func TestInventoryGroupVars_PublishedPerRelayGroup(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	setStoredVars(t, s, "dmz1", `{"env":"staging","datacenter":"paris","replicas":3,"ansible_python_interpreter":"/usr/bin/python3"}`)

	req := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var dmz1 struct {
		Hosts []string                   `json:"hosts"`
		Vars  map[string]json.RawMessage `json:"vars"`
	}
	if err := json.Unmarshal(doc["dmz1"], &dmz1); err != nil {
		t.Fatal(err)
	}
	if string(dmz1.Vars["env"]) != `"staging"` || string(dmz1.Vars["replicas"]) != `3` ||
		string(dmz1.Vars["ansible_python_interpreter"]) != `"/usr/bin/python3"` {
		t.Errorf("dmz1 vars = %v (JSON types must be preserved)", dmz1.Vars)
	}
	// a relay without vars has no "vars" key at all
	if strings.Contains(string(doc["zone2"]), `"vars"`) {
		t.Errorf("zone2 has no group vars but the group carries a vars key: %s", doc["zone2"])
	}
}

func TestInventoryGroupVars_NodesOwnVarsServedInItsOwnGroup(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	ws.SetRelayLocalIDFunc(func() string { return "central" })
	SetLocalGroupVars(map[string]any{"env": "prod"})
	t.Cleanup(func() { ws.SetRelayLocalIDFunc(nil); SetLocalGroupVars(nil) })
	_, inv := getInv(t, withAuth, "")
	if string(inv.Groups["central"].Vars["env"]) != `"prod"` {
		t.Errorf("central vars = %v", inv.Groups["central"].Vars)
	}
	// a node without REPEATER_ID has no group of its own: its vars are not published anywhere
	ws.SetRelayLocalIDFunc(nil)
	_, inv = getInv(t, withAuth, "")
	if _, ok := inv.Groups["central"]; ok {
		t.Error("no own group without REPEATER_ID")
	}
}

// Whatever the database holds, only validated vars are served: a corrupted row, or one that
// predates the validation rules, is ignored (the controller must never receive a template).
func TestInventoryGroupVars_InvalidStoredVarsAreNeverServed(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	setStoredVars(t, s, "dmz1", `{"x":"{{ lookup('pipe','id') }}"}`)
	setStoredVars(t, s, "zone2", `{"ansible_connection":"local"}`)
	req := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)
	if strings.Contains(w.Body.String(), "lookup") || strings.Contains(w.Body.String(), "ansible_connection\":\"local") {
		t.Errorf("an invalid stored var reached the inventory:\n%s", w.Body.String())
	}
	_, inv := getInv(t, withAuth, "")
	if len(inv.Groups["dmz1"].Vars) != 0 || len(inv.Groups["zone2"].Vars) != 0 {
		t.Errorf("vars = %v / %v", inv.Groups["dmz1"].Vars, inv.Groups["zone2"].Vars)
	}
}

func TestInventoryGroupVars_ScopeKeepsOnlyVisibleGroupsVars(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedIssueTopology(t, s)
	setStoredVars(t, s, "dmz1", `{"env":"staging"}`)
	setStoredVars(t, s, "zone2", `{"secret_region":"eu"}`)
	_, scoped := getInv(t, withAuth, "?relay=dmz1")
	if _, ok := scoped.Groups["zone2"]; ok {
		t.Error("the parent group must not be part of a subtree scope")
	}
	if string(scoped.Groups["dmz1"].Vars["env"]) != `"staging"` {
		t.Errorf("dmz1 vars = %v", scoped.Groups["dmz1"].Vars)
	}
}
