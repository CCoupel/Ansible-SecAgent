package server

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
)

func chainsOfSnapshot(t *testing.T, selfID string, st *storage.Store) (relays map[string][]string, agents map[string][]string) {
	t.Helper()
	snap := buildSnapshot(selfID, st)
	relays, agents = map[string][]string{}, map[string][]string{}
	for _, r := range snap.Relays {
		relays[r.RelayID] = r.RelayChain
	}
	for _, a := range snap.Agents {
		agents[a.Hostname] = a.RelayChain
	}
	return relays, agents
}

// The snapshot must publish the REAL path to each relay below the node (and to its hosts), at any
// depth: it used to declare every relay as a direct child ([self, relay]), which flattened the
// tree at the ancestors (wrong inventory, wrong scope, wrong event chain validation).
func TestBuildSnapshot_KeepsTheRealChainsAtDepth(t *testing.T) {
	st, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		if err := st.UpsertRelayNode(storage.RelayNode{ID: "id-" + id, RelayID: id, Mode: "pull", Status: "connected"}); err != nil {
			t.Fatal(err)
		}
	}
	// what this node learned from its direct child r1: r2 below r1, r3 below r2, r4 below r3
	for id, chain := range map[string][]string{
		"r1": {"r1"}, "r2": {"r1", "r2"}, "r3": {"r1", "r2", "r3"}, "r4": {"r1", "r2", "r3", "r4"},
	} {
		if _, err := st.SetRelayChain(id, chain); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.BulkUpsertRelayRouting("r3", []string{"deep-host"}); err != nil {
		t.Fatal(err)
	}
	if err := st.BulkUpsertRelayRouting("r1", []string{"near-host"}); err != nil {
		t.Fatal(err)
	}

	relays, agents := chainsOfSnapshot(t, "n0", st)
	wantRelays := map[string][]string{
		"r1": {"n0", "r1"},
		"r2": {"n0", "r1", "r2"},
		"r3": {"n0", "r1", "r2", "r3"},
		"r4": {"n0", "r1", "r2", "r3", "r4"},
	}
	if !reflect.DeepEqual(relays, wantRelays) {
		t.Errorf("relay chains = %v, want %v", relays, wantRelays)
	}
	wantAgents := map[string][]string{
		"deep-host": {"n0", "r1", "r2", "r3"},
		"near-host": {"n0", "r1"},
	}
	if !reflect.DeepEqual(agents, wantAgents) {
		t.Errorf("agent chains = %v, want %v", agents, wantAgents)
	}
}

// A relay without a stored path (direct child, never seen below another relay) is a direct child;
// an inconsistent stored path (not ending at the relay) is ignored rather than published.
func TestBuildSnapshot_DirectChildAndInconsistentChain(t *testing.T) {
	st, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, id := range []string{"direct", "odd"} {
		if err := st.UpsertRelayNode(storage.RelayNode{ID: "id-" + id, RelayID: id, Mode: "pull", Status: "connected"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.SetRelayChain("odd", []string{"a", "b"}); err != nil { // does not end at "odd"
		t.Fatal(err)
	}
	relays, _ := chainsOfSnapshot(t, "n0", st)
	if !reflect.DeepEqual(relays["direct"], []string{"n0", "direct"}) || !reflect.DeepEqual(relays["odd"], []string{"n0", "odd"}) {
		t.Errorf("chains = %v", relays)
	}
}

// ── 4 levels on REAL nodes ───────────────────────────────────────────────────

// Root ← r1 ← r2 ← r3: the inventory keeps the full chain and the nested groups, a scope on the
// INTERMEDIATE relay r2 is not empty, and an event from r3 is accepted with the chain [r3,r2,r1].
func TestInventory_FourLevelsKeepTheFullChain(t *testing.T) {
	_, api, admin, wsAddr := startNode(t, nil)
	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{"role": "plugin", "description": "inv"})
	if code != http.StatusCreated {
		t.Fatalf("plugin token: %d %s", code, body)
	}
	var pt struct{ Token string }
	_ = json.Unmarshal(body, &pt)

	token, _ := registerRelay(t, admin, "r1")
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
	send(map[string]any{"type": "relay_hello", "relay_id": "r1", "version": "3.0"})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var m map[string]any
	if err := c.ReadJSON(&m); err != nil {
		t.Fatal(err)
	}
	send(map[string]any{"type": "topology_snapshot",
		"relays": []any{
			map[string]any{"relay_id": "r2", "relay_chain": []string{"r1", "r2"}},
			map[string]any{"relay_id": "r3", "relay_chain": []string{"r1", "r2", "r3"}}},
		"agents": []any{map[string]any{"hostname": "deep-host", "relay_id": "r3", "relay_chain": []string{"r1", "r2", "r3"}}}})
	if err := c.ReadJSON(&m); err != nil || m["type"] != "topology_ack" {
		t.Fatalf("snapshot: %v %v", m, err)
	}
	send(map[string]any{"type": "event_forward", "event": "host.up", "hostname": "late-host", "status": "connected",
		"relay_chain": []string{"r3", "r2", "r1"}})

	get := func(addr, path, token string) map[string]json.RawMessage {
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
		return doc
	}
	var doc map[string]json.RawMessage
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		doc = get(api, "/api/inventory", pt.Token)
		if strings.Contains(string(doc["all"]), "late-host") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var meta struct {
		Hostvars map[string]struct {
			Chain   []string `json:"secagent_relay_chain"`
			NextHop string   `json:"secagent_next_hop"`
		} `json:"hostvars"`
	}
	_ = json.Unmarshal(doc["_meta"], &meta)
	for host, want := range map[string]string{"deep-host": "r3,r2,r1", "late-host": "r3,r2,r1"} {
		hv := meta.Hostvars[host]
		if strings.Join(hv.Chain, ",") != want || hv.NextHop != "r1" {
			t.Errorf("%s: chain %v next hop %q, want %s via r1 (the tree must not be flattened)", host, hv.Chain, hv.NextHop, want)
		}
	}
	type grp struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}
	var r1, r2, r3 grp
	_ = json.Unmarshal(doc["r1"], &r1)
	_ = json.Unmarshal(doc["r2"], &r2)
	_ = json.Unmarshal(doc["r3"], &r3)
	if len(r1.Children) != 1 || r1.Children[0] != "r2" || len(r2.Children) != 1 || r2.Children[0] != "r3" || len(r3.Hosts) != 2 {
		t.Errorf("groups r1=%+v r2=%+v r3=%+v, want r1 ⊃ r2 ⊃ r3 holding the 2 deep hosts", r1, r2, r3)
	}
	// a scope on the intermediate relay is not empty
	scoped := get(admin, "/api/inventory?relay=r2", testAdminToken)
	var sc grp
	_ = json.Unmarshal(scoped["all"], &sc)
	if len(sc.Hosts) != 2 {
		t.Errorf("relay=r2 scope = %+v, want the 2 hosts below r2", sc)
	}
}

// A node in the MIDDLE (r1) publishes to its parent the real chains of what is below its child:
// parent ← r1 ← r2 ← r3, r3 learned through r2 (the flattening bug declared r3 a child of r1).
func TestResnapshot_MiddleNodePublishesTheRealChains(t *testing.T) {
	t.Setenv("REPEATER_ID", "r1")
	_, _, admin, wsAddr := startNode(t, func(c *Config) {
		c.Tune = func(o *repeater.Options, _ *repeater.DialerOptions) {
			o.TopologyDebounce, o.TopologyMinGap = 20*time.Millisecond, 50*time.Millisecond
		}
	})
	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{
		"role": "relay-parent", "sub": "central", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, body)
	}
	var tok struct{ Token string }
	_ = json.Unmarshal(body, &tok)
	parent, _, err := dialRelayWS(wsAddr, tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	if err := parent.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	readSnapshot(t, parent, "the first snapshot")

	token, _ := registerRelay(t, admin, "r2")
	child, _, err := dialRelayWS(wsAddr, token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Close() }()
	if err := child.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "r2", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	_ = child.SetReadDeadline(time.Now().Add(5 * time.Second))
	var m map[string]any
	if err := child.ReadJSON(&m); err != nil || m["type"] != "relay_ack" {
		t.Fatalf("ack: %v %v", m, err)
	}
	if err := child.WriteJSON(map[string]any{"type": "topology_snapshot",
		"relays": []any{map[string]any{"relay_id": "r3", "relay_chain": []string{"r2", "r3"}}},
		"agents": []any{map[string]any{"hostname": "deep-host", "relay_id": "r3", "relay_chain": []string{"r2", "r3"}}}}); err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	for i := 0; i < 5; i++ {
		snap = readSnapshot(t, parent, "the snapshot with r3")
		if snapshotHas(snap, "relays", "relay_id", "r3") {
			break
		}
	}
	chainOfEntry := func(key, field, id string) string {
		items, _ := snap[key].([]any)
		for _, it := range items {
			e, _ := it.(map[string]any)
			if e != nil && e[field] == id {
				var parts []string
				for _, v := range e["relay_chain"].([]any) {
					parts = append(parts, v.(string))
				}
				return strings.Join(parts, ",")
			}
		}
		return "<absent>"
	}
	for _, c := range []struct{ key, field, id, want string }{
		{"relays", "relay_id", "r2", "r1,r2"},
		{"relays", "relay_id", "r3", "r1,r2,r3"},
		{"agents", "hostname", "deep-host", "r1,r2,r3"},
	} {
		if got := chainOfEntry(c.key, c.field, c.id); got != c.want {
			t.Errorf("%s %s chain = %s, want %s", c.key, c.id, got, c.want)
		}
	}
}
