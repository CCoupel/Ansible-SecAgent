package integration

// Ansible group vars per relay (#139 / #137 scenario 4) on real nodes: RELAY_GROUP_VARS reaches the
// root's inventory through hello, snapshot and relay.updated, exactly and with its JSON types;
// hostile values are refused everywhere and never logged; a relay can only speak for its own group.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// groupVarsOf returns, per relay group, the vars the root's /api/inventory publishes for it.
func groupVarsOf(t *testing.T, n *node) map[string]map[string]any {
	t.Helper()
	code, raw := n.call("GET", "/api/inventory", n.pluginToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("inventory on %s: %d %s", n.id, code, raw)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for k, v := range doc {
		if k == "_meta" || k == "all" {
			continue
		}
		var g struct {
			Vars map[string]any `json:"vars"`
		}
		if err := json.Unmarshal(v, &g); err != nil {
			t.Fatalf("group %q: %v", k, err)
		}
		if len(g.Vars) > 0 {
			out[k] = g.Vars
		}
	}
	return out
}

func varsJSON(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// (a) vars published by hello (pull relay), by snapshot (push relay, late sub-relay), updated on a
// restart, with their JSON types kept (string, number, list, object, bool).
func TestGroupVars_ArePublishedExactlyKeepTheirTypesAndFollowChanges(t *testing.T) {
	parallel(t)
	pVars := map[string]any{"env": "staging", "datacenter": "paris", "attempts": float64(3), "labels": []any{"a", "b"}, "opts": map[string]any{"fast": true}}
	root := startNode(t, nodeSpec{ID: "root", Env: []string{`RELAY_GROUP_VARS={"role":"top"}`}})
	p := startNode(t, nodeSpec{ID: "relayP", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayP"), Env: []string{"RELAY_GROUP_VARS=" + varsJSON(pVars)}})
	waitFor(t, "relayP linked", func() bool { return p.upstreamState() == "connected" })
	q := startNode(t, nodeSpec{ID: "relayQ", Env: []string{`RELAY_GROUP_VARS={"env":"prod","tier":2}`}}) // push child, started BEFORE the link
	linkPush(t, root, q)
	// a sub-relay that joins AFTER the link above it: its vars reach the root through the re-snapshot
	sub := startNode(t, nodeSpec{ID: "sub", ParentURL: p.wssURL(), ParentToken: p.registerChild("sub"), Env: []string{`RELAY_GROUP_VARS={"env":"sub","extra":"x"}`}})
	waitFor(t, "sub linked", func() bool { return sub.upstreamState() == "connected" })
	connectMinion(t, p, "a-p")
	connectMinion(t, q, "a-q")
	connectMinion(t, sub, "a-sub")
	waitFor(t, "the root's inventory carries every group's vars", func() bool {
		g := groupVarsOf(t, root)
		return len(g["relayP"]) > 0 && len(g["relayQ"]) > 0 && len(g["sub"]) > 0 && len(g["root"]) > 0
	})
	want := map[string]map[string]any{
		"relayP": pVars,
		"relayQ": {"env": "prod", "tier": float64(2)},
		"sub":    {"env": "sub", "extra": "x"},
		"root":   {"role": "top"},
	}
	if got := groupVarsOf(t, root); !reflect.DeepEqual(got, want) {
		t.Fatalf("group vars at the root:\n got  %v\n want %v", got, want)
	}

	// the relay changes its vars (restart with a new RELAY_GROUP_VARS: a new hello): the inventory follows,
	// old keys included
	p.setEnv("RELAY_GROUP_VARS", `{"env":"dev"}`)
	p.restart()
	waitFor(t, "relayP linked again", func() bool { return p.upstreamState() == "connected" })
	waitFor(t, "the root published the NEW vars of relayP (and nothing of the old ones)", func() bool {
		return reflect.DeepEqual(groupVarsOf(t, root)["relayP"], map[string]any{"env": "dev"})
	})
	// and the other groups did not move
	got := groupVarsOf(t, root)
	for _, g := range []string{"relayQ", "root"} {
		if !reflect.DeepEqual(got[g], want[g]) {
			t.Errorf("group %s changed with relayP's restart: %v", g, got[g])
		}
	}
}

// A relay REMOVED from the subtree takes its vars with it.
func TestGroupVars_DisappearWithTheirRelay(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	tok, rowID := root.registerChildWithID("relayP")
	p := startNode(t, nodeSpec{ID: "relayP", ParentURL: root.wssURL(), ParentToken: tok, Env: []string{`RELAY_GROUP_VARS={"env":"staging"}`}})
	waitFor(t, "relayP linked", func() bool { return p.upstreamState() == "connected" })
	connectMinion(t, p, "a-p")
	waitFor(t, "the vars are published", func() bool { return len(groupVarsOf(t, root)["relayP"]) == 1 })

	if code, m := root.admin("DELETE", "/api/admin/relays/"+rowID, nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("delete the relay: %d %v", code, m)
	}
	waitFor(t, "the removed relay's vars are gone from the inventory", func() bool { _, has := groupVarsOf(t, root)["relayP"]; return !has })
	if strings.Contains(inventoryRaw(root), "staging") {
		t.Errorf("the removed relay's vars are still served:\n%s", inventoryRaw(root))
	}
	// the inventory omits a group that holds no host, so also look where the vars are KEPT: the
	// removed relay's entry, with its stored vars, must be gone from the root's state file
	for id, nd := range root.stateSection("relay_nodes") {
		if id == "relayP" || nd["group_vars"] != nil {
			t.Errorf("the removed relay's stored group vars are still in the state: %s %v", id, nd)
		}
	}
}

// ── hostile vars ─────────────────────────────────────────────────────────────

const secretMarker = "S3cr3t-VALUE-must-never-be-logged"

// badGroupVars are values the validation must refuse, whichever way they arrive.
func badGroupVars() map[string]map[string]any {
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": secretMarker}}}}}
	return map[string]map[string]any{
		"ansible_connection":      {"ansible_connection": "local"},
		"ansible_become_pass":     {"ansible_become_pass": secretMarker},
		"ansible_ssh_common_args": {"ansible_ssh_common_args": "-o ProxyCommand=" + secretMarker},
		"secagent_ namespace":     {"secagent_relay_chain": []any{secretMarker}},
		"python interpreter ..":   {"ansible_python_interpreter": "/usr/bin/../../tmp/" + secretMarker},
		"jinja expression":        {"x": "{{ lookup('pipe','id') }} " + secretMarker},
		"jinja statement":         {"x": "{% for i in range(9) %}" + secretMarker},
		"jinja comment":           {"x": "{# " + secretMarker},
		"too deep":                {"deep": deep},
		"oversized string":        {"big": strings.Repeat("x", 2048) + secretMarker},
		"too many bytes":          {"a": strings.Repeat("y", 1000), "b": strings.Repeat("y", 1000), "c": strings.Repeat("y", 1000), "d": strings.Repeat("y", 1000), "e": strings.Repeat("y", 1000), "f": strings.Repeat("y", 1000), "g": strings.Repeat("y", 1000), "h": strings.Repeat("y", 1000), "i": strings.Repeat("y", 1000), "j": strings.Repeat("y", 1000), "k": strings.Repeat("y", 1000), "l": strings.Repeat("y", 1000), "m": strings.Repeat("y", 1000), "n": strings.Repeat("y", 1000), "o": strings.Repeat("y", 1000), "p": strings.Repeat("y", 1000), "q": strings.Repeat("y", 1000), "z": secretMarker},
		"invalid variable name":   {"bad name": secretMarker},
		"control character":       {"x": "a\u0007" + secretMarker},
	}
}

// The configuration itself is refused: the server does not even start, and the value is never printed.
func TestGroupVars_ForbiddenConfigurationRefusesToStart(t *testing.T) {
	parallel(t)
	for name, vars := range badGroupVars() {
		t.Run(name, func(t *testing.T) {
			n := prepareNode(t, nodeSpec{ID: "bad", Env: []string{"RELAY_GROUP_VARS=" + varsJSON(vars)}})
			code, out := n.runExpectingExit()
			if code == 0 || code == -1 {
				t.Fatalf("the server must refuse to start with these group vars (exit %d):\n%s", code, out)
			}
			if !strings.Contains(out, "RELAY_GROUP_VARS") {
				t.Errorf("the refusal must name RELAY_GROUP_VARS:\n%s", out)
			}
			if strings.Contains(out, secretMarker) || strings.Contains(out, "lookup(") {
				t.Errorf("the refused value was printed:\n%s", out)
			}
		})
	}
}

// Over the wire, a hostile payload is refused whichever message carries it (hello, replacement
// snapshot, relay.updated): nothing reaches the inventory, the value is never logged, and the vars
// that were published stay.
func TestGroupVars_HostilePayloadsAreRefusedOnTheWire(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	good := startNode(t, nodeSpec{ID: "good", ParentURL: root.wssURL(), ParentToken: root.registerChild("good"), Env: []string{`RELAY_GROUP_VARS={"env":"legit"}`}})
	waitFor(t, "good linked", func() bool { return good.upstreamState() == "connected" })
	connectMinion(t, good, "a-good") // a relay group only exists in the inventory once it holds a host
	waitFor(t, "good's vars published", func() bool { return len(groupVarsOf(t, root)["good"]) == 1 })

	i := 0
	for name, vars := range badGroupVars() {
		i++
		id := fmt.Sprintf("evil%d", i)
		t.Run("hello/"+name, func(t *testing.T) {
			tok := root.registerChild(id)
			h := http.Header{}
			h.Set("Authorization", "Bearer "+tok)
			d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
			conn, _, err := d.Dial(root.wssURL()+"/ws/relay", h)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": id, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}, "group_vars": vars}); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			for {
				var m map[string]any
				if err := conn.ReadJSON(&m); err != nil {
					if ce, ok := err.(*websocket.CloseError); !ok || ce.Code != 4012 {
						t.Fatalf("a hello with hostile group vars must end with a 4012 close, got %v", err)
					}
					break
				}
			}
			if _, has := groupVarsOf(t, root)[id]; has {
				t.Errorf("hostile vars of %s reached the inventory", id)
			}
		})
		t.Run("snapshot/"+name, func(t *testing.T) {
			f := newFakeChild(t, root, id+"s")
			f.snapshot([]map[string]any{{"relay_id": id + "sub", "relay_chain": []string{id + "s", id + "sub"}, "group_vars": vars}},
				[]map[string]any{{"hostname": "h-" + id, "relay_id": id + "sub", "relay_chain": []string{id + "s", id + "sub"}}})
			if code := f.waitClosed(); code != 4012 {
				t.Fatalf("a snapshot with hostile group vars must end with a 4012 close, got %d", code)
			}
			if _, has := groupVarsOf(t, root)[id+"sub"]; has {
				t.Error("hostile vars of a declared sub-relay reached the inventory")
			}
		})
		t.Run("relay.updated/"+name, func(t *testing.T) {
			f := newFakeChild(t, root, id+"u")
			f.snapshot([]map[string]any{{"relay_id": id + "usub", "relay_chain": []string{id + "u", id + "usub"}}},
				[]map[string]any{{"hostname": "hu-" + id, "relay_id": id + "usub", "relay_chain": []string{id + "u", id + "usub"}}})
			waitFor(t, "the sub-relay is declared", func() bool { return root.hasHost("hu-" + id) })
			f.send(map[string]any{"type": "event_forward", "event": "relay.updated", "relay_id": id + "usub",
				"relay_chain": []string{id + "usub", id + "u"}, "group_vars": vars})
			// a valid update after it proves the pipeline is alive and in order
			f.send(map[string]any{"type": "event_forward", "event": "relay.updated", "relay_id": id + "usub",
				"relay_chain": []string{id + "usub", id + "u"}, "group_vars": map[string]any{"ok": "yes"}})
			waitFor(t, "the valid update that follows is applied", func() bool {
				return reflect.DeepEqual(groupVarsOf(t, root)[id+"usub"], map[string]any{"ok": "yes"})
			})
			select {
			case err := <-f.closed:
				t.Errorf("a refused relay.updated must not cost the link: %v", err)
			default:
			}
		})
	}
	if got := groupVarsOf(t, root)["good"]; !reflect.DeepEqual(got, map[string]any{"env": "legit"}) {
		t.Errorf("the legitimate relay's vars were disturbed: %v", got)
	}
	logs := root.logs.String()
	if strings.Contains(logs, secretMarker) || strings.Contains(logs, "lookup('pipe'") || strings.Contains(logs, "ProxyCommand") {
		t.Errorf("a refused value was logged:\n%s", logs)
	}
}

// A relay speaks for ITS OWN group only (and the groups below it that it declares): not for a
// sibling, its parent, the "all" group nor a relay it does not declare.
func TestGroupVars_ARelayCannotSpeakForAnotherGroup(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Env: []string{`RELAY_GROUP_VARS={"owner":"root"}`}})
	sib := startNode(t, nodeSpec{ID: "sibling", ParentURL: root.wssURL(), ParentToken: root.registerChild("sibling"), Env: []string{`RELAY_GROUP_VARS={"owner":"sibling"}`}})
	waitFor(t, "sibling linked", func() bool { return sib.upstreamState() == "connected" })
	connectMinion(t, sib, "a-sibling")
	waitFor(t, "sibling's vars published", func() bool { return len(groupVarsOf(t, root)["sibling"]) == 1 })
	f := newFakeChild(t, root, "attacker")
	f.snapshot([]map[string]any{{"relay_id": "mine", "relay_chain": []string{"attacker", "mine"}}},
		[]map[string]any{{"hostname": "h-mine", "relay_id": "mine", "relay_chain": []string{"attacker", "mine"}}})
	waitFor(t, "its sub-relay is declared", func() bool { return root.hasHost("h-mine") })
	f.send(map[string]any{"type": "event_forward", "event": "relay.updated", "relay_id": "mine", "relay_chain": []string{"mine", "attacker"}, "group_vars": map[string]any{"owner": "attacker-sub"}})
	waitFor(t, "its own declared sub-relay may be described", func() bool {
		return reflect.DeepEqual(groupVarsOf(t, root)["mine"], map[string]any{"owner": "attacker-sub"})
	})

	for _, target := range []string{"sibling", "root", "all", "ungrouped", "unknown-relay"} {
		before := root.logs.count("relay.updated refused")
		f.send(map[string]any{"type": "event_forward", "event": "relay.updated", "relay_id": target,
			"relay_chain": []string{target, "attacker"}, "group_vars": map[string]any{"owner": "HIJACKED"}})
		waitFor(t, "the update for "+target+" is refused", func() bool {
			return root.logs.count("relay.updated refused") > before || root.logs.has("event_forward rejected")
		})
	}
	// the attacker's own group is the only one that changed
	got := groupVarsOf(t, root)
	if !reflect.DeepEqual(got["sibling"], map[string]any{"owner": "sibling"}) {
		t.Errorf("a sibling's vars were overwritten: %v", got["sibling"])
	}
	if !reflect.DeepEqual(got["root"], map[string]any{"owner": "root"}) {
		t.Errorf("the parent's own vars were overwritten: %v", got["root"])
	}
	for _, g := range []string{"all", "ungrouped", "unknown-relay"} {
		if v, has := got[g]; has {
			t.Errorf("group %q must not get vars from a child relay: %v", g, v)
		}
	}
	if strings.Contains(inventoryRaw(root), "HIJACKED") {
		t.Errorf("hijacked vars reached the inventory:\n%s", inventoryRaw(root))
	}
	select {
	case err := <-f.closed:
		t.Logf("the attacker's link ended: %v", err)
	default:
	}

	// a SNAPSHOT may not carry vars for a relay named like Ansible's group "all" either
	g := newFakeChild(t, root, "attacker2")
	g.snapshot([]map[string]any{{"relay_id": "all", "relay_chain": []string{"attacker2", "all"}, "group_vars": map[string]any{"owner": "HIJACKED-ALL"}}},
		[]map[string]any{{"hostname": "h-all", "relay_id": "all", "relay_chain": []string{"attacker2", "all"}}})
	waitFor(t, "the snapshot with a relay named all was handled", func() bool {
		return root.logs.count("topology_snapshot: relay_id=attacker2") >= 2 || func() bool {
			select {
			case <-g.closed:
				return true
			default:
				return false
			}
		}()
	})
	if strings.Contains(inventoryRaw(root), "HIJACKED-ALL") {
		t.Errorf("a child relay declared a relay named \"all\" and published vars into Ansible's all group:\n%s", inventoryRaw(root))
	}
}
