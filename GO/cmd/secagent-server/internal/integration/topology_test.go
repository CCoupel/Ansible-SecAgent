package integration

// Dynamic topology (#126 follow-up): a relay that joins or leaves below an already-linked relay is
// announced upwards by a full replacement topology_snapshot; the parent applies it atomically,
// refuses a hostile one without losing its other state, and rate-limits the replacements.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A relay that joins AFTER the link above it was established makes its parent re-send a full
// snapshot: the ancestors learn it, so the host.up of its agents is accepted, runs the hooks with
// the chain [relay2, relay1] and routes the deep host — and relay1's link is never recreated.
func TestTopology_LateJoiningRelay_DeepHostIsRoutableFromItsHostUp(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Hooks: standardHooks})
	waitFor(t, "relay1 linked to the root", func() bool { return relay1.upstreamState() == "connected" })
	waitFor(t, "the first snapshot reached the root", func() bool { return root.logs.count("topology_snapshot: relay_id=relay1") >= 1 })
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2"), Hooks: standardHooks})
	waitFor(t, "relay2 linked to relay1", func() bool { return relay2.upstreamState() == "connected" })
	// relay1 re-sends a full snapshot that declares relay2 (a REPLACEMENT of the first one)
	waitFor(t, "the root accepted a replacement snapshot", func() bool { return root.logs.count("topology_snapshot: relay_id=relay1") >= 2 })

	connectMinion(t, relay2, "late-deep")
	waitFor(t, "the root routes the late relay's host", func() bool { return root.hasHost("late-deep") })
	waitFor(t, "the root's hook ran with the full chain", func() bool {
		return root.hookHas("UP late-deep status=connected chain=relay2,relay1 origin=relay2")
	})
	if n := root.logs.count("Relay connected: relay_id=relay1"); n != 1 {
		t.Errorf("relay1 reconnected %d times: the late relay must be learned without cutting any link", n)
	}
	if r := root.exec("late-deep", execBody("whoami")); r.Code != http.StatusOK {
		t.Errorf("exec through the route learned from the late relay = %d %v", r.Code, r.Body)
	}
	assertNoSecrets(t, allLogs(root, relay1, relay2), nodeSecrets(root, relay1, relay2)...)
}

// A relay that unlinks: its hosts are no longer routable at any ancestor, their routes are cleaned
// up (ownership released), and when the relay comes back its hosts are routable again.
func TestTopology_UnlinkingRelay_HostsAreNoLongerRoutableAndRelinkRoutesAgain(t *testing.T) {
	parallel(t)
	root, mid, leaf := pushChain(t)
	connectMinion(t, leaf, "leaf-host")
	waitFor(t, "root routes the leaf's host", func() bool { return root.hasHost("leaf-host") })

	leaf.stop() // the leaf relay goes away
	waitFor(t, "mid no longer routes the leaf's host", func() bool { return !mid.hasHost("leaf-host") })
	waitFor(t, "root drops the unlinked relay's hosts", func() bool { return !root.hasHost("leaf-host") })
	if r := root.exec("leaf-host", execBody("id")); r.Code == http.StatusOK {
		t.Errorf("exec on a host whose relay is gone must fail, got %v", r)
	}

	// the relay comes back (a new process, re-registered) with its agent
	leaf2 := startNode(t, nodeSpec{ID: "leaf", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leaf"), Hooks: standardHooks})
	waitFor(t, "the relay is linked again", func() bool { return leaf2.upstreamState() == "connected" })
	waitFor(t, "mid learns the relay again", func() bool { return mid.logs.count("topology_snapshot: relay_id=leaf") >= 2 })
	m := connectMinion(t, leaf2, "leaf-host")
	waitFor(t, "root routes the host again", func() bool { return root.hasHost("leaf-host") })
	if r := root.exec("leaf-host", execBody("id")); r.Code != http.StatusOK || len(m.received()) != 1 {
		t.Errorf("exec after the relay came back = %d %v", r.Code, r.Body)
	}
}

// A replacement snapshot that is invalid (hostile id, loop, duplicate, claim of someone else's
// host) is refused: the link is closed with the correctable code 4012, nothing hostile lands, and
// the state of the OTHER peers is untouched.
func TestTopology_InvalidReplacementSnapshotIsRefusedWithoutLosingOtherState(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	other := startNode(t, nodeSpec{ID: "other", ParentURL: root.wssURL(), ParentToken: root.registerChild("other")})
	waitFor(t, "other linked", func() bool { return other.upstreamState() == "connected" })
	o1 := connectMinion(t, other, "o1")
	waitFor(t, "root routes o1 via other", func() bool { return root.hasHost("o1") })

	pwned := filepath.Join(t.TempDir(), "pwned") // a command injected through a hostname would create it
	rel := func(id string, chain ...string) map[string]any {
		return map[string]any{"relay_id": id, "relay_chain": chain}
	}
	agent := func(host, relay string, chain ...string) map[string]any {
		return map[string]any{"hostname": host, "relay_id": relay, "relay_chain": chain}
	}
	// a peer that legitimately owns the relay "owned-sub" for the whole test
	owner := newFakeChild(t, root, "owner")
	owner.snapshot([]map[string]any{rel("owned-sub", "owner", "owned-sub")}, nil)
	waitFor(t, "the owner's replacement snapshot is applied", func() bool { return root.logs.count("topology_snapshot: relay_id=owner") >= 2 })

	attacks := []struct {
		name     string
		relays   []map[string]any
		agents   []map[string]any
		hostile  string // a host or relay that must never appear
		hostFrom string
	}{
		{"hostile relay id", []map[string]any{rel("sub;rm -rf /", "F", "sub;rm -rf /")}, nil, "sub;rm", ""},
		{"hostile hostname", []map[string]any{rel("sub", "F", "sub")}, []map[string]any{agent("h;touch "+pwned, "sub", "F", "sub")}, "touch", ""},
		{"chain through the receiver (loop)", []map[string]any{rel("sub", "F", "root", "sub")}, nil, "sub", ""},
		{"duplicate relay declaration", []map[string]any{rel("sub", "F", "sub"), rel("sub", "F", "sub")}, nil, "sub", ""},
		{"re-declaration of a relay owned by another peer", []map[string]any{rel("owned-sub", "F", "owned-sub")}, nil, "", ""},
		{"claim of a host owned by another peer", []map[string]any{rel("sub", "F", "sub")}, []map[string]any{agent("o1", "sub", "F", "sub")}, "", "o1"},
	}
	for i, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			id := fmt.Sprintf("F%d", i)
			fix := func(l []map[string]any) []map[string]any { // rename the placeholder "F" to this attacker
				var out []map[string]any
				for _, m := range l {
					c := map[string]any{}
					for k, v := range m {
						c[k] = v
					}
					if ch, ok := m["relay_chain"].([]string); ok {
						n := make([]string, len(ch))
						for j, e := range ch {
							n[j] = strings.ReplaceAll(e, "F", id)
						}
						c["relay_chain"] = n
					}
					out = append(out, c)
				}
				return out
			}
			f := newFakeChild(t, root, id) // a valid, empty first snapshot
			f.snapshot(fix(a.relays), fix(a.agents))
			if code := f.waitClosed(); code != 4012 {
				t.Fatalf("the refused snapshot must close the link with 4012, got %d", code)
			}
			if a.hostile != "" && strings.Contains(inventoryRaw(root), a.hostile) {
				t.Errorf("hostile data %q reached the root's inventory", a.hostile)
			}
			// the state of the other peer is intact
			if !root.hasHost("o1") {
				t.Error("another peer's host was lost by the refusal")
			}
			if r := root.exec("o1", execBody("id")); r.Code != http.StatusOK {
				t.Errorf("another peer's host stopped working: %d %v", r.Code, r.Body)
			}
		})
	}
	select {
	case err := <-owner.closed:
		t.Errorf("the legitimate owner's link was disturbed: %v", err)
	default:
	}
	if len(o1.received()) == 0 {
		t.Error("the control exec never reached the legitimate peer's minion")
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Error("an injected command was executed")
	}
}

// Replacement snapshots are rate limited: past the limit the link is closed with the correctable
// code 4012 (the child reconnects with backoff and re-sends one coherent snapshot).
func TestTopology_SnapshotBurstIsRateLimited(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	f := newFakeChild(t, root, "burst")
	for i := 0; i < 60; i++ { // far above the limit (40 per minute); the parent closes the link at some point
		if err := f.conn.WriteJSON(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{}}); err != nil {
			break
		}
	}
	if code := f.waitClosed(); code != 4012 {
		t.Fatalf("the burst must end with a 4012 close, got %d", code)
	}
	waitFor(t, "the limit is logged", func() bool { return root.logs.has("topology_snapshot rate limit exceeded: relay_id=burst") })
	if n := root.logs.count("topology_snapshot: relay_id=burst"); n < 40 {
		t.Errorf("only %d snapshots accepted before the limit: the legitimate rate (<=30/min) must never be limited", n)
	}
}

// inventoryRaw is the root's aggregated inventory as text.
func inventoryRaw(n *node) string {
	_, raw := n.call("GET", "/api/inventory", n.pluginToken(), nil)
	return string(raw)
}

// A relay REMOVED from the subtree (deleted at its parent, so it is no longer declared): the
// ancestors clear its routes and release its ownership — and the same relay can be registered and
// linked again afterwards.
func TestTopology_RelayRemovedFromTheSubtreeIsCleanedAtTheAncestors(t *testing.T) {
	parallel(t)
	root, mid, leaf := pushChain(t)
	_ = leaf
	rowID := func() string {
		code, m := mid.admin("GET", "/api/admin/relays", nil)
		if code != http.StatusOK {
			t.Fatalf("list relays: %d %v", code, m)
		}
		for _, r := range relaysOf(m) {
			if r["relay_id"] == "leaf" {
				return r["id"].(string)
			}
		}
		t.Fatal("leaf not registered at mid")
		return ""
	}()
	connectMinion(t, leaf, "leaf-host")
	waitFor(t, "root routes the leaf's host", func() bool { return root.hasHost("leaf-host") })

	if code, m := mid.admin("DELETE", "/api/admin/relays/"+rowID, nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("delete the relay at mid: %d %v", code, m)
	}
	waitFor(t, "the relay left the subtree: the root cleans its routes", func() bool { return !root.hasHost("leaf-host") })
	if strings.Contains(inventoryRaw(root), `"leaf"`) {
		t.Errorf("the removed relay must not stay in the root's inventory:\n%s", inventoryRaw(root))
	}

	// ownership was released: ANOTHER peer can now declare that relay id (it would be refused as
	// "already owned" while mid still owned it)
	squatter := newFakeChild(t, root, "squatter")
	squatter.snapshot([]map[string]any{{"relay_id": "leaf", "relay_chain": []string{"squatter", "leaf"}}}, nil)
	waitFor(t, "the freed relay id is accepted from another peer", func() bool { return root.logs.count("topology_snapshot: relay_id=squatter") >= 2 })
	select {
	case err := <-squatter.closed:
		t.Fatalf("the removed relay's id must have been released at the root: %v", err)
	default:
	}
	_ = squatter.conn.Close()
	waitFor(t, "the squatter is gone", func() bool { return root.logs.has("Relay disconnected: relay_id=squatter") })

	// and the same relay can come back under mid
	leaf2 := startNode(t, nodeSpec{ID: "leaf", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leaf")})
	waitFor(t, "the relay is linked again", func() bool { return leaf2.upstreamState() == "connected" })
	connectMinion(t, leaf2, "leaf-host")
	waitFor(t, "root routes the host again", func() bool { return root.hasHost("leaf-host") })
}

// relaysOf extracts the relay rows of an /api/admin/relays response.
func relaysOf(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, key := range []string{"relays", "items", "data"} {
		if l, ok := m[key].([]any); ok {
			for _, x := range l {
				if r, ok := x.(map[string]any); ok {
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// mixedFiveLevels builds root → r1 → r2 → r3 → r4 with BOTH link directions mixed:
//
//	root ──push──▶ r1 ◀──pull── r2 ──push──▶ r3 ◀──pull── r4
//
// Every node runs the standard hooks. Nodes are started in an order that makes some links late
// (the dynamic-topology re-snapshots must carry the subtree up).
func mixedFiveLevels(t *testing.T) (root, r1, r2, r3, r4 *node) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	r1 = startNode(t, nodeSpec{ID: "r1", Hooks: standardHooks})
	r2 = startNode(t, nodeSpec{ID: "r2", ParentURL: r1.wssURL(), ParentToken: r1.registerChild("r2"), Hooks: standardHooks})
	r3 = startNode(t, nodeSpec{ID: "r3", Hooks: standardHooks})
	waitFor(t, "r2 linked to r1 (pull)", func() bool { return r2.upstreamState() == "connected" })
	r4 = startNode(t, nodeSpec{ID: "r4", ParentURL: r3.wssURL(), ParentToken: r3.registerChild("r4"), Hooks: standardHooks})
	waitFor(t, "r4 linked to r3 (pull)", func() bool { return r4.upstreamState() == "connected" })
	linkPush(t, r2, r3)   // r2 dials r3
	linkPush(t, root, r1) // root dials r1
	return
}

// A host.up three relays deep climbs to the root with the exact chain, and every node on the way
// runs its hooks with the chain it received (origin first, the sending relay last).
func TestTopology_DeepHostUpClimbsFiveLevelsWithTheExactChain(t *testing.T) {
	parallel(t)
	root, r1, r2, r3, r4 := mixedFiveLevels(t)
	// the whole tree is declared at the root (replacement snapshots carried the subtree up)
	waitFor(t, "the root's view includes r4", func() bool {
		return strings.Contains(inventoryRaw(root), "r4") || root.logs.count("topology_snapshot: relay_id=r1") >= 2
	})
	waitFor(t, "r1 knows r4 as a descendant", func() bool { return r1.logs.count("topology_snapshot: relay_id=r2") >= 1 })
	// let the re-snapshot chain settle: a probe event only counts once every hop declares its child
	connectMinion(t, r4, "probe-host")
	waitFor(t, "the probe reached the root", func() bool { return root.hookHas("UP probe-host") })

	m := connectMinion(t, r4, "ev-deep")
	want := map[*node]string{
		r4:   "UP ev-deep status=connected chain= origin= enrolled=",
		r3:   "UP ev-deep status=connected chain=r4 origin=r4 enrolled=",
		r2:   "UP ev-deep status=connected chain=r4,r3 origin=r4 enrolled=",
		r1:   "UP ev-deep status=connected chain=r4,r3,r2 origin=r4 enrolled=",
		root: "UP ev-deep status=connected chain=r4,r3,r2,r1 origin=r4 enrolled=",
	}
	for n, line := range want {
		n := n
		waitFor(t, n.id+"'s hook ran for the deep host.up", func() bool { return n.hookHas("UP ev-deep") })
		var got string
		for _, l := range n.hookLines() {
			if strings.HasPrefix(l, "UP ev-deep") {
				got = l
			}
		}
		if got != line {
			t.Errorf("%s hook = %q, want %q", n.id, got, line)
		}
	}
	waitFor(t, "the root routes the deep host", func() bool { return root.hasHost("ev-deep") })
	if r := root.exec("ev-deep", execBody("id")); r.Code != http.StatusOK || len(m.received()) != 1 {
		t.Errorf("exec down the five-level chain = %d %v", r.Code, r.Body)
	}
	assertNoSecrets(t, allLogs(root, r1, r2, r3, r4), nodeSecrets(root, r1, r2, r3, r4)...)
}
