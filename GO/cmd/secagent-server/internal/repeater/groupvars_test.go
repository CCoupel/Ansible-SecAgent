package repeater

import (
	"testing"
)

// ── group vars are sent in relay_hello (pull) and in the topology_snapshot (#139) ──

func TestGroupVars_PullClientSendsThemInHelloAndSnapshot(t *testing.T) {
	p := newMockParent(t, "central")
	vars := map[string]any{"env": "staging", "datacenter": "paris"}
	startClient(t, p, Options{GroupVars: vars})
	hello := <-p.hellos
	gv, ok := hello["group_vars"].(map[string]any)
	if !ok || gv["env"] != "staging" || gv["datacenter"] != "paris" {
		t.Errorf("relay_hello group_vars = %v", hello["group_vars"])
	}
	snap := p.next(t, "topology_snapshot")
	if sv, ok := snap["group_vars"].(map[string]any); !ok || sv["env"] != "staging" {
		t.Errorf("topology_snapshot group_vars = %v", snap["group_vars"])
	}
}

func TestGroupVars_AbsentWhenNotConfigured(t *testing.T) {
	p := newMockParent(t, "central")
	startClient(t, p, Options{})
	hello := <-p.hellos
	if _, ok := hello["group_vars"]; ok {
		t.Errorf("no group_vars expected in hello: %v", hello)
	}
	snap := p.next(t, "topology_snapshot")
	if _, ok := snap["group_vars"]; ok {
		t.Errorf("no group_vars expected in the snapshot: %v", snap)
	}
}

func TestGroupVars_SnapshotCarriesDescendantVars(t *testing.T) {
	p := newMockParent(t, "central")
	startClient(t, p, Options{Snapshot: func() Snapshot {
		return Snapshot{Relays: []TopoRelay{{RelayID: "zone-a", RelayChain: []string{"dmz1", "zone-a"}, GroupVars: map[string]any{"env": "zone"}}}}
	}})
	snap := p.next(t, "topology_snapshot")
	rel := snap["relays"].([]any)[0].(map[string]any)
	if gv, ok := rel["group_vars"].(map[string]any); !ok || gv["env"] != "zone" {
		t.Errorf("descendant relay entry = %v", rel)
	}
}
