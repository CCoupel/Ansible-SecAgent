package integration

// #180 (L6): the suspension of an agent held by a descendant relay is shown in the inventory of its
// ancestors (informative), through the topology_snapshot (field "suspended") and the events
// host.suspended / host.resumed. The authority stays with the relay that holds the agent: an ancestor
// never refuses a task on the strength of the flag it received.

import (
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func suspendedAt(n *node, host string) bool {
	hv, ok := n.inventoryHosts()[host]
	if !ok {
		return false
	}
	v, _ := hv["secagent_suspended"].(bool)
	return v
}

func suspensionTree(t *testing.T) (root, relay1 *node) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root"})
	relay1 = startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	return root, relay1
}

// root -> relay1 -> agent: suspend on relay1 (event), resume (event).
func TestSuspension_EventsReachTheRootInventory(t *testing.T) {
	parallel(t)
	root, relay1 := suspensionTree(t)
	connectMinion(t, relay1, "agent-a")
	waitFor(t, "root routes agent-a", func() bool { return root.hasHost("agent-a") })
	if suspendedAt(root, "agent-a") {
		t.Fatal("agent-a is not suspended yet")
	}

	if code, m := relay1.admin("POST", "/api/admin/minions/agent-a/suspend", map[string]any{}); code != http.StatusOK {
		t.Fatalf("suspend: %d %v", code, m)
	}
	waitFor(t, "the root inventory shows agent-a suspended", func() bool { return suspendedAt(root, "agent-a") })
	// the same rendering as a direct agent, and the holder still refuses
	if r := relay1.exec("agent-a", map[string]any{"cmd": "true", "timeout": 5}); r.Code != http.StatusServiceUnavailable {
		t.Errorf("the holder must refuse a suspended agent: %d %v", r.Code, r.Body)
	}

	if code, m := relay1.admin("POST", "/api/admin/minions/agent-a/resume", map[string]any{}); code != http.StatusOK {
		t.Fatalf("resume: %d %v", code, m)
	}
	waitFor(t, "the flag disappears at the root", func() bool { return !suspendedAt(root, "agent-a") })
}

// The snapshot alone restores the flag after the parent lost its memory (no event is sent).
func TestSuspension_TheSnapshotRestoresTheFlagAfterTheParentRestarts(t *testing.T) {
	parallel(t)
	root, relay1 := suspensionTree(t)
	connectMinion(t, relay1, "agent-a")
	waitFor(t, "root routes agent-a", func() bool { return root.hasHost("agent-a") })
	if code, _ := relay1.admin("POST", "/api/admin/minions/agent-a/suspend", map[string]any{}); code != http.StatusOK {
		t.Fatal("suspend")
	}
	waitFor(t, "flag at the root", func() bool { return suspendedAt(root, "agent-a") })

	root.restart() // the routes and the flags of a node are in memory only
	waitFor(t, "relay1 reconnected", func() bool { return relay1.upstreamState() == "connected" })
	waitFor(t, "the snapshot restored the flag", func() bool { return suspendedAt(root, "agent-a") })
}

// A hostile child: the flag it reports is informative; the root still dispatches the task to it, and
// an event for a host that is not in its subtree is refused.
func TestSuspension_TheRootGrantsNoAuthorityToTheFlag(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	tok := root.registerChild("liar")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, _, err := d.Dial(root.wssURL()+"/ws/relay", h)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	send := func(m map[string]any) {
		if err := conn.WriteJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	read := func(typ string) map[string]any {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			var m map[string]any
			if err := conn.ReadJSON(&m); err != nil {
				t.Fatalf("waiting for %s: %v", typ, err)
			}
			if m["type"] == typ {
				return m
			}
		}
	}
	send(map[string]any{"type": "relay_hello", "relay_id": "liar", "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}})
	read("relay_ack")
	// the child declares a host and says it is suspended; an old child would not send the field at all
	send(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{
		map[string]any{"hostname": "liar-host", "relay_id": "liar", "relay_chain": []string{"liar"}, "suspended": true},
		map[string]any{"hostname": "old-host", "relay_id": "liar", "relay_chain": []string{"liar"}}, // no "suspended": false
	}})
	read("topology_ack")
	send(map[string]any{"type": "agent_list", "agents": []any{map[string]any{"hostname": "liar-host", "status": "connected"}, map[string]any{"hostname": "old-host", "status": "connected"}}})
	waitFor(t, "root routes both hosts", func() bool { return root.hasHost("liar-host") && root.hasHost("old-host") })
	if !suspendedAt(root, "liar-host") || suspendedAt(root, "old-host") {
		t.Fatalf("flags at the root: liar-host=%v old-host=%v, want true / false (an old child sends no field)", suspendedAt(root, "liar-host"), suspendedAt(root, "old-host"))
	}

	// the root does not refuse on the strength of the flag: the task goes down to the child
	done := make(chan execResult, 1)
	go func() { done <- root.exec("liar-host", map[string]any{"cmd": "true", "timeout": 10}) }()
	task := read("task_dispatch")
	if task["hostname"] != "liar-host" {
		t.Fatalf("task for %v", task["hostname"])
	}
	send(map[string]any{"type": "task_result", "task_id": task["task_id"], "rc": 0})
	if r := <-done; r.Code != http.StatusOK {
		t.Errorf("the root refused (or failed) a task for a host reported suspended by an untrusted child: %d %v", r.Code, r.Body)
	}

	// an event for a host outside its subtree (here: unknown to the root) is refused and changes nothing
	send(map[string]any{"type": "event_forward", "event": "host.suspended", "hostname": "not-mine", "relay_chain": []string{"liar"}})
	// the legitimate resume of its own host clears the flag
	send(map[string]any{"type": "event_forward", "event": "host.resumed", "hostname": "liar-host", "relay_chain": []string{"liar"}})
	waitFor(t, "resumed event applied", func() bool { return !suspendedAt(root, "liar-host") })
	if root.hasHost("not-mine") {
		t.Error("an event must never create a host")
	}
	root.logs.expectLog(t, "has no route", "the refusal of the host outside the subtree must be logged")
}
