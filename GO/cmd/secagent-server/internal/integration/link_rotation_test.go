package integration

// #141 (L1d+L1e) — rotation of the root link key through a real tree (SERVER_SPEC §9.2.1, DECISION_141 §4):
// link_keys travels root -> relay1, relay1 confirms with link_state, tokens signed by the NEW key are
// accepted by relay1, a token signed by the OLD key stops working after retire-link-previous, and the
// retire is refused (409 rotation_unconfirmed) while a known relay has not confirmed.

import (
	"net/http"
	"testing"
)

func TestLinkRotation_ChildFollowsTheRotationAndRetireIsGuarded(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	// a token signed by the CURRENT (old) key, kept for later
	oldTok := relay1.registerChild("late-old-key")

	code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{})
	if code != http.StatusOK || rot["seq"] != float64(1) {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	// relay1 applies link_keys and confirms (link_state travels up): the root sees it
	waitFor(t, "relay1 confirmed the rotation", func() bool {
		_, st := root.admin("GET", "/api/admin/link/status", nil)
		rels, _ := st["relays"].([]any)
		for _, r := range rels {
			m, _ := r.(map[string]any)
			if m["relay_id"] == "relay1" && m["confirmed"] == true {
				return true
			}
		}
		return false
	})
	// a token signed by the NEW key opens a link below relay1
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay2 (token of the new key) linked to relay1", func() bool { return relay2.upstreamState() == "connected" })
	// the old-key token still works during the double acceptation
	late := startNode(t, nodeSpec{ID: "late-old-key", ParentURL: relay1.wssURL(), ParentToken: oldTok})
	waitFor(t, "the previous key is still accepted during the window", func() bool { return late.upstreamState() == "connected" })
	late.stop()

	// a second rotation is refused while the window is open
	if code, m := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusConflict || m["error"] != "previous_key_not_retired" {
		t.Errorf("second rotation = %d %v, want 409 previous_key_not_retired", code, m)
	}
	// retire: everything is confirmed, accepted
	if code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{}); code != http.StatusOK || m["seq"] != float64(2) {
		t.Fatalf("retire: %d %v", code, m)
	}
	// the old key no longer opens a link; the tree is not disturbed
	if c, _, err := dialRelayLink(relay1, oldTok); err == nil {
		got := closeCodeOf(t, c)
		_ = c.Close()
		t.Errorf("a token of the retired key opened a link (closed with %d)", got)
	}
	if relay1.upstreamState() != "connected" || relay2.upstreamState() != "connected" {
		t.Error("the retire must not disturb the established links")
	}
}
