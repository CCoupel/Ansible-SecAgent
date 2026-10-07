package integration

import (
	"net/http"
	"strings"
	"testing"
)

// permanent refusals: the child must stop (refused_permanent in /health) and the refusing node
// must say why in its log.
func waitRefusedPermanent(t *testing.T, n *node) {
	t.Helper()
	waitFor(t, n.id+" upstream refused_permanent", func() bool { return n.upstreamState() == "refused_permanent" })
	if !n.health().Degraded {
		t.Errorf("%s must report degraded in /health", n.id)
	}
}

// (c) identity usurpation: a valid token issued for "relay1" presented by a node announcing another id.
func TestRefusal_ImpersonationIsPermanent(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	tokForRelay1 := root.registerChild("relay1")
	imposter := startNode(t, nodeSpec{ID: "imposter", ParentURL: root.wssURL(), ParentToken: tokForRelay1})
	waitRefusedPermanent(t, imposter)
	if u := imposter.health().Links.Upstream; u == nil || u.Reason == "" {
		t.Errorf("the refusal reason must be reported: %+v", u)
	}
	if code, m := root.admin("GET", "/api/admin/relays", nil); code != http.StatusOK || strings.Contains(string(mustJSON(t, m)), `"imposter"`) {
		t.Errorf("the imposter must never be registered: %d %v", code, m)
	}
	// the legitimate holder of the token still links
	good := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tokForRelay1})
	waitFor(t, "legitimate relay1 linked", func() bool { return good.upstreamState() == "connected" })
	assertNoSecrets(t, allLogs(root, imposter, good), tokForRelay1)
}

// (c) loops: a child announcing an ancestor's id is refused for good. A child named like its own parent
// cannot even be signed: the root never mints a token whose sub equals its aud (v3.0.4).
func TestRefusal_LoopIsPermanent(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	t.Run("a child named like its parent cannot be signed", func(t *testing.T) {
		if code, m := root.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-child", "sub": "relay1", "aud": "relay1"}); code != http.StatusBadRequest || m["error"] != "sub_equals_aud" {
			t.Errorf("mint sub=aud = %d %v, want 400 sub_equals_aud", code, m)
		}
	})
	t.Run("child announces an ancestor's id", func(t *testing.T) {
		looping := startNode(t, nodeSpec{ID: "root", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("root")})
		waitRefusedPermanent(t, looping)
		if relay1.upstreamState() != "connected" {
			t.Error("a refused looping child must not disturb the rest of the tree")
		}
		relay1.logs.expectLog(t, "loop", "the parent must log the loop refusal")
	})
}

// (c) push side: the parent never dials itself nor one of its ancestors.
func TestRefusal_PushDialOutLoopIsRejected(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	for _, tc := range []struct {
		name string
		on   *node
		id   string
	}{
		{"root registers itself", root, "root"},
		{"relay1 registers its ancestor root as a push child", relay1, "root"},
		{"relay1 registers itself", relay1, "relay1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, _ := relay1.mintParentToken("unrelated-parent") // any well-formed token: the loop check comes first
			code, m := tc.on.admin("POST", "/api/admin/relays", map[string]any{"relay_id": tc.id, "mode": "push", "url": relay1.wssURL(), "token": tok})
			if code != http.StatusBadRequest || m["error"] != "relay_id_would_create_loop" {
				t.Errorf("push registration of %s on %s = %d %v, want 400 relay_id_would_create_loop", tc.id, tc.on.id, code, m)
			}
		})
	}
}

// Only the root mints link tokens, and it never signs a token whose presenter is its own verifier.
func TestRefusal_LinkTokenMintingRules(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	for _, role := range []string{"relay-parent", "relay-child"} {
		if code, m := root.admin("POST", "/api/admin/tokens", map[string]any{"role": role, "sub": "relay1", "aud": "relay1"}); code != http.StatusBadRequest || m["error"] != "sub_equals_aud" {
			t.Errorf("%s with sub == aud on the root = %d %v, want 400 sub_equals_aud", role, code, m)
		}
		if code, m := relay1.admin("POST", "/api/admin/tokens", map[string]any{"role": role, "sub": "x", "aud": "relay1"}); code != http.StatusConflict || m["error"] != "not_root" {
			t.Errorf("%s on a relay that has a parent = %d %v, want 409 not_root", role, code, m)
		}
	}
}
