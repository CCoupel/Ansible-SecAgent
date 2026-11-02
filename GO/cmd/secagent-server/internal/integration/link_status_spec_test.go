package integration

// LOT-3 on real nodes — #234 (never_seen), #215 (option C: relays not directly connected since the rotation are
// told apart, informative, never blocking) and #218 (explicit refusal of a stale pinned root key).
//
// API under test (plan "Contrats API" + dev-relay):
//   GET  /api/admin/link/status        relays[].{relay_id,link_kid,confirmed,state,direct}, not_direct[]
//        state = confirmed | unconfirmed | never_seen ; confirmed=false for never_seen, outside a rotation too
//   POST /api/admin/link/keys/retire-previous
//        409 {error: rotation_unconfirmed, unconfirmed[] (every non-confirmed), never_seen[] (subset), not_direct[], message}
//        200 {retired, seq, unconfirmed[], never_seen[], not_direct[]}

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

type relayRow struct {
	State     string
	Confirmed bool
	Direct    bool
	Present   bool
}

func linkStatus(t *testing.T, root *node) (rows map[string]relayRow, notDirect []string) {
	t.Helper()
	code, st := root.admin("GET", "/api/admin/link/status", nil)
	if code != http.StatusOK {
		t.Fatalf("link status: %d %v", code, st)
	}
	rows = map[string]relayRow{}
	rels, _ := st["relays"].([]any)
	for _, r := range rels {
		m, _ := r.(map[string]any)
		id, _ := m["relay_id"].(string)
		state, _ := m["state"].(string)
		conf, _ := m["confirmed"].(bool)
		dir, _ := m["direct"].(bool)
		rows[id] = relayRow{State: state, Confirmed: conf, Direct: dir, Present: true}
	}
	return rows, strList(st["not_direct"])
}

func strList(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// #234 — outside a rotation a declared relay that never connected is NOT "confirmed".
func TestLinkStatus_ADeclaredRelayThatNeverConnectedIsNeverSeenOutsideARotation(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	root.registerChildWithID("ghost") // declared (relays add), never started
	rows, notDirect := linkStatus(t, root)
	g := rows["ghost"]
	if !g.Present {
		t.Fatalf("a declared relay must be listed: %v", rows)
	}
	if g.State != "never_seen" || g.Confirmed {
		t.Errorf("ghost = %+v, want state never_seen and confirmed=false (it used to be confirmed=true outside a rotation)", g)
	}
	if g.Direct || !has(notDirect, "ghost") {
		t.Errorf("a relay that never connected is not directly connected: direct=%v not_direct=%v", g.Direct, notDirect)
	}
}

// #234 + #215 — during a rotation: the never-seen relay blocks the retire and is told apart in the 409; the
// connected, confirmed relay is not listed; after `relays remove` the retire passes.
func TestLinkStatus_RotationRetireIsRefusedForANeverSeenRelayThenAcceptedAfterRemove(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	_, ghostRow := root.registerChildWithID("ghost")

	if code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "relay1 confirmed and direct", func() bool {
		rows, _ := linkStatus(t, root)
		return rows["relay1"].State == "confirmed"
	})
	rows, notDirect := linkStatus(t, root)
	if r := rows["relay1"]; !r.Confirmed || !r.Direct {
		t.Errorf("relay1 = %+v, want confirmed and direct", r)
	}
	if g := rows["ghost"]; g.State != "never_seen" || g.Confirmed || g.Direct {
		t.Errorf("ghost = %+v during the rotation, want never_seen, not confirmed, not direct", g)
	}
	if !has(notDirect, "ghost") || has(notDirect, "relay1") {
		t.Errorf("not_direct = %v, want ghost and not relay1", notDirect)
	}

	code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{})
	if code != http.StatusConflict || m["error"] != "rotation_unconfirmed" {
		t.Fatalf("retire with a never-seen relay = %d %v, want 409 rotation_unconfirmed", code, m)
	}
	if nv := strList(m["never_seen"]); len(nv) != 1 || nv[0] != "ghost" {
		t.Errorf("never_seen = %v, want [ghost] (relay1 reported, it is not never_seen)", m["never_seen"])
	}
	if un := strList(m["unconfirmed"]); !has(un, "ghost") || has(un, "relay1") {
		t.Errorf("unconfirmed = %v, want ghost (every non-confirmed relay) and not relay1", un)
	}
	if !has(strList(m["not_direct"]), "ghost") {
		t.Errorf("not_direct = %v, want ghost", m["not_direct"])
	}
	if msg, _ := m["message"].(string); !strings.Contains(msg, "relays remove") {
		t.Errorf("the refusal must give the remedy for an abandoned relay (relays remove <id>): %q", msg)
	}

	// the abandoned relay is dropped: the retire passes, without --force
	code, m = root.admin("DELETE", "/api/admin/relays/"+ghostRow, nil)
	if code == http.StatusConflict && m["error"] == "relay_not_revoked" {
		// a relay whose token the node does not track (the harness mints it through the token API) must be
		// revoked first (#153); a relay added through `relays add` carries its JTI and needs no such step
		if c, rm := root.admin("POST", "/api/admin/relays/"+ghostRow+"/revoke", nil); c != http.StatusOK {
			t.Fatalf("revoke ghost: %d %v", c, rm)
		}
		code, m = root.admin("DELETE", "/api/admin/relays/"+ghostRow, nil)
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("relays remove ghost: %d %v", code, m)
	}
	if rows, _ := linkStatus(t, root); rows["ghost"].Present {
		t.Errorf("a removed relay must disappear from the status: %+v", rows["ghost"])
	}
	if code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{}); code != http.StatusOK || m["retired"] != true {
		t.Fatalf("retire after relays remove = %d %v, want 200", code, m)
	}
}

// #215 — a relay that connects DIRECTLY after the rotation is no longer listed; the retire then passes.
func TestLinkStatus_ARelayThatReconnectsDirectlyAfterTheRotationIsNoLongerListed(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	tok, _ := root.registerChildWithID("late") // token signed by the key of BEFORE the rotation
	if code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	if rows, nd := linkStatus(t, root); rows["late"].Direct || !has(nd, "late") {
		t.Fatalf("before it connects, late must be listed as not direct: %+v %v", rows["late"], nd)
	}
	late := startNode(t, nodeSpec{ID: "late", ParentURL: root.wssURL(), ParentToken: tok})
	waitFor(t, "late linked", func() bool { return late.upstreamState() == "connected" })
	waitFor(t, "late is direct and confirmed", func() bool {
		rows, nd := linkStatus(t, root)
		return rows["late"].Direct && rows["late"].State == "confirmed" && !has(nd, "late")
	})
	if code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{}); code != http.StatusOK {
		t.Fatalf("retire: %d %v", code, m)
	}
}

// #215 (option C) — a relay two levels down is only known through the relay between: its confirmation is
// relayed unsigned by an intermediary that could forge it. It is LISTED (not_direct) in the status and in
// the answer of retire-previous, and does NOT block the retire (informative, operator in the loop).
func TestLinkStatus_ARelayBelowAnIntermediaryIsListedNotDirectAndNeverBlocksTheRetire(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay2 linked", func() bool { return relay2.upstreamState() == "connected" })
	waitFor(t, "the root knows relay2", func() bool { rows, _ := linkStatus(t, root); return rows["relay2"].Present })

	if code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "relay1 and relay2 confirmed", func() bool {
		rows, _ := linkStatus(t, root)
		return rows["relay1"].State == "confirmed" && rows["relay2"].State == "confirmed"
	})
	rows, nd := linkStatus(t, root)
	if !rows["relay1"].Direct || rows["relay2"].Direct {
		t.Errorf("direct: relay1=%v relay2=%v, want true / false", rows["relay1"].Direct, rows["relay2"].Direct)
	}
	if !has(nd, "relay2") || has(nd, "relay1") {
		t.Errorf("not_direct = %v, want relay2 only", nd)
	}
	code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("a not_direct relay must never block the retire: %d %v", code, m)
	}
	if got := strList(m["not_direct"]); !has(got, "relay2") || has(got, "relay1") {
		t.Errorf("the retire answer must list relay2 as not_direct: %v", m["not_direct"])
	}
	if !root.logs.has("not directly connected since the rotation") {
		t.Error("the retire must journalize the unsigned confirmations as a [SECURITY WARNING]")
	}
}

// #218 (D4: fail closed, no tolerance) — rotation then retire leaves the pinned file of a child on the OLD key;
// its next start is refused with an EXPLICIT message: the kids (pinned and current), the cause and both remedies,
// never a key.
func TestLinkTrust_AStalePinnedKeyRefusesTheRestartAndExplainsIt(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	_, pk := root.admin("GET", "/api/admin/link/pubkey", nil)
	pinnedKID, _ := pk["kid"].(string)
	if pinnedKID == "" {
		pinnedKID, _ = pk["current_kid"].(string)
	}
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	if code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "relay1 confirmed", func() bool { rows, _ := linkStatus(t, root); return rows["relay1"].State == "confirmed" })
	code, ret := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("retire: %d %v", code, ret)
	}
	_, after := root.admin("GET", "/api/admin/link/status", nil)
	currentKID, _ := after["current_kid"].(string)
	if currentKID == "" || pinnedKID == "" || currentKID == pinnedKID {
		t.Fatalf("fixture: pinned kid %q, current kid %q", pinnedKID, currentKID)
	}

	// the pinned file still holds the original key (nobody re-exported it): stop relay1 and start it again
	relay1.stop()
	var pinned string
	for _, e := range relay1.env {
		if strings.HasPrefix(e, "REPEATER_ROOT_LINK_KEY_FILE=") {
			if b, err := os.ReadFile(strings.TrimPrefix(e, "REPEATER_ROOT_LINK_KEY_FILE=")); err == nil {
				pinned = string(b)
			}
		}
	}
	rc, out := relay1.runExpectingExit()
	if rc == 0 || rc == -1 {
		t.Fatalf("a relay with a stale pinned key must refuse to start (exit code %d):\n%s", rc, out)
	}
	for _, want := range []struct{ what, needle string }{
		{"the kid of the pinned file", pinnedKID},
		{"the current persisted kid", currentKID},
		{"the remedy keys link-pubkey", "keys link-pubkey"},
		{"the remedy state link-trust reset", "state link-trust reset"},
	} {
		if !strings.Contains(out, want.needle) {
			t.Errorf("the refusal must contain %s (%q):\n%s", want.what, want.needle, out)
		}
	}
	// no key material: not the PEM body of the pinned file
	for _, line := range strings.Split(strings.TrimSpace(pinned), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 20 && !strings.HasPrefix(line, "-----") && strings.Contains(out, line) {
			t.Errorf("the refusal leaks the pinned public key (%q…)", line[:12])
		}
	}
}

// M10 (security review of LOT-3) — "direct" must describe HOW the confirmation arrived, not whether the relay once had
// a direct link: it is true only when the relay's last link_state came over its OWN link (id == conn.RelayID).
// Scenario: relay2 first confirms the rotation directly to the root (direct), then moves BELOW relay1 (an
// intermediary that stays connected the whole time): from then on its link_state reaches the root through relay1,
// which could forge it. relay2 must be listed not_direct again. Before the fix the connection/disconnection
// timestamps kept it "direct" (it had a direct link after the rotation).
func TestLinkStatus_M10_ARelayThatMovesBelowAnIntermediaryStopsBeingDirect(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay2")})
	waitFor(t, "relay2 linked to the root", func() bool { return relay2.upstreamState() == "connected" })

	if code, rot := root.admin("POST", "/api/admin/link/keys/rotate", map[string]any{}); code != http.StatusOK {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	waitFor(t, "relay1 and relay2 confirmed directly", func() bool {
		rows, nd := linkStatus(t, root)
		return rows["relay1"].State == "confirmed" && rows["relay2"].State == "confirmed" && rows["relay2"].Direct && !has(nd, "relay2")
	})

	// relay2 leaves the root and re-attaches below relay1 (same identity, state and secrets)
	relay2.linkTo(relay1)
	waitFor(t, "relay2 linked below relay1", func() bool { return relay2.upstreamState() == "connected" })
	waitFor(t, "relay2 is reachable below relay1", func() bool { rows, _ := linkStatus(t, root); return rows["relay2"].Present })

	// relay1 stayed connected all along; relay2 must now be listed as NOT direct
	waitFor(t, "relay2 reported not direct (its confirmation now comes through relay1)", func() bool {
		rows, nd := linkStatus(t, root)
		return !rows["relay2"].Direct && has(nd, "relay2")
	})
	rows, nd := linkStatus(t, root)
	if r := rows["relay1"]; !r.Direct || has(nd, "relay1") {
		t.Errorf("relay1 is still directly connected: %+v not_direct=%v", r, nd)
	}
	code, m := root.admin("POST", "/api/admin/link/keys/retire-previous", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("a not_direct relay never blocks the retire: %d %v", code, m)
	}
	if got := strList(m["not_direct"]); !has(got, "relay2") || has(got, "relay1") {
		t.Errorf("the retire answer must list relay2 (and not relay1) as not_direct: %v", m["not_direct"])
	}
}
