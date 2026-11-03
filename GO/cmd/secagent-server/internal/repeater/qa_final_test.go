package repeater

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
)

// QA final: forged link_keys {current_pub=<trusted>, sig=garbage, seq=99999} during an OPEN rotation on a
// non-root relay: nothing relayed, remembered or confirmed; an authentic replay is confirmed.
func TestQAFinal_ForgedKeysFrameDuringOpenRotation(t *testing.T) {
	root := newLT(t)
	newPub, _, _ := auth.GenerateLinkKey()
	f := &lt{store: &fakeTrustStore{}, bl: &fakeBlacklist{}}
	m, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: root.pub, Store: f.store, Blacklist: f.bl})
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	m.OnForward(func(raw []byte) { f.fwd = append(f.fwd, raw) })
	rot := root.keys(t, root.priv, newPub, root.pub, 7)
	tok, _, _ := auth.SignLinkToken(root.priv, "root", "dmz1", "central", auth.RoleRelayChild, time.Hour)
	p := newMockParent(t, "central")
	startLinkClient(t, p, f, tok)
	conn := p.conn(t)
	_ = p.next(t, "topology_snapshot")
	if err := conn.WriteMessage(websocket.TextMessage, rot); err != nil {
		t.Fatal(err)
	}
	st := p.next(t, "link_state")
	for st["seq"] != float64(7) {
		t.Logf("initial self-reported link_state: %v", st)
		st = p.next(t, "link_state")
	}
	if st["seq"] != float64(7) || st["current_kid"] != auth.LinkKID(newPub) {
		t.Fatalf("legit rotation not confirmed: %v", st)
	}
	tr := m.Trust()
	if tr.Previous == nil {
		t.Fatal("rotation should be open")
	}
	fwdBefore, replayBefore := len(f.fwd), len(m.Replay())

	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	b := func(k []byte) string { return base64.RawURLEncoding.EncodeToString(k) }
	forged := []byte(`{"type":"link_keys","current_pub":"` + b(newPub) + `","current_kid":"` + auth.LinkKID(newPub) + `","previous_pub":"` + b(root.pub) + `","previous_kid":"` + auth.LinkKID(root.pub) + `","seq":99999,"sig":"` + sig + `"}`)
	if err := conn.WriteMessage(websocket.TextMessage, forged); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(1500 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-p.incoming:
			if msg["type"] == "link_state" {
				t.Errorf("a link_state was sent after the forged frame: %v", msg)
			}
		case <-deadline:
			break loop
		}
	}
	if len(f.fwd) != fwdBefore {
		t.Errorf("forged frame relayed to children")
	}
	if len(m.Replay()) != replayBefore {
		t.Errorf("forged frame remembered for replay")
	}
	if seq, _ := m.State(); seq != 7 {
		t.Errorf("state seq changed: %d", seq)
	}
	// authentic replay of the same rotation: confirmed again
	if err := conn.WriteMessage(websocket.TextMessage, rot); err != nil {
		t.Fatal(err)
	}
	st = p.next(t, "link_state")
	for st["seq"] != float64(7) {
		st = p.next(t, "link_state")
	}
	t.Logf("authentic replay confirmed: seq=%v kid==new:%v; forged: nothing sent/relayed/remembered", st["seq"], st["current_kid"] == auth.LinkKID(newPub))
	if len(f.fwd) != fwdBefore+1 {
		t.Errorf("authentic replay should be relayed once, fwd=%d (before %d)", len(f.fwd), fwdBefore)
	}
}
