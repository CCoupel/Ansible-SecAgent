package repeater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/config"
)

func startLinkClient(t *testing.T, p *mockParent, f *lt, token string) *Client {
	t.Helper()
	opts := Options{LinkTrust: f.m, TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond}
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: token}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUplink_LinkFramesAreVerifiedAppliedAckedAndForwarded(t *testing.T) {
	f := newLT(t)
	tok, _, _ := auth.SignLinkToken(f.priv, "root", "dmz1", "central", auth.RoleRelayChild, time.Hour)
	p := newMockParent(t, "central")
	startLinkClient(t, p, f, tok)
	conn := p.conn(t)
	_ = p.next(t, "topology_snapshot")

	// a forged revocation list: ignored, the link stays up, nothing acked
	_, evil, _ := auth.GenerateLinkKey()
	if err := conn.WriteMessage(websocket.TextMessage, f.revocations(t, evil, 5, "jx")); err != nil {
		t.Fatal(err)
	}
	// the genuine one
	if err := conn.WriteMessage(websocket.TextMessage, f.revocations(t, f.priv, 5, "j-other")); err != nil {
		t.Fatal(err)
	}
	st := p.next(t, "link_state")
	if st["relay_id"] != "dmz1" || st["seq"] != float64(5) || st["current_kid"] != auth.LinkKID(f.pub) {
		t.Fatalf("link_state = %v", st)
	}
	if f.bl.IsLinkJTIBlacklisted("jx") || !f.bl.IsLinkJTIBlacklisted("j-other") {
		t.Fatal("blacklist not as expected")
	}
	if len(f.fwd) != 1 {
		t.Fatalf("forwarded %d frames, want 1 (only the verified one)", len(f.fwd))
	}
}

func TestUplink_RevocationOfOwnLinkTokenIsPermanent(t *testing.T) {
	f := newLT(t)
	tok, jti, _ := auth.SignLinkToken(f.priv, "root", "dmz1", "central", auth.RoleRelayChild, time.Hour)
	p := newMockParent(t, "central")
	c := startLinkClient(t, p, f, tok)
	conn := p.conn(t)
	_ = p.next(t, "topology_snapshot")

	if err := conn.WriteMessage(websocket.TextMessage, f.revocations(t, f.priv, 1, jti)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	case <-time.After(waitTimeout):
		t.Fatal("client did not stop after the revocation of its own token")
	}
	if st := c.Status(); st.State != LinkRefusedPermanent {
		t.Fatalf("status = %+v", st)
	}
	if c.Terminal() == nil {
		t.Fatal("no terminal error")
	}
	// never reconnects with a revoked token
	time.Sleep(300 * time.Millisecond)
	if n := p.accepted.Load(); n != 1 {
		t.Fatalf("the client reconnected %d time(s) with a revoked token", n-1)
	}
}

func TestUplink_LinkFramesWithoutLinkTrustAreIgnored(t *testing.T) {
	p := newMockParent(t, "central")
	c := startClient(t, p, Options{})
	conn := p.conn(t)
	_ = p.next(t, "topology_snapshot")
	if err := conn.WriteJSON(map[string]any{"type": "link_revocations", "seq": 1, "entries": []any{}, "sig": "x"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if st := c.Status(); st.State != LinkConnected {
		t.Fatalf("link dropped: %+v", st)
	}
}

// The confirmation (link_state) is sent for an idempotent rotation replay, with the frame's seq.
func TestUplink_RotationReplayOnUpToDateRelayIsConfirmedByLinkState(t *testing.T) {
	root := newLT(t)
	newPub, _, _ := auth.GenerateLinkKey()
	frame := root.keys(t, root.priv, newPub, root.pub, 7)
	f := &lt{store: &fakeTrustStore{}, bl: &fakeBlacklist{}}
	m, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: newPub, Store: f.store, Blacklist: f.bl})
	if err != nil {
		t.Fatal(err)
	}
	f.m = m
	tok, _, _ := auth.SignLinkToken(root.priv, "root", "dmz1", "central", auth.RoleRelayChild, time.Hour)
	p := newMockParent(t, "central")
	startLinkClient(t, p, f, tok)
	conn := p.conn(t)
	_ = p.next(t, "topology_snapshot")
	if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
		t.Fatal(err)
	}
	st := p.next(t, "link_state")
	if st["seq"] != float64(7) || st["current_kid"] != auth.LinkKID(newPub) || st["relay_id"] != "dmz1" {
		t.Fatalf("link_state = %v", st)
	}
}

// The parent ignores a link_state of a relay it has not seen declared yet: the uplink re-sends the
// remembered link_state frames right after every topology_snapshot.
func TestUplink_LinkStatesAreResentAfterEachSnapshot(t *testing.T) {
	f := newLT(t)
	tok, _, _ := auth.SignLinkToken(f.priv, "root", "dmz1", "central", auth.RoleRelayChild, time.Hour)
	p := newMockParent(t, "central")
	topo := make(chan struct{}, 1)
	opts := Options{LinkTrust: f.m, TopologyChanged: topo, TopologyDebounce: 10 * time.Millisecond, TopologyMinGap: 10 * time.Millisecond,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond} //nolint:gosec // test server cert
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: tok}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	_ = p.conn(t)
	_ = p.next(t, "topology_snapshot")
	if err := c.Uplink().SendUpstream(json.RawMessage(`{"type":"link_state","relay_id":"relay2","seq":4,"current_kid":"AAAAAAAAAAAAAAAAAAAAAA"}`)); err != nil {
		t.Fatal(err)
	}
	if st := p.next(t, "link_state"); st["relay_id"] != "relay2" {
		t.Fatalf("immediate link_state = %v", st)
	}
	topo <- struct{}{} // a new snapshot: the remembered state follows it
	_ = p.next(t, "topology_snapshot")
	if st := p.next(t, "link_state"); st["relay_id"] != "relay2" || st["seq"] != float64(4) {
		t.Fatalf("link_state after the snapshot = %v", st)
	}
}

// What the uplink keeps is bounded: only well formed, small link_state frames, one entry per relay_id,
// at most 1024 entries of at most 512 bytes.
func TestUplink_RememberedLinkStatesAreBounded(t *testing.T) {
	u := NewUplink("dmz1", Options{})
	kid := auth.LinkKID(make([]byte, 32))
	frame := func(id, k string) json.RawMessage {
		return json.RawMessage(`{"type":"link_state","relay_id":"` + id + `","seq":1,"current_kid":"` + k + `"}`)
	}
	send := func(id, k string) { _ = u.SendUpstream(frame(id, k)) }

	send("relay2", strings.Repeat("A", 1<<20)) // 1 MiB kid: never kept
	send("relay2", "short")
	send("bad id!", kid)
	send("relay3", kid+"\n")
	if len(u.states) != 0 {
		t.Fatalf("malformed frames were kept: %d", len(u.states))
	}
	for i := 0; i < 5; i++ { // same relay again and again: one entry
		send("relay2", kid)
	}
	if len(u.states) != 1 {
		t.Fatalf("entries = %d, want 1", len(u.states))
	}
	for i := 0; i < 3000; i++ { // many relays: capped
		send("r"+strconv.Itoa(i), kid)
	}
	if len(u.states) > maxRememberedLinkStates {
		t.Fatalf("entries = %d, cap %d", len(u.states), maxRememberedLinkStates)
	}
	total := 0
	for _, f := range u.states {
		total += len(f)
	}
	if total > maxRememberedLinkStates*maxLinkStateFrameLen {
		t.Fatalf("memory kept = %d bytes", total)
	}
}

// An oversized link frame is refused on the raw bytes, before any decoding.
func TestLinkTrust_OversizedFrameIsRefusedBeforeDecoding(t *testing.T) {
	f := newLT(t)
	big := []byte(`{"type":"link_revocations","pad":"` + strings.Repeat("x", maxLinkFrameLen) + `"}`)
	res, err := f.m.HandleFrame(big)
	if err == nil || res.Applied || res.Confirm {
		t.Fatalf("%+v %v", res, err)
	}
	if seq, _ := f.m.State(); seq != 0 || len(f.fwd) != 0 {
		t.Fatal("an oversized frame had effects")
	}
	// and on the uplink path (nothing sent, no panic)
	u := NewUplink("dmz1", Options{LinkTrust: f.m})
	u.handleLinkFrame(nil, big)
}
