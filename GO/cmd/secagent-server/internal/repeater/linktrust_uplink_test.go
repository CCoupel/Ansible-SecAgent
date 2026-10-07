package repeater

import (
	"context"
	"crypto/tls"
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
	// the parent saw a 4010 close
	_ = conn.SetReadDeadline(time.Now().Add(waitTimeout))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if ce, ok := err.(*websocket.CloseError); !ok || ce.Code != CloseCodePermanent {
				t.Fatalf("close = %v", err)
			}
			break
		}
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
