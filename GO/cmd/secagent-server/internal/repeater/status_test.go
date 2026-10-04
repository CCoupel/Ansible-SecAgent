package repeater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// ── observable link status (#154) ────────────────────────────────────────────

func waitStatus(t *testing.T, get func() LinkStatus, want LinkState) LinkStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := get()
		if st.State == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("state = %q (%q), want %q", st.State, st.Reason, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStatus_ClientPermanentRefusalIsVisible(t *testing.T) {
	p := newRefusalPeer(t, CloseCodePermanent, "central")
	c, _ := refusalClient(t, p)
	before := time.Now().Add(-time.Second)
	st := waitStatus(t, c.Status, LinkRefusedPermanent)
	if st.Reason == "" || !strings.Contains(st.Reason, "4010") || st.Since.Before(before) {
		t.Errorf("status = %+v, want a reason mentioning the 4010 close and a timestamp", st)
	}
}

func TestStatus_ClientCorrectableRefusalIsRetrying(t *testing.T) {
	p := newRefusalPeer(t, CloseCodeRetry, "central")
	c, _ := refusalClient(t, p)
	waitStatus(t, c.Status, LinkRetrying)
	waitAttempts(t, p, 3)
	if st := c.Status(); st.State != LinkRetrying || !strings.Contains(st.Reason, "4012") {
		t.Errorf("status = %+v, want retrying with the 4012 reason", st)
	}
	select {
	case <-c.Done():
		t.Error("a correctable refusal is never terminal")
	default:
	}
}

func TestStatus_ClientConnectedThenRetryingWhenLinkLost(t *testing.T) {
	p := newRefusalPeer(t, 0, "central")
	c, _ := refusalClient(t, p)
	waitStatus(t, c.Status, LinkConnected)
	p.dropLinks()
	st := waitStatus(t, c.Status, LinkRetrying)
	if !strings.Contains(st.Reason, "link lost") && !strings.Contains(st.Reason, "connect failed") {
		t.Errorf("reason = %q", st.Reason)
	}
	waitStatus(t, c.Status, LinkConnected) // and it recovers by itself
}

func TestStatus_ClientCancelIsNotTerminal(t *testing.T) {
	p := newRefusalPeer(t, 0, "central")
	c, cancel := refusalClient(t, p)
	waitStatus(t, c.Status, LinkConnected)
	cancel()
	st := waitStatus(t, c.Status, LinkRetrying)
	if st.State == LinkRefusedPermanent || c.Terminal() != nil {
		t.Errorf("cancel must not look like a refusal: %+v / %v", st, c.Terminal())
	}
}

func TestStatus_DialerPerChildAndManager(t *testing.T) {
	refused := newRefusalPeer(t, CloseCodePermanent, "child-a")
	healthy := newRefusalPeer(t, 0, "child-b")
	retrying := newRefusalPeer(t, CloseCodeRetry, "child-c")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewDialerManager(ctx, DialerOptions{
		Identity:   func() (string, []string) { return "central", nil },
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond,
		Serve: func(ctx context.Context, conn *websocket.Conn, _ string) error {
			<-ctx.Done()
			_ = conn.Close()
			return ctx.Err()
		},
	})
	for id, p := range map[string]*refusalPeer{"child-b": healthy, "child-a": refused, "child-c": retrying} {
		if err := m.Start(DialTarget{RelayID: id, URL: p.url(), Token: "super-secret-token"}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var got map[string]LinkState
	for {
		got = map[string]LinkState{}
		for _, s := range m.Statuses() {
			got[s.RelayID] = s.State
		}
		if got["child-a"] == LinkRefusedPermanent && got["child-b"] == LinkConnected && got["child-c"] == LinkRetrying {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("states = %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	list := m.Statuses()
	if len(list) != 3 || list[0].RelayID != "child-a" || list[2].RelayID != "child-c" {
		t.Errorf("statuses must be sorted by relay_id: %+v", list)
	}
	raw, _ := json.Marshal(list)
	for _, secret := range []string{"super-secret-token", "Bearer", "Authorization"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("status leaks %q: %s", secret, raw)
		}
	}
	m.Stop("child-a")
	for _, s := range m.Statuses() {
		if s.RelayID == "child-a" {
			t.Error("a stopped dialer must disappear from the statuses")
		}
	}
}

func TestStatus_DialerLoopAndIdentityMismatchAreRefusedPermanent(t *testing.T) {
	impostor := newRefusalPeer(t, 0, "impostor")
	d, _ := refusalDialer(t, impostor, "child1", func(string) bool { return false })
	if st := waitStatus(t, d.Status, LinkRefusedPermanent); !strings.Contains(st.Reason, "identity mismatch") {
		t.Errorf("reason = %q", st.Reason)
	}
	loop := newRefusalPeer(t, 0, "root")
	d2, _ := refusalDialer(t, loop, "root", func(id string) bool { return id == "root" })
	if st := waitStatus(t, d2.Status, LinkRefusedPermanent); !strings.Contains(st.Reason, "loop") {
		t.Errorf("reason = %q", st.Reason)
	}
}

func TestStatus_NoTokenInClientStatus(t *testing.T) {
	p := newRefusalPeer(t, CloseCodePermanent, "central")
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: "client-secret-token"}, Options{
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	st := waitStatus(t, c.Status, LinkRefusedPermanent)
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "client-secret-token") {
		t.Errorf("status leaks the token: %s", raw)
	}
}

func TestStatus_ReasonIsBounded(t *testing.T) {
	tr := newLinkTracker()
	tr.set(LinkRetrying, strings.Repeat("x", 5000))
	if got := tr.get().Reason; len(got) > maxReasonLen+4 { // + the ellipsis
		t.Errorf("reason length = %d", len(got))
	}
	// the same condition keeps its original timestamp
	tr.set(LinkRetrying, "same")
	first := tr.get().Since
	time.Sleep(5 * time.Millisecond)
	tr.set(LinkRetrying, "same")
	if !tr.get().Since.Equal(first) {
		t.Error("an unchanged state must keep its timestamp")
	}
}
