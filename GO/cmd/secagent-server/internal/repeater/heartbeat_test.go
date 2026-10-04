package repeater

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// waitFor polls fn until it returns true; it fails the test on timeout.
// It replaces fixed sleeps when observing asynchronous effects.
func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !fn() {
		t.Fatalf("timeout after %s waiting for: %s", timeout, what)
	}
}

// hbParent is a minimal parent that completes the handshake, counts the WebSocket
// pings it receives and can be muted (never answers with a pong).
type hbParent struct {
	srv      *httptest.Server
	pings    atomic.Int32
	accepted atomic.Int32
	mute     bool // do not answer pings with pongs
	conns    chan *websocket.Conn
	incoming chan map[string]any
}

func newHBParent(t *testing.T, mute bool) *hbParent {
	t.Helper()
	p := &hbParent{mute: mute, conns: make(chan *websocket.Conn, 8), incoming: make(chan map[string]any, 64)}
	up := websocket.Upgrader{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		p.accepted.Add(1)
		c.SetPingHandler(func(string) error {
			p.pings.Add(1)
			if p.mute {
				return nil
			}
			return c.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
		})
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		if err := c.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": "central", "status": "ok"}); err != nil {
			return
		}
		p.conns <- c
		for {
			var m map[string]any
			if err := c.ReadJSON(&m); err != nil {
				return
			}
			p.incoming <- m
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *hbParent) start(t *testing.T, opts Options) {
	t.Helper()
	opts.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server cert
	opts.MinBackoff, opts.MaxBackoff = 5*time.Millisecond, 10*time.Millisecond
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: "wss" + strings.TrimPrefix(p.srv.URL, "https"), UpstreamToken: "tok"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

// A WebSocket ping is emitted at every PingInterval, and the parent's pongs keep
// the link alive (read deadline extended): no reconnection happens meanwhile.
func TestHeartbeat_PingSentEveryInterval(t *testing.T) {
	p := newHBParent(t, false)
	p.start(t, Options{PingInterval: 40 * time.Millisecond, AgentListInterval: time.Hour})

	waitFor(t, waitTimeout, "at least 5 pings received by the parent", func() bool { return p.pings.Load() >= 5 })
	// 5 pings ≈ 200ms > 3×PingInterval (read deadline 120ms): without pong-driven
	// deadline extension the link would have been dropped and re-established.
	if n := p.accepted.Load(); n != 1 {
		t.Errorf("link must stay up while the parent answers pings, got %d connections", n)
	}
}

// A parent that never answers (no pong, no message) is detected after
// PingInterval×readTimeoutFactor: the link is closed and re-established.
func TestHeartbeat_SilentParentDetectedAndRecreated(t *testing.T) {
	p := newHBParent(t, true)
	interval := 30 * time.Millisecond
	start := time.Now()
	p.start(t, Options{PingInterval: interval, AgentListInterval: time.Hour})

	<-p.conns // first link established
	waitFor(t, waitTimeout, "client reconnects after a silent parent", func() bool { return p.accepted.Load() >= 2 })
	if elapsed := time.Since(start); elapsed < interval*readTimeoutFactor/2 {
		t.Errorf("reconnected after %s, expected a detection delay close to %s", elapsed, interval*readTimeoutFactor)
	}
	<-p.conns // a fresh link, handshake completed again
}

// A heartbeat from the parent is answered with a heartbeat_ack carrying an RFC 3339 timestamp.
func TestHeartbeat_AckCarriesTimestamp(t *testing.T) {
	p := newHBParent(t, false)
	p.start(t, Options{PingInterval: time.Hour, AgentListInterval: time.Hour})
	c := <-p.conns
	if err := c.WriteJSON(map[string]any{"type": "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(waitTimeout)
	for {
		select {
		case m := <-p.incoming:
			if m["type"] != "heartbeat_ack" {
				continue
			}
			ts, _ := m["timestamp"].(string)
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				t.Errorf("heartbeat_ack timestamp %q is not RFC 3339: %v", ts, err)
			}
			return
		case <-deadline:
			t.Fatal("no heartbeat_ack")
		}
	}
}
