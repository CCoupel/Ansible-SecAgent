package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// ── permanent (4010) vs correctable (4012) refusals (#148) ───────────────────

// refusalPeer is a WSS peer that, after reading relay_hello, either closes with `code`
// (when code != 0) or answers relay_ack with `ackID`; it records attempt times.
type refusalPeer struct {
	srv   *httptest.Server
	code  atomic.Int32
	ackID atomic.Value // string
	mu    sync.Mutex
	times []time.Time
	conns []*websocket.Conn
}

func newRefusalPeer(t *testing.T, code int, ackID string) *refusalPeer {
	t.Helper()
	p := &refusalPeer{}
	p.code.Store(int32(code))
	p.ackID.Store(ackID)
	up := websocket.Upgrader{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		p.mu.Lock()
		p.times = append(p.times, time.Now())
		p.conns = append(p.conns, c)
		p.mu.Unlock()
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		if code := int(p.code.Load()); code != 0 {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, "refused"), time.Now().Add(time.Second))
			return
		}
		_ = c.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": p.ackID.Load().(string), "status": "ok"})
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *refusalPeer) url() string { return "wss" + strings.TrimPrefix(p.srv.URL, "https") }

// dropLinks abruptly closes every open link (hijacked conns are not tracked by httptest).
func (p *refusalPeer) dropLinks() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
}

func (p *refusalPeer) attempts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.times)
}

func (p *refusalPeer) gaps() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	var g []time.Duration
	for i := 1; i < len(p.times); i++ {
		g = append(g, p.times[i].Sub(p.times[i-1]))
	}
	return g
}

func refusalClient(t *testing.T, p *refusalPeer) (*Client, context.CancelFunc) {
	t.Helper()
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: "tok"}, Options{
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return c, cancel
}

func waitAttempts(t *testing.T, p *refusalPeer, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.attempts() < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d attempts, want %d", p.attempts(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func awaitDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout: %s", what)
	}
}

func TestRefusal_Client4010IsPermanent(t *testing.T) {
	p := newRefusalPeer(t, CloseCodePermanent, "central")
	c, _ := refusalClient(t, p)
	awaitDone(t, c.Done(), "client must give up after 4010")
	if err := c.Terminal(); !errors.Is(err, ErrPermanentRefusal) {
		t.Fatalf("Terminal() = %v, want ErrPermanentRefusal", err)
	}
	n := p.attempts()
	time.Sleep(300 * time.Millisecond) // negative check: ~4 backoff periods, no reconnection allowed
	if p.attempts() != n || n != 1 {
		t.Errorf("attempts = %d then %d, want exactly 1 (no reconnection after 4010)", n, p.attempts())
	}
}

func TestRefusal_Client4012IsRetriedWithGrowingBackoff(t *testing.T) {
	p := newRefusalPeer(t, CloseCodeRetry, "central")
	c, _ := refusalClient(t, p)
	deadline := time.Now().Add(5 * time.Second)
	for p.attempts() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.attempts() < 5 {
		t.Fatalf("only %d attempts: 4012 must be retried", p.attempts())
	}
	g := p.gaps()
	if g[1] < g[0] || g[2] < 60*time.Millisecond || g[3] > 400*time.Millisecond {
		t.Errorf("backoff must grow then cap (20ms→80ms): %v", g)
	}
	select {
	case <-c.Done():
		t.Error("a correctable refusal must never be terminal")
	default:
	}
	if c.Terminal() != nil {
		t.Errorf("Terminal() = %v", c.Terminal())
	}
}

func TestRefusal_ClientRecoversAfterCorrectableRefusal(t *testing.T) {
	p := newRefusalPeer(t, CloseCodeRetry, "central")
	c, _ := refusalClient(t, p)
	waitAttempts(t, p, 2)
	p.code.Store(0) // the cause was fixed
	deadline := time.Now().Add(5 * time.Second)
	for c.ParentID() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.ParentID() != "central" {
		t.Error("client must link once the correctable refusal is gone")
	}
}

func TestRefusal_ClientIdentityChangeIsPermanent(t *testing.T) {
	p := newRefusalPeer(t, 0, "central")
	c, _ := refusalClient(t, p)
	deadline := time.Now().Add(5 * time.Second)
	for c.ParentID() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// the parent is replaced by another identity and the link drops → mismatch on reconnect
	p.ackID.Store("impostor")
	p.dropLinks()
	awaitDone(t, c.Done(), "identity mismatch must be terminal")
	if !errors.Is(c.Terminal(), ErrPermanentRefusal) {
		t.Errorf("Terminal() = %v", c.Terminal())
	}
}

func TestRefusal_CancelIsNotTerminal(t *testing.T) {
	p := newRefusalPeer(t, CloseCodeRetry, "central")
	c, cancel := refusalClient(t, p)
	waitAttempts(t, p, 1)
	cancel()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-c.Done():
		t.Error("ctx cancellation is not a refusal")
	default:
	}
	if c.Terminal() != nil {
		t.Errorf("Terminal() = %v", c.Terminal())
	}
}

// ── dialer ───────────────────────────────────────────────────────────────────

func refusalDialer(t *testing.T, p *refusalPeer, relayID string, wouldLoop func(string) bool) (*Dialer, *atomic.Int32) {
	t.Helper()
	var serves atomic.Int32
	d, err := NewDialer(DialTarget{RelayID: relayID, URL: p.url(), Token: "tok"}, DialerOptions{
		Identity:   func() (string, []string) { return "central", nil },
		WouldLoop:  wouldLoop,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond,
		Serve: func(ctx context.Context, conn *websocket.Conn, _ string) error {
			serves.Add(1)
			<-ctx.Done()
			_ = conn.Close()
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return d, &serves
}

func awaitTerminal(t *testing.T, d *Dialer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.Terminal() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !errors.Is(d.Terminal(), ErrPermanentRefusal) {
		t.Fatalf("Terminal() = %v, want ErrPermanentRefusal", d.Terminal())
	}
}

func TestRefusal_Dialer4010StopsAndNeverRedials(t *testing.T) {
	p := newRefusalPeer(t, CloseCodePermanent, "child1")
	d, _ := refusalDialer(t, p, "child1", func(string) bool { return false })
	awaitTerminal(t, d)
	n := p.attempts()
	time.Sleep(300 * time.Millisecond)
	if n != 1 || p.attempts() != n {
		t.Errorf("attempts = %d then %d, want exactly 1", n, p.attempts())
	}
}

func TestRefusal_DialerChildIdentityMismatchStops(t *testing.T) {
	p := newRefusalPeer(t, 0, "impostor")
	d, serves := refusalDialer(t, p, "child1", func(string) bool { return false })
	awaitTerminal(t, d)
	time.Sleep(200 * time.Millisecond)
	if serves.Load() != 0 || p.attempts() != 1 {
		t.Errorf("serves=%d attempts=%d, want 0 and 1", serves.Load(), p.attempts())
	}
}

func TestRefusal_DialerLoopIsPermanentAndNeverDials(t *testing.T) {
	p := newRefusalPeer(t, 0, "root")
	d, _ := refusalDialer(t, p, "root", func(id string) bool { return id == "root" })
	awaitTerminal(t, d)
	if p.attempts() != 0 {
		t.Errorf("a looping child must never be dialed, got %d attempts", p.attempts())
	}
}

func TestRefusal_Dialer4012IsRetried(t *testing.T) {
	p := newRefusalPeer(t, CloseCodeRetry, "child1")
	d, serves := refusalDialer(t, p, "child1", func(string) bool { return false })
	waitAttempts(t, p, 3)
	if d.Terminal() != nil {
		t.Errorf("Terminal() = %v for a correctable refusal", d.Terminal())
	}
	p.code.Store(0)
	deadline := time.Now().Add(5 * time.Second)
	for serves.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if serves.Load() == 0 {
		t.Error("dialer must link once the correctable refusal is gone")
	}
}
