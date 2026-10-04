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
)

// mockChild is a WSS child accepting a dial-out from its parent.
type mockChild struct {
	srv     *httptest.Server
	idv     atomic.Value // identity announced in relay_ack
	auths   chan string
	hellos  chan map[string]any
	accepts atomic.Int32
	noAck   bool
}

func newMockChild(t *testing.T, id string) *mockChild {
	t.Helper()
	m := &mockChild{auths: make(chan string, 8), hellos: make(chan map[string]any, 8)}
	m.idv.Store(id)
	up := websocket.Upgrader{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws/relay" {
			http.NotFound(w, r)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		m.accepts.Add(1)
		m.auths <- r.Header.Get("Authorization")
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		m.hellos <- hello
		if m.noAck {
			_ = c.Close()
			return
		}
		_ = c.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": m.idv.Load().(string), "status": "ok"})
		for { // keep the link open until the parent closes it
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockChild) url() string { return "wss" + strings.TrimPrefix(m.srv.URL, "https") }

type serveCall struct{ peer string }

func dialerOpts(serve chan<- serveCall) DialerOptions {
	return DialerOptions{
		Identity:   func() (string, []string) { return "central", []string{"root"} },
		WouldLoop:  func(id string) bool { return id == "central" || id == "root" },
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 40 * time.Millisecond,
		Serve: func(ctx context.Context, conn *websocket.Conn, peer string) error {
			serve <- serveCall{peer}
			<-ctx.Done()
			_ = conn.Close()
			return ctx.Err()
		},
	}
}

func TestDialer_HandshakeAndServe(t *testing.T) {
	child := newMockChild(t, "dmz1")
	serve := make(chan serveCall, 4)
	d, err := NewDialer(DialTarget{RelayID: "dmz1", URL: child.url(), Token: "tok-secret"}, dialerOpts(serve))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-child.auths; got != "Bearer tok-secret" {
		t.Errorf("Authorization = %q", got)
	}
	h := <-child.hellos
	if h["type"] != "relay_hello" || h["relay_id"] != "central" || h["mode"] != "push" ||
		h["node_type"] != "relay" || h["version"] != "3.0" {
		t.Errorf("hello = %v", h)
	}
	if anc := h["ancestors"].([]any); len(anc) != 1 || anc[0] != "root" {
		t.Errorf("hello ancestors = %v", anc)
	}
	select {
	case c := <-serve:
		if c.peer != "dmz1" {
			t.Errorf("peer = %q", c.peer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve not called after the handshake")
	}
	if err := d.Start(ctx); err == nil {
		t.Error("second Start must fail")
	}
}

func TestDialer_RefusesChildIdentityMismatch(t *testing.T) {
	child := newMockChild(t, "impostor")
	serve := make(chan serveCall, 4)
	d, _ := NewDialer(DialTarget{RelayID: "dmz1", URL: child.url(), Token: "t"}, dialerOpts(serve))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	<-child.hellos
	select {
	case <-serve:
		t.Fatal("Serve must not be called for a mismatching identity")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestDialer_NeverDialsLoopingChild(t *testing.T) {
	for _, id := range []string{"central", "root"} { // ourselves and an ancestor
		child := newMockChild(t, id)
		serve := make(chan serveCall, 1)
		d, _ := NewDialer(DialTarget{RelayID: id, URL: child.url(), Token: "t"}, dialerOpts(serve))
		ctx, cancel := context.WithCancel(context.Background())
		if err := d.Start(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // negative check: no dial may happen
		cancel()
		if n := child.accepts.Load(); n != 0 {
			t.Errorf("child %q dialed %d times despite the loop", id, n)
		}
	}
}

func TestDialer_ReconnectsWithBackoff(t *testing.T) {
	child := newMockChild(t, "dmz1")
	child.noAck = true // every attempt fails after hello → reconnect loop
	serve := make(chan serveCall, 4)
	d, _ := NewDialer(DialTarget{RelayID: "dmz1", URL: child.url(), Token: "t"}, dialerOpts(serve))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-child.hellos:
		case <-time.After(5 * time.Second):
			t.Fatalf("no reconnection attempt %d", i)
		}
	}
}

func TestDialer_StopsOnContextCancel(t *testing.T) {
	child := newMockChild(t, "dmz1")
	serve := make(chan serveCall, 1)
	d, _ := NewDialer(DialTarget{RelayID: "dmz1", URL: child.url(), Token: "t"}, dialerOpts(serve))
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	<-serve
	cancel()
	before := child.accepts.Load()
	time.Sleep(150 * time.Millisecond)
	if child.accepts.Load() != before {
		t.Error("dialer kept reconnecting after cancel")
	}
}

func TestValidateDialTarget(t *testing.T) {
	ok := DialTarget{RelayID: "dmz1", URL: "wss://dmz1.example:7772", Token: "t"}
	if err := ValidateDialTarget(ok); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mut  func(*DialTarget)
	}{
		{"ws scheme", func(d *DialTarget) { d.URL = "ws://dmz1:7772" }},
		{"https scheme", func(d *DialTarget) { d.URL = "https://dmz1" }},
		{"userinfo", func(d *DialTarget) { d.URL = "wss://alice:hunter2@dmz1" }},
		{"no host", func(d *DialTarget) { d.URL = "wss://" }},
		{"empty token", func(d *DialTarget) { d.Token = " " }},
		{"bad id", func(d *DialTarget) { d.RelayID = "a b" }},
		{"empty id", func(d *DialTarget) { d.RelayID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ok
			tt.mut(&d)
			err := ValidateDialTarget(d)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, secret := range []string{"hunter2", "alice"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks %q: %v", secret, err)
				}
			}
		})
	}
}

func TestDialer_TokenNotPrinted(t *testing.T) {
	d, err := NewDialer(DialTarget{RelayID: "dmz1", URL: "wss://dmz1:7772", Token: "secret-token"}, dialerOpts(make(chan serveCall)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.String(), "secret-token") {
		t.Error("token leaked by String()")
	}
}

func TestDialerManager_HotStartStopAndReplace(t *testing.T) {
	child := newMockChild(t, "dmz1")
	serve := make(chan serveCall, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewDialerManager(ctx, dialerOpts(serve))
	tgt := DialTarget{RelayID: "dmz1", URL: child.url(), Token: "t"}
	if err := m.Start(tgt); err != nil {
		t.Fatal(err)
	}
	<-serve
	if m.Running() != 1 {
		t.Errorf("running = %d", m.Running())
	}
	if err := m.Start(tgt); err != nil { // replace: old dialer cancelled, new one dials
		t.Fatal(err)
	}
	<-serve
	if m.Running() != 1 {
		t.Errorf("running after replace = %d", m.Running())
	}
	m.Stop("dmz1")
	if m.Running() != 0 {
		t.Errorf("running after stop = %d", m.Running())
	}
	if err := m.Start(DialTarget{RelayID: "x", URL: "ws://insecure", Token: "t"}); err == nil {
		t.Error("manager must refuse a non-wss target")
	}
}
