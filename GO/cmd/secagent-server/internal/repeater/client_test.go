package repeater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

const waitTimeout = 5 * time.Second

// mockParent is a WSS parent: it records handshakes and exposes the live conn.
type mockParent struct {
	srv          *httptest.Server
	idv          atomic.Value // identity answered in relay_ack (string)
	ackBody      func() any
	conns        chan *websocket.Conn
	hellos       chan map[string]any
	auths        chan string
	incoming     chan map[string]any
	accepted     atomic.Int32
	ackAncestors []string
	closeWith    int // when >0: close with this code right after relay_hello
}

func newMockParent(t *testing.T, id string) *mockParent {
	t.Helper()
	p := &mockParent{conns: make(chan *websocket.Conn, 8), hellos: make(chan map[string]any, 8),
		auths: make(chan string, 8), incoming: make(chan map[string]any, 64)}
	p.idv.Store(id)
	up := websocket.Upgrader{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws/relay" {
			http.NotFound(w, r)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		p.accepted.Add(1)
		p.auths <- r.Header.Get("Authorization")
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		p.hellos <- hello
		if p.closeWith > 0 {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(p.closeWith, "loop"), time.Now().Add(time.Second))
			_ = c.Close()
			return
		}
		if err := c.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": p.idv.Load().(string), "status": "ok", "ancestors": p.ackAncestors}); err != nil {
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

func (p *mockParent) url() string { return "wss" + strings.TrimPrefix(p.srv.URL, "https") }

func (p *mockParent) next(t *testing.T, typ string) map[string]any {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case m := <-p.incoming:
			if m["type"] == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("timeout waiting for %q", typ)
		}
	}
}

func (p *mockParent) conn(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case c := <-p.conns:
		return c
	case <-time.After(waitTimeout):
		t.Fatal("timeout waiting for client connection")
		return nil
	}
}

func startClient(t *testing.T, p *mockParent, opts Options) *Client {
	t.Helper()
	opts.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server cert
	if opts.MinBackoff == 0 {
		opts.MinBackoff = 10 * time.Millisecond
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = 40 * time.Millisecond
	}
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: "tok-secret"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHandshakeAndAgentList(t *testing.T) {
	p := newMockParent(t, "central")
	c := startClient(t, p, Options{
		DirectAgents: func() []AgentInfo { return []AgentInfo{{Hostname: "host-A", Status: "connected"}} },
		Snapshot: func() Snapshot {
			return Snapshot{Relays: []TopoRelay{{RelayID: "zone-a", RelayChain: []string{"zone-a"}}}}
		},
	})

	hello := <-p.hellos
	if hello["type"] != "relay_hello" || hello["node_type"] != "relay" || hello["mode"] != "pull" ||
		hello["relay_id"] != "dmz1" || hello["version"] != "3.0" {
		t.Errorf("bad relay_hello: %v", hello)
	}
	if auth := <-p.auths; auth != "Bearer tok-secret" {
		t.Errorf("bad Authorization header: %q", auth)
	}
	snap := p.next(t, "topology_snapshot")
	if len(snap["relays"].([]any)) != 1 {
		t.Errorf("snapshot relays: %v", snap)
	}
	if len(snap["agents"].([]any)) != 0 {
		t.Errorf("snapshot agents must be an empty array: %v", snap)
	}
	al := p.next(t, "agent_list")
	if a := al["agents"].([]any); len(a) != 1 || a[0].(map[string]any)["hostname"] != "host-A" {
		t.Errorf("agent_list: %v", al)
	}
	if c.ParentID() != "central" {
		t.Errorf("ParentID = %q", c.ParentID())
	}
}

func TestAncestorsLearnedFromAck(t *testing.T) {
	p := newMockParent(t, "central")
	p.ackAncestors = []string{"central", "root"}
	c := startClient(t, p, Options{})
	p.conn(t)
	p.next(t, "topology_snapshot") // sent after the ack was processed
	got := c.Ancestors()
	if len(got) != 2 || got[0] != "central" || got[1] != "root" {
		t.Errorf("Ancestors = %v", got)
	}
}

func TestAgentListOnChange(t *testing.T) {
	p := newMockParent(t, "central")
	changed := make(chan struct{}, 1)
	var n atomic.Int32
	startClient(t, p, Options{
		Changed: changed,
		DirectAgents: func() []AgentInfo {
			return []AgentInfo{{Hostname: "h", Status: "n" + string(rune('0'+n.Add(1)))}}
		},
	})
	p.conn(t)
	p.next(t, "agent_list")
	changed <- struct{}{}
	al := p.next(t, "agent_list")
	if st := al["agents"].([]any)[0].(map[string]any)["status"]; st != "n2" {
		t.Errorf("expected refreshed agent_list, got status %v", st)
	}
}

func TestEventForwardAddsRepeaterID(t *testing.T) {
	p := newMockParent(t, "central")
	events := make(chan Event, 4)
	startClient(t, p, Options{Events: events})
	p.conn(t)
	p.next(t, "agent_list")

	events <- Event{Event: "host.up", Hostname: "host-A", RelayID: "dmz1", RelayChain: nil}
	events <- Event{Event: "relay.up", RelayID: "zone-a", RelayChain: []string{"zone-a"}}
	events <- Event{Event: "host.down", Hostname: "x", RelayChain: []string{"dmz1"}} // already contains us → dropped
	events <- Event{Event: "host.new", Hostname: "y"}

	e1 := p.next(t, "event_forward")
	if got := e1["relay_chain"].([]any); len(got) != 1 || got[0] != "dmz1" {
		t.Errorf("e1 chain = %v", got)
	}
	e2 := p.next(t, "event_forward")
	if got := e2["relay_chain"].([]any); len(got) != 2 || got[0] != "zone-a" || got[1] != "dmz1" {
		t.Errorf("e2 chain = %v", got)
	}
	e3 := p.next(t, "event_forward") // the looping event must have been skipped
	if e3["event"] != "host.new" {
		t.Errorf("looping event was not dropped, got %v", e3)
	}
}

func TestForwardChain(t *testing.T) {
	if _, err := ForwardChain([]string{"a", "dmz1"}, "dmz1"); err == nil {
		t.Error("expected loop error")
	}
	in := []string{"a"}
	out, err := ForwardChain(in, "b")
	if err != nil || len(out) != 2 || len(in) != 1 {
		t.Errorf("out=%v err=%v in=%v", out, err, in)
	}
}

func TestParentEventForwardNotReforwarded(t *testing.T) {
	p := newMockParent(t, "central")
	startClient(t, p, Options{})
	c := p.conn(t)
	p.next(t, "agent_list")
	if err := c.WriteJSON(map[string]any{"type": "event_forward", "event": "host.up", "hostname": "h", "relay_chain": []string{"other"}}); err != nil {
		t.Fatal(err)
	}
	// Barrier: a heartbeat answered by the client proves the event was processed before.
	if err := c.WriteJSON(map[string]any{"type": "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(waitTimeout)
	for {
		select {
		case m := <-p.incoming:
			if m["type"] == "event_forward" {
				t.Fatalf("event from parent was re-forwarded: %v", m)
			}
			if m["type"] == "heartbeat_ack" {
				return
			}
		case <-deadline:
			t.Fatal("no heartbeat_ack")
		}
	}
}

func TestTaskForwardDispatched(t *testing.T) {
	p := newMockParent(t, "central")
	got := make(chan string, 1)
	startClient(t, p, Options{OnTask: func(_ context.Context, raw json.RawMessage, reply func(any) error) {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		got <- m["hostname"].(string)
		_ = reply(map[string]any{"type": "task_result", "task_id": m["task_id"], "rc": 0})
	}})
	c := p.conn(t)
	if err := c.WriteJSON(map[string]any{"type": "task_forward", "task_id": "t1", "hostname": "host-C", "cmd": "id"}); err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-got:
		if h != "host-C" {
			t.Errorf("hostname = %s", h)
		}
	case <-time.After(waitTimeout):
		t.Fatal("handler not called")
	}
	if r := p.next(t, "task_result"); r["task_id"] != "t1" {
		t.Errorf("result: %v", r)
	}
}

func TestReconnectAfterDisconnectIsIdempotent(t *testing.T) {
	p := newMockParent(t, "central")
	startClient(t, p, Options{})
	c1 := p.conn(t)
	if h := <-p.hellos; h["relay_id"] != "dmz1" {
		t.Fatalf("hello1 %v", h)
	}
	_ = c1.Close()
	c2 := p.conn(t) // reconnected
	h2 := <-p.hellos
	if h2["relay_id"] != "dmz1" {
		t.Errorf("hello2 relay_id = %v", h2["relay_id"])
	}
	p.next(t, "topology_snapshot")
	_ = c2
}

func TestParentIdentityMismatchRefused(t *testing.T) {
	p := newMockParent(t, "central")
	c := startClient(t, p, Options{})
	c1 := p.conn(t)
	p.next(t, "agent_list")
	p.idv.Store("impostor")
	_ = c1.Close()
	deadline := time.After(waitTimeout)
	for p.accepted.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("no reconnection attempt")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if c.ParentID() != "central" {
		t.Errorf("parent identity must stay pinned, got %q", c.ParentID())
	}
	// the impostor session must never reach the topology_snapshot step
	deadline = time.After(150 * time.Millisecond)
	for {
		select {
		case m := <-p.incoming:
			if m["type"] == "topology_snapshot" {
				t.Fatal("snapshot sent to a parent with a changed identity")
			}
		case <-deadline:
			return
		}
	}
}

func TestParentRefusalCode4010(t *testing.T) {
	p := newMockParent(t, "central")
	p.closeWith = CloseCodeRefused
	c := startClient(t, p, Options{})
	<-p.hellos
	// Refusal → client waits MaxBackoff (40ms) before retrying, and never reports ParentID.
	deadline := time.After(waitTimeout)
	for p.accepted.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("client did not retry after refusal")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if c.ParentID() != "" {
		t.Errorf("ParentID set despite refusal: %q", c.ParentID())
	}
}

func TestStartTwiceFails(t *testing.T) {
	p := newMockParent(t, "central")
	c := startClient(t, p, Options{})
	if err := c.Start(context.Background()); err == nil {
		t.Error("second Start must fail (one goroutine, one parent)")
	}
}

func TestDefaults(t *testing.T) {
	c := New(config.RepeaterConfig{ID: "a", UpstreamURL: "wss://x", UpstreamToken: "t"}, Options{})
	if c.opts.MinBackoff != 5*time.Second || c.opts.MaxBackoff != 60*time.Second {
		t.Errorf("backoff defaults = %v..%v, want 5s..60s", c.opts.MinBackoff, c.opts.MaxBackoff)
	}
	if got := c.endpoint(); got != "wss://x/ws/relay" {
		t.Errorf("endpoint = %s", got)
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	// Parent that always fails the HTTP upgrade → client must retry with growing gaps capped at max.
	var times []time.Time
	var mu atomic.Int32
	ch := make(chan time.Time, 16)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Add(1)
		ch <- time.Now()
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: "wss" + strings.TrimPrefix(srv.URL, "https"), UpstreamToken: "t"},
		Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}, MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond}) //nolint:gosec // test
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		select {
		case ts := <-ch:
			times = append(times, ts)
		case <-time.After(waitTimeout):
			t.Fatal("not enough attempts")
		}
	}
	gaps := make([]time.Duration, 0, 4)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]))
	}
	if gaps[1] < gaps[0] || gaps[2] < 60*time.Millisecond {
		t.Errorf("backoff not growing: %v", gaps)
	}
	if gaps[3] > 400*time.Millisecond {
		t.Errorf("backoff not capped: %v", gaps)
	}
}
