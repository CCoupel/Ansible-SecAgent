package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"secagent-server/internal/endpoints"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
)

// deadURL is the wss address of a server that no longer listens: the dial is refused (before send).
func deadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	u := "wss" + strings.TrimPrefix(srv.URL, "https")
	srv.Close()
	return u
}

// silentServer reads the WebSocket upgrade request, then never answers: the dial is "after send".
func silentServer(t *testing.T) (url string, requests *atomic.Int32) {
	t.Helper()
	requests = new(atomic.Int32)
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	return "wss" + strings.TrimPrefix(srv.URL, "https"), requests
}

func TestClient_FirstAddressDown_FallsBackToTheSecond(t *testing.T) {
	p := newMockParent(t, "central")
	opts := Options{}
	opts.TLSConfig = testTLS()
	opts.MinBackoff, opts.MaxBackoff = 10*time.Millisecond, 40*time.Millisecond
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: deadURL(t) + "," + p.url(),
		UpstreamURLs: []string{deadURL(t), p.url()}, UpstreamToken: "tok"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	p.conn(t) // the second address received the link
}

func TestClient_ReconnectsToTheFirstAddressWhenItIsBack(t *testing.T) {
	p1 := newMockParent(t, "central")
	p2 := newMockParent(t, "central")
	opts := Options{TLSConfig: testTLS(), MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond}
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURLs: []string{p1.url(), p2.url()}, UpstreamToken: "tok"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	conn := p1.conn(t) // the first address is served first
	if p2.accepted.Load() != 0 {
		t.Fatal("the second address must not be used while the first one answers")
	}
	_ = conn.Close() // the link drops: the last good address is retried first
	p1.conn(t)
	if p2.accepted.Load() != 0 {
		t.Fatal("the second address must not be used while the first one answers")
	}
}

// MarkSent, pull path: the first address got the upgrade request and stays silent (timeout AFTER send):
// the request may have been processed, so the second address must not receive the same attempt.
func TestClient_MarkSent_AfterSendFailureIsNotReplayedOnTheNextAddress(t *testing.T) {
	silentURL, silentReqs := silentServer(t)
	p2 := newMockParent(t, "central")
	opts := Options{TLSConfig: testTLS(), MinBackoff: time.Hour, MaxBackoff: time.Hour, HandshakeTimeout: 400 * time.Millisecond}
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURLs: []string{silentURL, p2.url()}, UpstreamToken: "tok"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(waitTimeout)
	for silentReqs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(900 * time.Millisecond) // past the handshake timeout of the first attempt
	if silentReqs.Load() != 1 {
		t.Fatalf("first address: %d upgrade requests, want 1", silentReqs.Load())
	}
	if n := p2.accepted.Load(); n != 0 {
		t.Fatalf("the second address received %d connection(s) after an after-send failure, want 0", n)
	}
}

func TestDialer_FirstAddressDown_FallsBackToTheSecond(t *testing.T) {
	child := newMockChild(t, "dmz1")
	serve := make(chan serveCall, 4)
	d, err := NewDialer(DialTarget{RelayID: "dmz1", URLs: []string{deadURL(t), child.url()}, Token: "tok"}, dialerOpts(serve))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serve:
	case <-time.After(waitTimeout):
		t.Fatal("the dialer never reached the second address")
	}
}

// MarkSent, push path (see the pull twin above).
func TestDialer_MarkSent_AfterSendFailureIsNotReplayedOnTheNextAddress(t *testing.T) {
	silentURL, silentReqs := silentServer(t)
	child := newMockChild(t, "dmz1")
	serve := make(chan serveCall, 4)
	o := dialerOpts(serve)
	o.MinBackoff, o.MaxBackoff, o.HandshakeTimeout = time.Hour, time.Hour, 400*time.Millisecond
	d, err := NewDialer(DialTarget{RelayID: "dmz1", URLs: []string{silentURL, child.url()}, Token: "tok"}, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if silentReqs.Load() != 1 {
		t.Fatalf("first address: %d upgrade requests, want 1", silentReqs.Load())
	}
	if n := child.accepts.Load(); n != 0 {
		t.Fatalf("the second address received %d connection(s) after an after-send failure, want 0", n)
	}
}

func TestDialer_RefusesAListWithAForbiddenAddress(t *testing.T) {
	withGuard(t)
	_, err := NewDialer(DialTarget{RelayID: "dmz1", URLs: []string{"wss://10.0.0.1:7772", "wss://127.0.0.1:7772"}, Token: "t"}, dialerOpts(make(chan serveCall, 1)))
	if err == nil {
		t.Fatal("a list with a loopback address must be refused as a whole")
	}
}

func testTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server certs
}

// markSentConn alone (the upgrade is also seen by DialFirst's own trace): its first Write flags the
// attempt as "sent", so a timeout that follows is after-send and no other address is tried.
func TestMarkSentConn_FirstWriteMakesATimeoutAfterSend(t *testing.T) {
	urls, err := endpoints.ParseSchemes("wss://a.example:1,wss://b.example:2", "wss")
	if err != nil {
		t.Fatal(err)
	}
	r, err := endpoints.NewRotor(urls, endpoints.Backoff{Min: time.Millisecond, Max: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	run := func(write bool) (calls int, err error) {
		_, _, err = endpoints.DialFirst(context.Background(), r, time.Second,
			func(ctx context.Context, _ *url.URL) (struct{}, error) {
				calls++
				if write {
					c1, c2 := net.Pipe()
					defer func() { _ = c1.Close(); _ = c2.Close() }()
					go func() { _, _ = io.Copy(io.Discard, c2) }()
					_, _ = (&markSentConn{Conn: c1, ctx: ctx}).Write([]byte("x"))
				}
				return struct{}{}, context.DeadlineExceeded
			})
		return calls, err
	}
	if calls, err := run(true); calls != 1 || !errors.Is(err, endpoints.ErrAfterSend) {
		t.Errorf("after a write: %d dial(s), err=%v; want 1 and ErrAfterSend", calls, err)
	}
	if calls, err := run(false); calls != 2 || !errors.Is(err, endpoints.ErrAllFailed) {
		t.Errorf("without a write: %d dial(s), err=%v; want 2 and ErrAllFailed", calls, err)
	}
}
