package repeater

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log"
	"log/slog"
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

// leakToken is long enough to have significant fragments (prefix, middle, suffix).
const leakToken = "eyJhbGciOiJIUzI1NiJ9.SECRETPAYLOAD-0123456789.sIgNaTuRe-abcdef"

// logSink is a goroutine-safe buffer receiving both the standard logger and
// slog's default logger for the duration of a test.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func captureLogs(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	prevOut, prevFlags, prevSlog := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(sink)
	slog.SetDefault(slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		slog.SetDefault(prevSlog)
	})
	return sink
}

// secretNeedles lists everything that must never be logged: the raw token, its
// significant fragments, its encodings and the Authorization header.
func secretNeedles(token string) []string {
	return []string{
		token,
		token[:12],                             // prefix
		token[len(token)/2-6 : len(token)/2+6], // middle
		token[len(token)-12:],                  // suffix
		"SECRETPAYLOAD",
		base64.StdEncoding.EncodeToString([]byte(token)),
		"Bearer",
		"Authorization",
	}
}

func assertNoLeak(t *testing.T, logs string, token string) {
	t.Helper()
	for _, n := range secretNeedles(token) {
		if strings.Contains(logs, n) {
			t.Errorf("log output leaks %q:\n%s", n, logs)
		}
	}
}

// scriptedPeer is a WSS peer whose behaviour depends on the attempt number.
type scriptedPeer struct {
	srv      *httptest.Server
	attempts atomic.Int32
	ids      string // identity announced in relay_ack
	steady   atomic.Int32
}

// script: 1 → HTTP 401 (dial error), 2 → close 4012 (correctable refusal) after hello, 3 → handshake then abrupt
// drop (link lost) after sending a heartbeat, 4+ → healthy link.
func newScriptedPeer(t *testing.T, id string, ackID func(attempt int32) string) *scriptedPeer {
	t.Helper()
	p := &scriptedPeer{ids: id}
	up := websocket.Upgrader{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := p.attempts.Add(1)
		if n == 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		if n == 2 {
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(CloseCodeRetry, "refused"), time.Now().Add(time.Second))
			return
		}
		if err := c.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": ackID(n), "status": "ok"}); err != nil {
			return
		}
		_ = c.WriteJSON(map[string]any{"type": "heartbeat"})
		if n == 3 {
			// let the child talk once, then drop the link abruptly
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _, _ = c.ReadMessage()
			return
		}
		p.steady.Add(1)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *scriptedPeer) url() string { return "wss" + strings.TrimPrefix(p.srv.URL, "https") }

// Client side: dial error (401), close 4012, link lost + reconnection, steady
// state with heartbeats, and an unreachable parent — the token must never appear
// in the standard log nor in slog.
func TestLogs_ClientNeverLeaksToken(t *testing.T) {
	sink := captureLogs(t)
	p := newScriptedPeer(t, "central", func(int32) string { return "central" })
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: p.url(), UpstreamToken: leakToken}, Options{
		TLSConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff:   5 * time.Millisecond,
		MaxBackoff:   10 * time.Millisecond,
		PingInterval: 20 * time.Millisecond, AgentListInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "healthy link after 401, 4012 and a dropped link", func() bool { return p.steady.Load() >= 1 })

	// Unreachable parent: dial error path with the address in the message.
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	deadURL := "wss" + strings.TrimPrefix(dead.URL, "https")
	dead.Close()
	c2 := New(config.RepeaterConfig{ID: "dmz2", UpstreamURL: deadURL, UpstreamToken: leakToken}, Options{
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
	})
	if err := c2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "dial failure logged for the unreachable parent", func() bool {
		return strings.Contains(sink.String(), "connect to parent failed") && strings.Count(sink.String(), deadURL[len("wss://"):]) >= 1
	})
	cancel()

	logs := sink.String()
	// Guard against a vacuous test: every path must have produced a log line.
	for _, marker := range []string{"linked to parent", "refused link", "connect to parent failed", "link to parent lost"} {
		if !strings.Contains(logs, marker) {
			t.Errorf("expected log marker %q to prove the path was exercised", marker)
		}
	}
	assertNoLeak(t, logs, leakToken)
}

// Dialer side (push): dial error (401), correctable refusal, link served then
// lost, loop refusal — the token must never appear in any log.
func TestLogs_DialerNeverLeaksToken(t *testing.T) {
	sink := captureLogs(t)
	// attempt 2 = 4012 close, 3+ = good identity (an identity mismatch is a PERMANENT refusal
	// since #148: the dialer stops, covered in refusal_test.go).
	p := newScriptedPeer(t, "child1", func(int32) string { return "child1" })
	var serves atomic.Int32
	opts := DialerOptions{
		Identity:   func() (string, []string) { return "central", []string{"root"} },
		WouldLoop:  func(id string) bool { return id == "central" || id == "root" },
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		Serve: func(ctx context.Context, conn *websocket.Conn, _ string) error {
			if serves.Add(1) == 1 {
				_ = conn.Close()
				return errors.New("link dropped")
			}
			<-ctx.Done()
			_ = conn.Close()
			return ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := NewDialer(DialTarget{RelayID: "child1", URL: p.url(), Token: leakToken}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Loop refusal path (child == an ancestor): never dialed.
	loop, err := NewDialer(DialTarget{RelayID: "root", URL: p.url(), Token: leakToken}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := loop.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "served twice (second serve after a lost link)", func() bool { return serves.Load() >= 2 })
	// Validation errors must not echo the token either.
	if err := ValidateDialTarget(DialTarget{RelayID: "bad id!", URL: "https://x", Token: leakToken}); err != nil {
		assertNoLeak(t, err.Error(), leakToken)
	}
	cancel()

	logs := sink.String()
	for _, marker := range []string{"connect to child child1 failed", "refused link", "linked to child", "dial-out refused"} {
		if !strings.Contains(logs, marker) {
			t.Errorf("expected log marker %q to prove the path was exercised", marker)
		}
	}
	assertNoLeak(t, logs, leakToken)
	if strings.Contains(d.String(), leakToken) {
		t.Error("Dialer.String() leaks the token")
	}
}
