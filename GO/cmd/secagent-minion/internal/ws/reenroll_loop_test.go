package ws

// #182 — boucle de ré-enrôlement : backoff, erreurs permanentes, 4001, pas de secret dans les logs.
// Les délais sont enregistrés par un hook `wait` (aucune attente réelle).

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
)

// recorder collects the delays Run asks to wait and cancels the context after max waits.
type recorder struct {
	mu     sync.Mutex
	delays []time.Duration
	max    int
	cancel context.CancelFunc
}

func (r *recorder) wait(ctx context.Context, d time.Duration) error {
	r.mu.Lock()
	r.delays = append(r.delays, d)
	n := len(r.delays)
	r.mu.Unlock()
	if r.max > 0 && n >= r.max {
		r.cancel()
	}
	return ctx.Err()
}

func (r *recorder) got() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logSink) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureLog(t *testing.T) *logSink {
	t.Helper()
	s := &logSink{}
	prev := log.Writer()
	log.SetOutput(s)
	t.Cleanup(func() { log.SetOutput(prev) })
	return s
}

func mockReEnroll(t *testing.T, fn func(ctx context.Context, ec EnrollConfig, pub string) (string, error)) {
	t.Helper()
	orig := reEnrollOnce
	reEnrollOnce = fn
	t.Cleanup(func() { reEnrollOnce = orig })
}

const (
	secretJWT   = "SECRET-JWT-VALUE-xyz"
	secretToken = "SECRET-ENROLLMENT-TOKEN-xyz"
)

func newLoopDispatcher(t *testing.T, srvURL string, rec *recorder) *Dispatcher {
	t.Helper()
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srvURL, "http"), JWT: secretJWT, Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{
			RegisterURL: srvURL + "/api/register", Hostname: "h", PrivateKey: generateTestKey2048(t), EnrollmentToken: secretToken,
		})
	d.wait = rec.wait
	return d
}

func TestRun_BackoffGrowsWhenEnrollmentWorksButWSStays401(t *testing.T) {
	logs := captureLog(t)
	var connects atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // safety net: a missing backoff fails here instead of spinning
	defer cancel()
	rec := &recorder{max: 9, cancel: cancel}
	d := newLoopDispatcher(t, srv.URL, rec)
	var enrolls atomic.Int32
	mockReEnroll(t, func(context.Context, EnrollConfig, string) (string, error) {
		enrolls.Add(1)
		return "fresh-" + secretJWT, nil
	})

	_ = d.Run(ctx)

	// first cycle immediate, then 1s, 2s, 4s ... capped at 60s: never a burst
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	got := rec.got()
	if len(got) != len(want) {
		t.Fatalf("delays %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays %v, want %v", got, want)
		}
	}
	if e := enrolls.Load(); e != int32(len(want)+1) {
		t.Errorf("%d re-enrollments for %d waits", e, len(want))
	}
	if !strings.Contains(logs.String(), "[ERROR]") {
		t.Error("an explicit [ERROR] is expected after 5 consecutive cycles")
	}
	for _, s := range []string{secretJWT, secretToken} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("a secret leaked in the logs: %q", s)
		}
	}
}

func TestRun_BackoffResetsAfterASuccessfulWebSocket(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var n atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // safety net: a missing backoff fails here instead of spinning
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1, 2, 4: // refused
			w.WriteHeader(http.StatusUnauthorized)
		case 3: // works, then the link drops
			c, err := up.Upgrade(w, r, nil)
			if err == nil {
				_ = c.Close()
			}
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	rec := &recorder{max: 3, cancel: cancel} // the test ends at the third wait
	d := newLoopDispatcher(t, srv.URL, rec)
	mockReEnroll(t, func(context.Context, EnrollConfig, string) (string, error) { return "j", nil })

	_ = d.Run(ctx)

	// n=1: 401 → immediate cycle; n=2: 401 → wait 1s; n=3: WS ok then drop → plain reconnect
	// delay 1s (backoff was reset by the successful handshake); n=4: 401 → immediate again
	// (without the reset it would wait 2s); n=5: 401 → 1s (second cycle since the reset)
	got := rec.got()
	want := []time.Duration{time.Second, time.Second, time.Second}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("delays %v, want %v (the cycle counter must reset after a working WebSocket)", got, want)
	}
}

func TestRun_TransientEnrollmentFailuresRetryWithBackoffForever(t *testing.T) {
	logs := captureLog(t)
	var wsConnects atomic.Int32
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) // safety net: a missing backoff fails here instead of spinning
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wsConnects.Add(1) <= 5 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil) // finally works: stop
		if err == nil {
			_ = c.Close()
		}
		cancel()
	}))
	defer srv.Close()
	rec := &recorder{cancel: cancel}
	d := newLoopDispatcher(t, srv.URL, rec)
	var calls atomic.Int32
	mockReEnroll(t, func(context.Context, EnrollConfig, string) (string, error) {
		switch calls.Add(1) {
		case 1:
			return "", &enrollment.HTTPError{Step: 1, Status: 400, Body: map[string]any{"error": "missing_fields"}}
		case 2:
			return "", errors.New("reenroll step1: POST: connection refused") // network
		case 3:
			return "", &enrollment.HTTPError{Step: 2, Status: 503}
		}
		return "new", nil
	})

	// the minion never gives up: Run ends only when the WebSocket finally works and the context is
	// cancelled (nil), or when the context ends while waiting (context.Canceled)
	if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run must keep trying until the context ends, got %v", err)
	}
	got := rec.got()
	if len(got) < 3 || got[0] != time.Second || got[1] != 2*time.Second || got[2] != 4*time.Second {
		t.Fatalf("delays %v, want 1s,2s,4s for the failed attempts", got)
	}
	if calls.Load() < 4 {
		t.Errorf("only %d re-enrollment attempts: the minion gave up", calls.Load())
	}
	if strings.Contains(logs.String(), secretJWT) || strings.Contains(logs.String(), secretToken) {
		t.Error("secret leaked in the logs")
	}
}

func TestRun_Forbidden403IsPermanentAndExplicit(t *testing.T) {
	logs := captureLog(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer srv.Close()
	rec := &recorder{}
	d := newLoopDispatcher(t, srv.URL, rec)
	var calls atomic.Int32
	mockReEnroll(t, func(context.Context, EnrollConfig, string) (string, error) {
		calls.Add(1)
		return "", &enrollment.HTTPError{Step: 1, Status: http.StatusForbidden, Body: map[string]any{"error": "token_invalid"}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := d.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "enrollment refused") {
		t.Fatalf("403 must stop the minion with an explicit error, got %v", err)
	}
	if calls.Load() != 1 || len(rec.got()) != 0 {
		t.Errorf("attempts %d, waits %v: a 403 must not be retried", calls.Load(), rec.got())
	}
	if !strings.Contains(logs.String(), "enrollment refused (403)") {
		t.Error("explicit log expected")
	}
}

func TestRun_MissingEnrollmentTokenIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer srv.Close()
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "x", Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{RegisterURL: srv.URL, Hostname: "h", PrivateKey: generateTestKey2048(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Run(ctx); err == nil || !strings.Contains(err.Error(), "RELAY_ENROLLMENT_TOKEN") {
		t.Fatalf("got %v", err)
	}
}

// 4001 (revocation): no reconnection, no re-enrollment (non-regression).
func TestRun_Close4001StopsWithoutReenrollment(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "revoked"))
		time.Sleep(50 * time.Millisecond)
		_ = c.Close()
	}))
	defer srv.Close()
	rec := &recorder{}
	d := newLoopDispatcher(t, srv.URL, rec)
	var enrolls atomic.Int32
	mockReEnroll(t, func(context.Context, EnrollConfig, string) (string, error) { enrolls.Add(1); return "j", nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := d.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("4001 must stop the dispatcher, got %v", err)
	}
	if enrolls.Load() != 0 || len(rec.got()) != 0 {
		t.Errorf("re-enrollments %d, waits %v after a revocation", enrolls.Load(), rec.got())
	}
}
