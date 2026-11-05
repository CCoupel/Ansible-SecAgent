// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func init() {
	// Les tests historiques sur 401 attendent le ré-enrôlement immédiat : réessais désactivés par
	// défaut ; les tests ci-dessous fixent d.unauthRetryMax explicitement.
	unauthRetryMaxDefault = -1
}

// waitRecorder remplace d.wait : mémorise les délais demandés sans attendre.
type waitRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (w *waitRecorder) wait(ctx context.Context, d time.Duration) error {
	w.mu.Lock()
	w.delays = append(w.delays, d)
	w.mu.Unlock()
	return ctx.Err()
}
func (w *waitRecorder) get() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.delays...)
}

// srv401 : refuse en 401 les n premiers handshakes (n < 0 : toujours), puis accepte et note les JWT vus.
func srv401(t *testing.T, n int32) (*httptest.Server, *atomic.Int32, *[]string, *sync.Mutex) {
	t.Helper()
	var reqs atomic.Int32
	var seen []string
	var mu sync.Mutex
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cnt := reqs.Add(1)
		mu.Lock()
		seen = append(seen, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		mu.Unlock()
		if n < 0 || cnt <= n {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(300 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs, &seen, &mu
}

func TestUnauthRetryDelayBoundsAndTotal(t *testing.T) {
	var total time.Duration
	for n := 1; n <= 3; n++ {
		lo := time.Duration(float64(unauthRetryBaseDefault) * float64(int(1)<<(n-1)) * 0.8)
		hi := time.Duration(float64(unauthRetryBaseDefault) * float64(int(1)<<(n-1)) * 1.2)
		for i := 0; i < 200; i++ {
			if d := unauthRetryDelay(unauthRetryBaseDefault, n); d < lo || d > hi {
				t.Fatalf("retry %d: %s outside [%s,%s]", n, d, lo, hi)
			}
		}
		total += lo
	}
	if total < 60*time.Second {
		t.Errorf("worst-case total %s must exceed the relay pong delay (~60 s)", total)
	}
}

// 401 transitoire puis succès : même JWT présenté, pas de ré-enrôlement, JWT local conservé.
func TestUnauthRetryTransient401ThenSuccessKeepsJWT(t *testing.T) {
	srv, reqs, seen, mu := srv401(t, 2)
	rec := &waitRecorder{}
	var reenrolled atomic.Bool
	orig := reEnrollOnce
	defer func() { reEnrollOnce = orig }()
	reEnrollOnce = func(context.Context, EnrollConfig, string) (string, error) {
		reenrolled.Store(true)
		return "should-not-happen", nil
	}
	jwtPath := t.TempDir() + "/token.jwt"
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "kept-jwt", Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{RegisterURL: srv.URL, Hostname: "h", PrivateKey: generateTestKey2048(t), EnrollmentToken: "tok", JWTPath: jwtPath})
	d.wait = rec.wait
	d.unauthRetryMax = 3
	writeFileT(t, jwtPath, "kept-jwt")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Run(ctx) }()
	// d.Run reads reEnrollOnce: it must be over before the deferred restore of the variable (LIFO: this runs first)
	defer func() { cancel(); <-done }()
	waitFor(t, "WS connected", func() bool { return d.connected.Load() })
	cancel()

	if reenrolled.Load() {
		t.Error("re-enrolled on a transient 401")
	}
	if n := reqs.Load(); n != 3 {
		t.Errorf("handshakes: %d, want 3", n)
	}
	mu.Lock()
	for _, j := range *seen {
		if j != "kept-jwt" {
			t.Errorf("JWT changed between retries: %q", j)
		}
	}
	mu.Unlock()
	if b := readFileT(t, jwtPath); b != "kept-jwt" {
		t.Errorf("token.jwt altered/erased: %q", b)
	}
	if got := rec.get(); len(got) != 2 || got[1] < got[0] {
		t.Errorf("delays %v: want 2 growing delays", got)
	}
}

// 401 persistant (agent révoqué ou refus durable) : N réessais bornés, puis comportement historique.
func TestUnauthRetryPersistent401ThenReenrollAfterN(t *testing.T) {
	srv, reqs, _, _ := srv401(t, -1)
	rec := &waitRecorder{}
	logs := captureLog(t)
	var reenrolls atomic.Int32
	orig := reEnrollOnce
	defer func() { reEnrollOnce = orig }()
	reEnrollOnce = func(context.Context, EnrollConfig, string) (string, error) {
		reenrolls.Add(1)
		return "fresh-jwt", nil
	}
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "old-jwt", Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{RegisterURL: srv.URL, Hostname: "h", PrivateKey: generateTestKey2048(t), EnrollmentToken: "tok"})
	d.wait = rec.wait
	d.unauthRetryMax = 3

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Run(ctx) }()
	// d.Run reads reEnrollOnce: wait for it before the deferred restore of the variable (LIFO: this runs first)
	defer func() { cancel(); <-done }()
	waitFor(t, "re-enrollment after the retries", func() bool { return reenrolls.Load() >= 1 })

	if n := reqs.Load(); n < 4 {
		t.Errorf("handshakes before re-enrollment: %d, want >= 4 (1 + 3 retries)", n)
	}
	if got := rec.get(); len(got) < 3 {
		t.Errorf("delays %v: want >= 3 retries", got)
	}
	// Après ré-enrôlement, le JWT neuf refusé à son tour ne déclenche pas de nouveaux réessais.
	waitFor(t, "second handshake wave", func() bool { return reqs.Load() >= 5 })
	if strings.Contains(logs.String(), "old-jwt") || strings.Contains(logs.String(), "fresh-jwt") {
		t.Error("JWT leaked in logs")
	}
}

// Sans jeton d'enrôlement réutilisable : réessais puis sortie 78 (comportement historique), borné.
func TestUnauthRetryNoEnrollmentTokenStopsAfterN(t *testing.T) {
	srv, reqs, _, _ := srv401(t, -1)
	rec := &waitRecorder{}
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "x", Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{RegisterURL: srv.URL, Hostname: "h", PrivateKey: generateTestKey2048(t)})
	d.wait = rec.wait
	d.unauthRetryMax = 3

	err := d.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "RELAY_ENROLLMENT_TOKEN") {
		t.Fatalf("got %v", err)
	}
	if ExitCode(err) != ExitEnrollmentRefused {
		t.Errorf("exit code %d", ExitCode(err))
	}
	if n := reqs.Load(); n != 4 {
		t.Errorf("handshakes: %d, want 4", n)
	}
}

// Révocation signalée par fermeture 4001 : aucun réessai, sortie 77.
func TestUnauthRetryRevoked4001NoRetry(t *testing.T) {
	rec := &waitRecorder{}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var reqs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(CloseCodeRevoked, "revoked"))
		time.Sleep(200 * time.Millisecond)
		_ = c.Close()
	}))
	defer srv.Close()
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "x", Insecure: true}, nil)
	d.wait = rec.wait
	d.unauthRetryMax = 3

	err := d.Run(context.Background())
	if err == nil || ExitCode(err) != ExitRevoked {
		t.Fatalf("got %v (code %d)", err, ExitCode(err))
	}
	if len(rec.get()) != 0 || reqs.Load() != 1 {
		t.Errorf("retried on revocation: delays %v, handshakes %d", rec.get(), reqs.Load())
	}
}

// Une connexion qui ne reçoit que des pings du relais reste ouverte (aucun délai de lecture côté
// minion) et répond par des pongs.
func TestPingOnlyConnectionStaysOpenAndPongs(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var pongs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		c.SetPongHandler(func(string) error { pongs.Add(1); return nil })
		go func() {
			for { // lecture nécessaire pour traiter les pongs
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for i := 0; i < 5; i++ {
			_ = c.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second))
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	d := NewDispatcher(ConnConfig{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), JWT: "x", Insecure: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_ = d.Run(ctx)
	if n := pongs.Load(); n < 4 {
		t.Errorf("pongs received by the relay: %d, want >= 4", n)
	}
}

func writeFileT(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}
