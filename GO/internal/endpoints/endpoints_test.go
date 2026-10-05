package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr error
	}{
		{"single", "wss://a.example:8443", []string{"wss://a.example:8443"}, nil},
		{"list with spaces", " wss://a.example , wss://b.example:9 ", []string{"wss://a.example", "wss://b.example:9"}, nil},
		{"scheme and host lowercased", "WSS://A.Example", []string{"wss://a.example"}, nil},
		{"empty", "", nil, ErrEmpty},
		{"blank", "   ", nil, ErrEmpty},
		{"empty item", "wss://a.example,,wss://b.example", nil, ErrInvalid},
		{"trailing comma", "wss://a.example,", nil, ErrInvalid},
		{"duplicate", "wss://a.example,wss://b.example, wss://A.example", nil, ErrDuplicate},
		{"duplicate trailing slash", "https://a.example/,https://a.example", nil, ErrDuplicate},
		{"userinfo", "wss://user:s3cret@a.example", nil, ErrUserinfo},
		{"userinfo no password", "wss://tok3n@a.example", nil, ErrUserinfo},
		{"no scheme", "a.example:8443", nil, ErrInvalid},
		{"no host", "wss://", nil, ErrInvalid},
		{"unparsable", "wss://a.example:port", nil, ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				for _, secret := range []string{"s3cret", "tok3n", "a.example"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("error echoes input (%q): %v", secret, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d urls, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].String() != tt.want[i] {
					t.Errorf("url %d = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseSchemes(t *testing.T) {
	if _, err := ParseSchemes("wss://a.example,ws://b.example", "wss"); !errors.Is(err, ErrScheme) {
		t.Fatalf("err = %v, want ErrScheme", err)
	}
	if _, err := ParseSchemes("wss://a.example,WSS://b.example", "wss"); err != nil {
		t.Fatal(err)
	}
}

func mustRotor(t *testing.T, list string, bo Backoff) *Rotor {
	t.Helper()
	urls, err := Parse(list)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRotor(urls, bo)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRotor_Order(t *testing.T) {
	r := mustRotor(t, "https://a,https://b,https://c", Backoff{})
	if got := r.Order(); !eqInts(got, []int{0, 1, 2}) {
		t.Fatalf("initial order %v", got)
	}
	r.Success(2)
	if got := r.Order(); !eqInts(got, []int{2, 0, 1}) {
		t.Fatalf("after Success(2) order %v", got)
	}
	r.Success(1)
	if got := r.Order(); !eqInts(got, []int{1, 0, 2}) {
		t.Fatalf("after Success(1) order %v", got)
	}
	r.Success(99) // ignored
	r.Failure(-1) // ignored
	if got := r.Order(); !eqInts(got, []int{1, 0, 2}) {
		t.Fatalf("out of range must be ignored, order %v", got)
	}
}

func TestRotor_Backoff(t *testing.T) {
	r := mustRotor(t, "https://a,https://b", Backoff{Min: time.Second, Max: 8 * time.Second})
	if d := r.Backoff(); d != 0 {
		t.Fatalf("fresh rotor backoff %v", d)
	}
	r.Failure(0)
	if d := r.Backoff(); d != 0 {
		t.Fatalf("incomplete round backoff %v", d)
	}
	want := []time.Duration{time.Second, time.Second, 2 * time.Second, 2 * time.Second,
		4 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, w := range want {
		r.Failure(i % 2)
		if d := r.Backoff(); d != w {
			t.Fatalf("after %d failures backoff = %v, want %v", i+2, d, w)
		}
	}
	r.Success(1)
	if d := r.Backoff(); d != 0 {
		t.Fatalf("backoff not reset after success: %v", d)
	}
	r.Failure(0)
	r.Failure(1)
	if d := r.Backoff(); d != time.Second {
		t.Fatalf("backoff after reset = %v, want 1s", d)
	}
}

func TestRotor_BackoffDefaultsAndNoOverflow(t *testing.T) {
	r := mustRotor(t, "https://a", Backoff{})
	for i := 0; i < 10000; i++ {
		r.Failure(0)
	}
	if d := r.Backoff(); d != time.Minute {
		t.Fatalf("backoff = %v, want default max 1m", d)
	}
	if _, err := NewRotor(nil, Backoff{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("NewRotor(nil) err = %v", err)
	}
}

func TestRotor_Wait(t *testing.T) {
	r := mustRotor(t, "https://a", Backoff{Min: 20 * time.Millisecond, Max: 20 * time.Millisecond})
	if err := r.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Failure(0)
	start := time.Now()
	if err := r.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 15*time.Millisecond {
		t.Fatal("Wait returned before the backoff")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait on cancelled ctx = %v", err)
	}
}

// tlsFixture starts n httptest TLS servers and returns a client trusting only
// the servers whose index is in trusted.
func trustPool(servers ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return pool
}

func urlsOf(t *testing.T, servers ...*httptest.Server) *Rotor {
	t.Helper()
	var l []string
	for _, s := range servers {
		l = append(l, s.URL)
	}
	return mustRotor(t, strings.Join(l, ","), Backoff{})
}

// getFn performs a full GET (dial + send + read) with the given trust pool.
func getFn(pool *x509.CertPool) func(context.Context, *url.URL) (string, error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}}
	return func(ctx context.Context, u *url.URL) (string, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+"/ping", nil)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
}

// closedAddr returns a TCP address on which nothing listens (connection refused).
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestDialFirst_RefusedThenSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "master") }))
	defer srv.Close()
	r := mustRotor(t, "https://"+closedAddr(t)+","+srv.URL, Backoff{})

	got, u, err := DialFirst(context.Background(), r, time.Second, getFn(trustPool(srv)))
	if err != nil {
		t.Fatal(err)
	}
	if got != "master" || u.String() != srv.URL {
		t.Fatalf("got %q from %v", got, u)
	}
	if o := r.Order(); !eqInts(o, []int{1, 0}) {
		t.Fatalf("last good address must be first, order %v", o)
	}
}

func TestDialFirst_BlackholeTimeoutPerAddress(t *testing.T) {
	r := mustRotor(t, "https://a.invalid,https://b.invalid,https://c.invalid", Backoff{})
	var calls int
	start := time.Now()
	_, _, err := DialFirst(context.Background(), r, 50*time.Millisecond,
		func(ctx context.Context, u *url.URL) (int, error) {
			calls++
			<-ctx.Done() // silent host: only the per-address timeout frees us
			return 0, MarkBeforeSend(ctx.Err())
		})
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v, want ErrAllFailed", err)
	}
	el := time.Since(start)
	if calls != 3 || el < 140*time.Millisecond || el > 2*time.Second {
		t.Fatalf("calls=%d elapsed=%v: timeout must apply to each address", calls, el)
	}
	if b := r.Backoff(); b != time.Second {
		t.Fatalf("a failed round must trigger the backoff, got %v", b)
	}
}

func TestDialFirst_SilentHostTLSHandshakeTimeout(t *testing.T) {
	// TCP accepted but never answers: the TLS handshake is bounded by the
	// per-address timeout and the next address is used.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	r := mustRotor(t, "https://"+silent.Addr().String()+","+srv.URL, Backoff{})
	pool := trustPool(srv)
	get := getFn(pool)
	start := time.Now()
	got, _, err := DialFirst(context.Background(), r, 200*time.Millisecond,
		func(ctx context.Context, u *url.URL) (string, error) {
			// Connection phase: TCP + TLS handshake only.
			d := tls.Dialer{Config: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
			c, err := d.DialContext(ctx, "tcp", u.Host)
			if err != nil {
				return "", MarkBeforeSend(err)
			}
			_ = c.Close()
			return get(ctx, u)
		})
	if err != nil || got != "ok" {
		t.Fatalf("got %q err %v", got, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("silent host blocked the list")
	}
}

func TestDialFirst_InvalidCertThenSuccess(t *testing.T) {
	bad := untrustedTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "bad") }))
	defer bad.Close()
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "good") }))
	defer good.Close()
	r := urlsOf(t, bad, good)

	logs := &logBuf{}
	defer captureLogs(logs)()
	got, u, err := DialFirst(context.Background(), r, time.Second, getFn(trustPool(good))) // bad's CA not trusted
	if err != nil {
		t.Fatal(err)
	}
	if got != "good" || u.String() != good.URL {
		t.Fatalf("got %q from %v", got, u)
	}
	if !strings.Contains(logs.String(), "tls=true") || !strings.Contains(logs.String(), "address=1") {
		t.Fatalf("TLS failure must be logged, logs: %s", logs.String())
	}
}

func TestDialFirst_InvalidCertEverywhere(t *testing.T) {
	bad := untrustedTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer bad.Close()
	r := urlsOf(t, bad)
	_, _, err := DialFirst(context.Background(), r, time.Second, getFn(x509.NewCertPool()))
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v, want ErrAllFailed", err)
	}
}

// TestDialFirst_NoRetryAfterSend is the central security invariant of the
// multi-address clients: once the request has been sent, a failure is never
// replayed on another address (an exec must not run twice).
func TestDialFirst_NoRetryAfterSend(t *testing.T) {
	var received1, received2 atomic.Int32
	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received1.Add(1)
		// Request received: cut the connection without answering.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv1.Close()
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received2.Add(1)
		_, _ = io.WriteString(w, "second")
	}))
	defer srv2.Close()
	r := urlsOf(t, srv1, srv2)

	got, _, err := DialFirst(context.Background(), r, time.Second, getFn(trustPool(srv1, srv2)))
	if err == nil {
		t.Fatalf("expected an error, got result %q", got)
	}
	if !errors.Is(err, ErrAfterSend) || errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v, want ErrAfterSend only", err)
	}
	if n := received1.Load(); n != 1 {
		t.Fatalf("server 1 received %d requests, want 1", n)
	}
	if n := received2.Load(); n != 0 {
		t.Fatalf("server 2 received %d requests after send, want 0", n)
	}
}

func TestDialFirst_NoRetryAfterSend_ServerStatusIsResult(t *testing.T) {
	// A non-nil error that is neither marked nor a connection-phase error is
	// after-send by default (fail safe).
	r := mustRotor(t, "https://a.invalid,https://b.invalid", Backoff{})
	var calls int
	_, _, err := DialFirst(context.Background(), r, time.Second,
		func(context.Context, *url.URL) (int, error) { calls++; return 0, errors.New("boom") })
	if !errors.Is(err, ErrAfterSend) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDialFirst_ContextCancelled(t *testing.T) {
	r := mustRotor(t, "https://a.invalid,https://b.invalid", Backoff{})
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	_, _, err := DialFirst(ctx, r, time.Second, func(c context.Context, _ *url.URL) (int, error) {
		calls++
		cancel()
		return 0, MarkBeforeSend(c.Err())
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if _, _, err := DialFirst[int](context.Background(), nil, time.Second, nil); err == nil {
		t.Fatal("nil rotor must fail")
	}
}

func TestDialFirst_NoURLNorTokenInErrorsOrLogs(t *testing.T) {
	r := mustRotor(t, "https://"+closedAddr(t)+"/path?token=SECRETTOKEN", Backoff{})
	logs := &logBuf{}
	defer captureLogs(logs)()
	client := &http.Client{}
	_, _, err := DialFirst(context.Background(), r, time.Second,
		func(ctx context.Context, u *url.URL) (int, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			resp, err := client.Do(req) // *url.Error embeds the full URL
			if err == nil {
				_ = resp.Body.Close()
			}
			return 0, err
		})
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v", err)
	}
	for _, out := range []string{err.Error(), logs.String()} {
		if strings.Contains(out, "SECRETTOKEN") || strings.Contains(out, "token=") || strings.Contains(out, "/path") {
			t.Fatalf("URL leaked: %s", out)
		}
	}
}

func TestIsBeforeSend(t *testing.T) {
	if IsBeforeSend(nil) || IsBeforeSend(io.EOF) || IsBeforeSend(errors.New("x")) {
		t.Fatal("nil/EOF/unknown must not be before-send")
	}
	if !IsBeforeSend(&net.DNSError{Err: "no such host", Name: "x"}) ||
		!IsBeforeSend(&net.OpError{Op: "dial", Err: errors.New("refused")}) ||
		!IsBeforeSend(MarkBeforeSend(errors.New("x"))) {
		t.Fatal("DNS/dial/marked must be before-send")
	}
	if IsBeforeSend(&net.OpError{Op: "read", Err: io.EOF}) {
		t.Fatal("read error is after send")
	}
	if MarkBeforeSend(nil) != nil {
		t.Fatal("MarkBeforeSend(nil) must be nil")
	}
}
