package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/internal/endpoints"
)

const okInventory = `{"all":{"hosts":["h1"]},"_meta":{"hostvars":{"h1":{}}}}`

// counting returns a server answering with fn and counting the requests it received.
func counting(t *testing.T, fn http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		fn(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func okHandler(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(okInventory)) }

func deadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

func TestFetchInventory_DeadThenLiveAddress(t *testing.T) {
	live, n := counting(t, okHandler)
	inv, err := fetchInventory(config{serverURL: deadURL(t) + "," + live.URL})
	if err != nil || len(inv.All.Hosts) != 1 || n.Load() != 1 {
		t.Fatalf("inv=%v err=%v hits=%d", inv, err, n.Load())
	}
}

func TestFetchInventory_503MovesToTheNextAddress(t *testing.T) {
	first, n1 := counting(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	second, n2 := counting(t, okHandler)
	if _, err := fetchInventory(config{serverURL: first.URL + "," + second.URL}); err != nil {
		t.Fatal(err)
	}
	if n1.Load() != 1 || n2.Load() != 1 {
		t.Errorf("hits %d/%d, want 1/1", n1.Load(), n2.Load())
	}
}

func TestFetchInventory_AuthorizationErrorsAreFinal(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		first, _ := counting(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		second, n2 := counting(t, okHandler)
		_, err := fetchInventory(config{serverURL: first.URL + "," + second.URL})
		if err == nil || !strings.Contains(err.Error(), http.StatusText(code)) && !strings.Contains(err.Error(), "server returned") {
			t.Errorf("%d: err = %v", code, err)
		}
		if n2.Load() != 0 {
			t.Errorf("%d: the second address was tried (%d hits)", code, n2.Load())
		}
	}
}

func TestFetchInventory_AllUnreachableListsHostsWithoutToken(t *testing.T) {
	const token = "SECRET-TOKEN-VALUE"
	a, b := deadURL(t), deadURL(t)
	_, err := fetchInventory(config{serverURL: a + "," + b, token: token, scopeRelay: "SCOPE-QUERY-VALUE"})
	if err == nil {
		t.Fatal("expected an error")
	}
	ua, _ := neturl.Parse(a)
	ub, _ := neturl.Parse(b)
	msg := err.Error()
	for _, want := range []string{"2 address(es) tried", ua.Host, ub.Host} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q missing from %q", want, msg)
		}
	}
	for _, leak := range []string{token, "SCOPE-QUERY-VALUE", "/api/inventory"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the error leaks %q: %s", leak, msg)
		}
	}
}

func TestFetchInventory_TimeoutAfterSendReplaysTheIdempotentGET(t *testing.T) {
	old := perAddressTimeout
	perAddressTimeout = 200 * time.Millisecond
	defer func() { perAddressTimeout = old }()
	release := make(chan struct{})
	hang, nHang := counting(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	live, nLive := counting(t, okHandler)
	if _, err := fetchInventory(config{serverURL: hang.URL + "," + live.URL}); err != nil {
		t.Fatal(err)
	}
	if nHang.Load() != 1 || nLive.Load() != 1 {
		t.Errorf("hits %d/%d", nHang.Load(), nLive.Load())
	}
}

func TestFetchInventory_TotalCeiling(t *testing.T) {
	oldA, oldT := perAddressTimeout, fetchTotalTimeout
	perAddressTimeout, fetchTotalTimeout = time.Second, 300*time.Millisecond
	defer func() { perAddressTimeout, fetchTotalTimeout = oldA, oldT }()
	release := make(chan struct{})
	var hs []string
	for i := 0; i < 4; i++ {
		s, _ := counting(t, func(w http.ResponseWriter, r *http.Request) { <-release })
		hs = append(hs, s.URL)
	}
	defer close(release)
	start := time.Now()
	if _, err := fetchInventory(config{serverURL: strings.Join(hs, ",")}); err == nil {
		t.Fatal("expected an error")
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("the global ceiling was not applied: %v", d)
	}
}

func TestFetchInventory_InvalidListIsRefused(t *testing.T) {
	for _, v := range []string{"", "https://u:p@host", "https://a,https://a", "not a url"} {
		if _, err := fetchInventory(config{serverURL: v}); err == nil {
			t.Errorf("%q must be refused", v)
		}
	}
}

// TLS is verified per address: the CA trusts the second server only, the first one fails its
// handshake (before anything is sent) and the second serves the inventory.
func TestFetchInventory_TLSIsVerifiedPerAddress(t *testing.T) {
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(okHandler)) // its own certificate
	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	untrusted.StartTLS()
	defer untrusted.Close()
	trusted := httptest.NewTLSServer(http.HandlerFunc(okHandler))
	defer trusted.Close()
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw})
	if err := os.WriteFile(bundle, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchInventory(config{serverURL: untrusted.URL + "," + trusted.URL, caBundle: bundle}); err != nil {
		t.Fatalf("second address (trusted) must serve: %v", err)
	}
	if _, err := fetchInventory(config{serverURL: untrusted.URL, caBundle: bundle}); err == nil {
		t.Error("an untrusted certificate must be refused, never skipped")
	}
}

func TestCheckInsecureTLS_AppliesToEveryAddress(t *testing.T) {
	var sink strings.Builder
	cfg := config{serverURL: "https://localhost:7770,https://relay.example.com", insecure: true}
	if err := checkInsecureTLS(cfg, &sink); err == nil {
		t.Error("a non loopback address in the list must be refused without the ACK")
	}
	cfg.insecureAck = insecureAckValue
	if err := checkInsecureTLS(cfg, &sink); err != nil {
		t.Errorf("with the ACK: %v", err)
	}
	cfg = config{serverURL: "https://localhost:7770,https://127.0.0.1:7771", insecure: true}
	if err := checkInsecureTLS(cfg, &sink); err != nil {
		t.Errorf("only loopback addresses: %v", err)
	}
}

// Regression guard of the endpoints.MarkSent contract: a timeout after the request left is an
// "after send" failure (ErrAfterSend) for DialFirst, and the next address sees no connection. The
// inventory replays on purpose (idempotent GET), after DialFirst has said so.
func TestDialFirst_TimeoutAfterSendIsReportedAndNotReplayed(t *testing.T) {
	release := make(chan struct{})
	hang, _ := counting(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	second, n2 := counting(t, okHandler)
	var urls []*neturl.URL
	for _, s := range []string{hang.URL, second.URL} {
		u, _ := neturl.Parse(s)
		urls = append(urls, u)
	}
	rotor, err := endpoints.NewRotor(urls, endpoints.Backoff{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = endpoints.DialFirst(context.Background(), rotor, 200*time.Millisecond,
		func(ctx context.Context, u *neturl.URL) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+"/api/inventory", nil)
			return (&http.Client{}).Do(req)
		})
	if !errors.Is(err, endpoints.ErrAfterSend) {
		t.Fatalf("err = %v, want ErrAfterSend", err)
	}
	if n2.Load() != 0 {
		t.Errorf("the second server got %d connection(s)", n2.Load())
	}
}

// selfSigned returns a certificate for 127.0.0.1 that no test CA bundle trusts.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "untrusted"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// BAS-2: no redirection is ever followed; the token never reaches the host named by Location.
func TestFetchInventory_NeverFollowsARedirect(t *testing.T) {
	const token = "TOKEN-THAT-MUST-STAY-HOME"
	var otherAuth atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherAuth.Store(r.Header.Get("Authorization"))
		okHandler(w, r)
	}))
	defer other.Close()
	redirecting, _ := counting(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/inventory?secret=LOCATION-SECRET", http.StatusFound)
	})
	second, n2 := counting(t, okHandler)
	_, err := fetchInventory(config{serverURL: redirecting.URL + "," + second.URL, token: token})
	if err == nil || !strings.Contains(err.Error(), "302") || !strings.Contains(err.Error(), "redirection refused") {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{other.URL, "LOCATION-SECRET", token} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error echoes %q: %v", leak, err)
		}
	}
	if v := otherAuth.Load(); v != nil {
		t.Errorf("the redirect target was contacted (Authorization %q)", v)
	}
	if n2.Load() != 0 {
		t.Error("a redirect is final: no other address is tried")
	}
}

// BAS-1: http:// towards a non-loopback host is warned about (stderr), never refused, no token.
func TestWarnPlainHTTP(t *testing.T) {
	var sb strings.Builder
	warnPlainHTTP(config{serverURL: "http://localhost:7770,http://127.0.0.1:1,https://relay.example.com,http://relay2.example.com:7770", token: "SECRET-TOKEN"}, &sb)
	out := sb.String()
	if strings.Count(out, "[SECURITY WARNING]") != 1 || !strings.Contains(out, "#4 (relay2.example.com:7770)") || !strings.Contains(out, "https is required") {
		t.Errorf("warnings = %q", out)
	}
	if strings.Contains(out, "SECRET-TOKEN") || strings.Contains(out, "#1 ") || strings.Contains(out, "#2 ") || strings.Contains(out, "#3 ") {
		t.Errorf("unexpected content: %q", out)
	}
	sb.Reset()
	warnPlainHTTP(config{serverURL: "https://relay.example.com"}, &sb)
	if sb.Len() != 0 {
		t.Errorf("https must not warn: %q", sb.String())
	}
}

// N2: failed attempts are silent unless RELAY_INVENTORY_VERBOSE=1; the final error carries them.
func TestConfigureLogging_QuietUnlessVerbose(t *testing.T) {
	prev := slog.Default()
	defer slog.SetDefault(prev)
	var sb, before strings.Builder
	slog.SetDefault(slog.New(slog.NewTextHandler(&before, nil))) // what a default logger would have shown
	configureLogging(&sb, false)
	slog.Warn("endpoints: address failed before send", "address", 1)
	if sb.Len() != 0 || before.Len() != 0 {
		t.Errorf("quiet mode must replace the default logger and write nothing: %q %q", sb.String(), before.String())
	}
	configureLogging(&sb, true)
	slog.Warn("endpoints: address failed before send", "address", 1)
	if !strings.Contains(sb.String(), "address failed before send") {
		t.Errorf("verbose mode must show the detail: %q", sb.String())
	}
}

// N1: the final message says how many addresses were NOT tried for lack of time.
func TestFetchInventory_ReportsAddressesNotTriedForLackOfTime(t *testing.T) {
	oldA, oldT := perAddressTimeout, fetchTotalTimeout
	perAddressTimeout, fetchTotalTimeout = time.Second, 300*time.Millisecond
	defer func() { perAddressTimeout, fetchTotalTimeout = oldA, oldT }()
	release := make(chan struct{})
	var hs []string
	for i := 0; i < 4; i++ {
		s, _ := counting(t, func(w http.ResponseWriter, r *http.Request) { <-release })
		hs = append(hs, s.URL)
	}
	defer close(release)
	_, err := fetchInventory(config{serverURL: strings.Join(hs, ",")})
	if err == nil || !strings.Contains(err.Error(), "1 address(es) tried, 3 not tried (time budget)") {
		t.Fatalf("err = %v", err)
	}
}
