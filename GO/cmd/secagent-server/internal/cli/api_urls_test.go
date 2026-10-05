package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deadAPI is a loopback address that refuses connections.
func deadAPI(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	u := s.URL
	s.Close()
	return u
}

// resetServer reads the request then closes the connection without answering: a write sent to it
// "may have been applied".
func resetServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	n := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		_ = c.Close()
	}))
	t.Cleanup(s.Close)
	return s, n
}

func okServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	n := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	return s, n
}

func TestAPIURLs_Parsing(t *testing.T) {
	t.Setenv("RELAY_API_URL", "")
	if l, err := apiURLs(); err != nil || len(l) != 1 || l[0] != "http://localhost:7771" {
		t.Errorf("default: %v %v", l, err)
	}
	t.Setenv("RELAY_API_URL", "https://a:7771/, https://b:7771")
	if l, err := apiURLs(); err != nil || len(l) != 2 || l[0] != "https://a:7771" || l[1] != "https://b:7771" {
		t.Errorf("list: %v %v", l, err)
	}
	for _, bad := range []string{"https://a,,https://b", "ftp://a", "https://u:p@a", "https://a,https://a", "a:7771"} {
		t.Setenv("RELAY_API_URL", bad)
		_, err := apiURLs()
		if err == nil {
			t.Errorf("%q must be refused", bad)
		} else if strings.Contains(err.Error(), "u:p") {
			t.Errorf("userinfo leaked: %v", err)
		}
	}
}

func TestAPIRequest_ReadSwitchesAddressOnAnyFailure(t *testing.T) {
	reset, _ := resetServer(t)
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", deadAPI(t)+","+reset.URL+","+ok.URL)
	data, status, err := apiRequest("GET", "/api/admin/relays", nil)
	if err != nil || status != 200 || !strings.Contains(string(data), "ok") {
		t.Fatalf("read: %s %d %v", data, status, err)
	}
	if okHits.Load() != 1 {
		t.Errorf("hits on the good address = %d", okHits.Load())
	}
}

func TestAPIRequest_WriteSwitchesOnlyWhenNothingWasSent(t *testing.T) {
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", deadAPI(t)+","+ok.URL)
	if _, status, err := apiRequest("POST", "/api/admin/relays", map[string]string{"a": "b"}); err != nil || status != 200 {
		t.Fatalf("a refused connection is before send, the next address is used: %d %v", status, err)
	}
	if okHits.Load() != 1 {
		t.Errorf("hits = %d, want 1", okHits.Load())
	}
}

func TestAPIRequest_WriteIsNotReplayedAfterItLeft(t *testing.T) {
	reset, resetHits := resetServer(t)
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", reset.URL+","+ok.URL)
	_, _, err := apiRequest("POST", "/api/admin/relays", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("the failed write must be reported")
	}
	if resetHits.Load() != 1 || okHits.Load() != 0 {
		t.Fatalf("hits: first=%d second=%d, want 1 and 0 (the write may have been applied)", resetHits.Load(), okHits.Load())
	}
}

// REPEATER_CA_FILE (#147): the admin API certificate is verified against that bundle only.
func TestAPIRequest_CAFileReplacesTheSystemRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) }))
	t.Cleanup(srv.Close)
	t.Setenv("RELAY_API_URL", srv.URL)

	// no CA file: the self-signed test certificate is not trusted by the system roots
	t.Setenv("REPEATER_CA_FILE", "")
	if _, _, err := apiRequest("GET", "/x", nil); err == nil {
		t.Fatal("an untrusted certificate must be refused without a CA file")
	}

	// the server's certificate as the CA file: trusted
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	good := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(good, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPEATER_CA_FILE", good)
	if data, status, err := apiRequest("GET", "/x", nil); err != nil || status != 200 {
		t.Fatalf("with the CA file: %s %d %v", data, status, err)
	}

	// another CA: refused
	otherPEM := unrelatedCAPEM(t) // (httptest servers all share one certificate: a distinct CA is needed)
	wrong := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(wrong, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPEATER_CA_FILE", wrong)
	if _, _, err := apiRequest("GET", "/x", nil); err == nil {
		t.Fatal("a certificate not issued by the configured CA must be refused")
	}
}

func TestAPIRequest_UnusableCAFileIsAnErrorNotAFallback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	t.Setenv("RELAY_API_URL", srv.URL)
	t.Setenv("REPEATER_CA_FILE", filepath.Join(t.TempDir(), "absent.pem"))
	if _, _, err := apiRequest("GET", "/x", nil); err == nil {
		t.Fatal("an unusable CA file must fail the call")
	}
	if hits.Load() != 0 {
		t.Fatal("no request may be sent when the CA file is unusable")
	}
}

// unrelatedCAPEM is a valid self-signed CA certificate that signed nothing.
func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "unrelated"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
