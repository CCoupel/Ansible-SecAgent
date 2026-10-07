package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string, notBefore, notAfter time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func validCA(t *testing.T, cn string) *testCA {
	return newCA(t, cn, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// serverCert issues a leaf for 127.0.0.1 signed by ca.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_UnsetMeansDefault(t *testing.T) {
	if cfg, err := Load(""); cfg != nil || err != nil {
		t.Fatalf("Load(\"\") = %v, %v", cfg, err)
	}
	t.Setenv(EnvCAFile, "  ")
	if cfg, err := FromEnv(); cfg != nil || err != nil {
		t.Fatalf("FromEnv blank = %v, %v", cfg, err)
	}
}

func TestLoad_ValidBundleReplacesTheSystemRoots(t *testing.T) {
	a, b := validCA(t, "ca-a"), validCA(t, "ca-b")
	cfg, err := Load(writeFile(t, append(append([]byte{}, a.pem...), b.pem...)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil || cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must never be set")
	}
	if n := len(cfg.RootCAs.Subjects()); n != 2 { //nolint:staticcheck // counting only the roots loaded from the file
		t.Fatalf("the pool holds %d roots, want exactly the 2 of the file (no system root)", n)
	}
}

func TestLoad_RefusesUnusableFiles(t *testing.T) {
	ca := validCA(t, "ca")
	keyDER, _ := x509.MarshalECPrivateKey(ca.key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	expired := newCA(t, "old", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	notYet := newCA(t, "future", time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	cases := map[string][]byte{
		"empty":                 {},
		"garbage":               []byte("this is not a pem file"),
		"private key in bundle": append(append([]byte{}, ca.pem...), keyPEM...),
		"trailing garbage":      append(append([]byte{}, ca.pem...), []byte("\nsecret-looking-trailer")...),
		"unparsable cert":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}),
		"only expired":          expired.pem,
		"only not yet valid":    notYet.pem,
		"too large":             append(append([]byte{}, ca.pem...), []byte(strings.Repeat("#", maxCAFileBytes))...),
	}
	for name, data := range cases {
		cfg, err := Load(writeFile(t, data))
		if err == nil || cfg != nil {
			t.Errorf("%s: want a refusal, got cfg=%v err=%v", name, cfg, err)
			continue
		}
		if !errors.Is(err, ErrInvalidCAFile) {
			t.Errorf("%s: error does not wrap ErrInvalidCAFile: %v", name, err)
		}
		for _, leak := range []string{"secret-looking-trailer", "PRIVATE KEY-----"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error leaks the file content: %v", name, err)
			}
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.pem")); !errors.Is(err, ErrInvalidCAFile) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrInvalidCAFile) {
		t.Errorf("a directory: %v", err)
	}
}

func TestLoad_ABundleWithAnExpiredAndAValidCertIsUsable(t *testing.T) {
	expired := newCA(t, "old", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	ok := validCA(t, "ok")
	if _, err := Load(writeFile(t, append(append([]byte{}, expired.pem...), ok.pem...))); err != nil {
		t.Fatalf("a rotated bundle must load: %v", err)
	}
}

// The real property: a server signed by the file's CA is trusted, one signed by another CA is not, and
// the system roots play no part (httptest's own certificate is untrusted too).
func TestLoad_VerifiesAgainstTheFileOnly(t *testing.T) {
	trusted, other := validCA(t, "trusted"), validCA(t, "other")
	cfg, err := Load(writeFile(t, trusted.pem))
	if err != nil {
		t.Fatal(err)
	}
	get := func(srvCert tls.Certificate) error {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
		srv.StartTLS()
		defer srv.Close()
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg.Clone()}, Timeout: 5 * time.Second}
		resp, err := c.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(trusted.serverCert(t)); err != nil {
		t.Errorf("a server signed by the configured CA must be trusted: %v", err)
	}
	if err := get(other.serverCert(t)); err == nil {
		t.Error("a server signed by another CA must be refused")
	}
}
