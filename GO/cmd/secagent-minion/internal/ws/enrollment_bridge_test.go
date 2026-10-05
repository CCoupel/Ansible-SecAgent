package ws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testPubPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestReenrollStep1_UsesPublicKeyPEMField(t *testing.T) {
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/api/register") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenge":"Y2hhbGxlbmdl","server_public_key_pem":"c2VydmVy"}`))
	}))
	defer srv.Close()

	ec := EnrollConfig{
		Hostname:        "minion-1",
		EnrollmentToken: "tok",
		RegisterURL:     srv.URL + "/api/register",
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	pub := testPubPEM(t)
	_, _, _ = reenrollStep1(context.Background(), client, ec, pub)

	if !strings.Contains(body, `"public_key_pem"`) {
		t.Fatalf("reenroll step1 body missing public_key_pem: %q", body)
	}
	if strings.Contains(body, `"pubkey_pem"`) {
		t.Fatalf("reenroll step1 body still uses legacy pubkey_pem: %q", body)
	}
	// PEM newlines are JSON-escaped; the key value must still be present.
	escaped := strings.ReplaceAll(pub, "\n", "\\n")
	if !strings.Contains(body, escaped) && !strings.Contains(body, "PUBLIC KEY") {
		t.Fatalf("reenroll step1 body missing PEM value: %q", body)
	}
}
