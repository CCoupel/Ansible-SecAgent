package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #182: the server's rejection is a typed error, 403 is recognised as permanent, and no secret
// (enrollment token, public key) ends up in the error text.
func TestEnroll_RejectionIsATypedHTTPError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{http.StatusForbidden, http.StatusBadRequest, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		}))
		_, err := ReEnroll(context.Background(), Config{
			RegisterURL: srv.URL, Hostname: "h", PrivateKey: key, EnrollmentToken: "SECRET-TOKEN", Insecure: true,
		})
		srv.Close()
		var he *HTTPError
		if !errors.As(err, &he) || he.Status != status || he.Step != 1 {
			t.Fatalf("status %d: got %v, want *HTTPError{Step:1, Status:%d}", status, err, status)
		}
		if IsForbidden(err) != (status == http.StatusForbidden) {
			t.Errorf("status %d: IsForbidden = %v", status, IsForbidden(err))
		}
		if strings.Contains(err.Error(), "SECRET-TOKEN") || strings.Contains(err.Error(), "BEGIN PUBLIC KEY") {
			t.Errorf("secret in the error: %v", err)
		}
	}
	if IsForbidden(nil) || IsForbidden(errors.New("x")) {
		t.Error("IsForbidden must be false for nil and unrelated errors")
	}
}

// Wire contract: the field names the server reads (handlers/register.go) are the ones this client
// sends. A re-implementation with other names (pubkey_pem, response) was rejected in 400
// missing_fields: this test pins the names.
func TestEnroll_Step1UsesTheServerFieldNames(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, _ = ReEnroll(context.Background(), Config{RegisterURL: srv.URL, Hostname: "h", PrivateKey: key, EnrollmentToken: "t", Insecure: true})
	for _, field := range []string{`"hostname"`, `"public_key_pem"`, `"enrollment_token"`} {
		if !strings.Contains(body, field) {
			t.Errorf("step 1 body lacks %s: %.80s", field, body)
		}
	}
	for _, wrong := range []string{`"pubkey_pem"`, `"response"`} {
		if strings.Contains(body, wrong) {
			t.Errorf("step 1 body carries the obsolete field %s", wrong)
		}
	}
}
