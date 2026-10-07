package enrollment

// #166 — multi-address enrollment: the one-shot token is never replayed on another address once
// the request has been sent.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/internal/endpoints"
	"secagent-server/internal/testnet"
)

// registerServer implements the two protocol steps of POST /api/register.
type registerServer struct {
	*httptest.Server
	step1, step2 atomic.Int32
	jwt          string
}

func newRegisterServer(t *testing.T, agent *rsa.PublicKey, serverKey *rsa.PrivateKey, jwt string, behave func(step int, w http.ResponseWriter, r *http.Request) bool) *registerServer {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	serverPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	rs := &registerServer{jwt: jwt}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		step := 1
		if _, ok := body["challenge_response"]; ok {
			step = 2
			rs.step2.Add(1)
		} else {
			rs.step1.Add(1)
		}
		if behave != nil && behave(step, w, r) {
			return
		}
		if step == 1 {
			nonce, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, agent, []byte("0123456789abcdef"), nil)
			_ = json.NewEncoder(w).Encode(map[string]string{"challenge": base64.StdEncoding.EncodeToString(nonce), "server_public_key_pem": serverPub})
			return
		}
		enc, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, agent, []byte(rs.jwt), nil)
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt_encrypted": base64.StdEncoding.EncodeToString(enc)})
	}))
	t.Cleanup(rs.Close)
	return rs
}

func closedBase(t *testing.T) string { t.Helper(); return "http://" + testnet.ClosedAddr(t) }

func rotorFor(t *testing.T, bases ...string) *endpoints.Rotor {
	t.Helper()
	var us []*url.URL
	for _, b := range bases {
		u, _ := url.Parse(b)
		us = append(us, u)
	}
	r, err := endpoints.NewRotor(us, endpoints.Backoff{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func multiKeys(t *testing.T) (agent, server *rsa.PrivateKey) {
	t.Helper()
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return a, s
}

func multiCfg(t *testing.T, key *rsa.PrivateKey, r *endpoints.Rotor) Config {
	t.Helper()
	return Config{Hostname: "h", PrivateKey: key, EnrollmentToken: "ONESHOT-TOKEN", Rotor: r, Insecure: true,
		JWTPath: filepath.Join(t.TempDir(), "token.jwt"), AttemptTimeout: 2 * time.Second}
}

func TestMultiEnroll_TCPRefusedOnTheFirstAddressThenEnrolledOnTheSecond(t *testing.T) {
	agent, serverKey := multiKeys(t)
	second := newRegisterServer(t, &agent.PublicKey, serverKey, "jwt-from-second", nil)
	r := rotorFor(t, closedBase(t), second.URL)
	jwt, err := Enroll(context.Background(), multiCfg(t, agent, r))
	if err != nil || jwt != "jwt-from-second" {
		t.Fatalf("jwt %q err %v", jwt, err)
	}
	if second.step1.Load() != 1 || second.step2.Load() != 1 {
		t.Errorf("both steps must run on the SAME instance: step1 %d step2 %d", second.step1.Load(), second.step2.Load())
	}
	if r.Head() != 1 {
		t.Errorf("the last good address must now be first, head %d", r.Head())
	}
}

// (b) the first server reads the body (the one-shot token left) and cuts the connection: the
// token is NOT sent to the second server, in this attempt.
func TestMultiEnroll_CutAfterSendOnTheFirstAddressIsNotReplayed(t *testing.T) {
	agent, serverKey := multiKeys(t)
	var firstHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		_, _ = io.ReadAll(r.Body) // the body, with the token, was received
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close() // ... and the connection is cut before any answer
		}
	}))
	defer first.Close()
	second := newRegisterServer(t, &agent.PublicKey, serverKey, "jwt-second", nil)
	r := rotorFor(t, first.URL, second.URL)

	_, err := Enroll(context.Background(), multiCfg(t, agent, r))
	if !errors.Is(err, endpoints.ErrAfterSend) {
		t.Fatalf("err = %v, want ErrAfterSend", err)
	}
	if n := second.step1.Load() + second.step2.Load(); n != 0 {
		t.Fatalf("the second server received %d request(s) after the token was sent to the first, want 0", n)
	}
	if firstHits.Load() != 1 {
		t.Errorf("first server hits %d", firstHits.Load())
	}
	if strings.Contains(err.Error(), "ONESHOT-TOKEN") {
		t.Error("the enrollment token leaked in the error")
	}
	// the NEXT cycle (a new attempt) starts on the other address: a frozen master does not starve it
	jwt, err := Enroll(context.Background(), multiCfg(t, agent, r))
	if err != nil || jwt != "jwt-second" {
		t.Fatalf("next cycle: %q %v", jwt, err)
	}
}

// the first server reads the request and then stays silent: timeout AFTER send => not replayed
func TestMultiEnroll_SilenceAfterSendIsNotReplayed(t *testing.T) {
	agent, serverKey := multiKeys(t)
	release := make(chan struct{})
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		<-release
	}))
	defer first.Close()
	defer close(release)
	second := newRegisterServer(t, &agent.PublicKey, serverKey, "jwt-second", nil)
	cfg := multiCfg(t, agent, rotorFor(t, first.URL, second.URL))
	cfg.AttemptTimeout = 400 * time.Millisecond
	_, err := Enroll(context.Background(), cfg)
	if !errors.Is(err, endpoints.ErrAfterSend) {
		t.Fatalf("err = %v, want ErrAfterSend", err)
	}
	if second.step1.Load()+second.step2.Load() != 0 {
		t.Fatal("the request was replayed on the second server")
	}
}

// step 2 fails after step 1 succeeded: the challenge lives on that instance, never move on.
func TestMultiEnroll_FailureAtStep2IsNotReplayedElsewhere(t *testing.T) {
	agent, serverKey := multiKeys(t)
	first := newRegisterServer(t, &agent.PublicKey, serverKey, "j", func(step int, w http.ResponseWriter, r *http.Request) bool {
		if step == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	second := newRegisterServer(t, &agent.PublicKey, serverKey, "jwt-second", nil)
	_, err := Enroll(context.Background(), multiCfg(t, agent, rotorFor(t, first.URL, second.URL)))
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 503 || he.Step != 2 {
		t.Fatalf("err = %v, want the step 2 HTTP 503", err)
	}
	if second.step1.Load() != 0 {
		t.Fatal("step 1 was replayed on the second server")
	}
}

func TestMultiEnroll_AllAddressesRefusedIsAFullRound(t *testing.T) {
	agent, _ := multiKeys(t)
	_, err := Enroll(context.Background(), multiCfg(t, agent, rotorFor(t, closedBase(t), closedBase(t))))
	if !errors.Is(err, endpoints.ErrAllFailed) {
		t.Fatalf("err = %v, want ErrAllFailed (safe to retry after the backoff)", err)
	}
}

func TestMultiEnroll_ForbiddenIsStillRecognised(t *testing.T) {
	agent, serverKey := multiKeys(t)
	first := newRegisterServer(t, &agent.PublicKey, serverKey, "j", func(step int, w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusForbidden)
		return true
	})
	second := newRegisterServer(t, &agent.PublicKey, serverKey, "j2", nil)
	_, err := Enroll(context.Background(), multiCfg(t, agent, rotorFor(t, first.URL, second.URL)))
	if !IsForbidden(err) {
		t.Fatalf("a 403 through the multi-address path must stay IsForbidden: %v", err)
	}
	if second.step1.Load() != 0 {
		t.Fatal("a 403 verdict must not be retried elsewhere")
	}
}
