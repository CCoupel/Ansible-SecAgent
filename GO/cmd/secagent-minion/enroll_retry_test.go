package main

// #166b — the first enrollment keeps trying (backoff) over the address list: after-send failures
// are correctable and rotate the address for the NEXT round; a 403 is permanent; the one-shot token
// is never presented twice in one round.

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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
	"secagent-server/internal/endpoints"
)

func TestEnrollWithRetry_BackoffAndPermanentErrors(t *testing.T) {
	var delays []time.Duration
	wait := func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }

	calls := 0
	jwt, err := enrollWithRetry(context.Background(), func(context.Context) (string, error) {
		calls++
		if calls <= 9 {
			return "", fmt.Errorf("round: %w", endpoints.ErrAfterSend)
		}
		return "the-jwt", nil
	}, wait, time.Second, time.Minute)
	if err != nil || jwt != "the-jwt" || calls != 10 {
		t.Fatalf("jwt %q err %v calls %d", jwt, err, calls)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, w := range want {
		if delays[i] != w*time.Second {
			t.Fatalf("delays %v, want 1s..32s then capped at 60s", delays)
		}
	}

	// a 403 is permanent: one attempt, no wait
	delays, calls = nil, 0
	noWait := func(context.Context, time.Duration) error { return errors.New("a 403 must not be retried") }
	_, err = enrollWithRetry(context.Background(), func(context.Context) (string, error) {
		calls++
		return "", &enrollment.HTTPError{Step: 1, Status: http.StatusForbidden}
	}, noWait, time.Second, time.Minute)
	if !enrollment.IsForbidden(err) || calls != 1 || len(delays) != 0 {
		t.Fatalf("403: err %v calls %d delays %v", err, calls, delays)
	}

	// the context stops the retries
	ctx, cancel := context.WithCancel(context.Background())
	_, err = enrollWithRetry(ctx, func(context.Context) (string, error) {
		cancel()
		return "", errors.New("boom")
	}, wait, time.Second, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

// ── real enrollment client over two servers ──

type fakeRegister struct {
	*httptest.Server
	hits atomic.Int32
}

// cutAfterRead reads the whole request (the one-shot token left) and cuts the connection.
func cutAfterRead(t *testing.T) *fakeRegister {
	f := &fakeRegister{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		_, _ = io.ReadAll(r.Body)
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func forbidden(t *testing.T) *fakeRegister {
	f := &fakeRegister{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(f.Close)
	return f
}

func healthy(t *testing.T, agent *rsa.PublicKey, jwt string) *fakeRegister {
	t.Helper()
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	serverPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	f := &fakeRegister{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if _, step2 := body["challenge_response"]; !step2 {
			nonce, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, agent, []byte("0123456789abcdef"), nil)
			_ = json.NewEncoder(w).Encode(map[string]string{"challenge": base64.StdEncoding.EncodeToString(nonce), "server_public_key_pem": serverPub})
			return
		}
		enc, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, agent, []byte(jwt), nil)
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt_encrypted": base64.StdEncoding.EncodeToString(enc)})
	}))
	t.Cleanup(f.Close)
	return f
}

func rotorOf(t *testing.T, bases ...string) *endpoints.Rotor {
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

func realAttempt(t *testing.T, key *rsa.PrivateKey, r *endpoints.Rotor) func(context.Context) (string, error) {
	t.Helper()
	pub, _ := enrollment.PublicKeyPEM(key)
	jwtPath := filepath.Join(t.TempDir(), "token.jwt")
	return func(ctx context.Context) (string, error) {
		return enrollment.Enroll(ctx, enrollment.Config{
			Rotor: r, Hostname: "h", PublicKeyPEM: pub, PrivateKey: key, EnrollmentToken: "ONESHOT-TOKEN",
			JWTPath: jwtPath, Insecure: true, AttemptTimeout: 2 * time.Second,
		})
	}
}

func TestFirstEnrollment_HalfDeadFirstAddressThenTheSecondInTheNextRound(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	first := cutAfterRead(t)
	second := healthy(t, &key.PublicKey, "jwt-from-second")
	attempt := realAttempt(t, key, rotorOf(t, first.URL, second.URL))

	var waits int
	wait := func(context.Context, time.Duration) error {
		waits++
		// between the rounds: the token went to the first server ONLY, never to the second
		if second.hits.Load() != 0 || first.hits.Load() != 1 {
			t.Errorf("round 1 presented the token to the wrong servers: first %d second %d", first.hits.Load(), second.hits.Load())
		}
		return nil
	}
	jwt, err := enrollWithRetry(context.Background(), attempt, wait, time.Second, time.Minute)
	if err != nil || jwt != "jwt-from-second" {
		t.Fatalf("jwt %q err %v", jwt, err)
	}
	if waits != 1 {
		t.Errorf("waits %d, want exactly one backoff between the two rounds", waits)
	}
	if first.hits.Load() != 1 {
		t.Errorf("the half-dead first address was presented the token %d times, want 1 (the next round starts elsewhere)", first.hits.Load())
	}
	if second.hits.Load() != 2 { // both protocol steps
		t.Errorf("second server requests %d, want 2 (step 1 and 2)", second.hits.Load())
	}
}

func TestFirstEnrollment_SecondAddressAnswering403IsPermanent(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	first := cutAfterRead(t)
	second := forbidden(t) // the token was consumed by the first address
	attempt := realAttempt(t, key, rotorOf(t, first.URL, second.URL))
	waits := 0
	_, err := enrollWithRetry(context.Background(), attempt, func(context.Context, time.Duration) error { waits++; return nil }, time.Second, time.Minute)
	if !enrollment.IsForbidden(err) {
		t.Fatalf("want a permanent 403, got %v", err)
	}
	if waits != 1 || first.hits.Load() != 1 || second.hits.Load() != 1 {
		t.Errorf("waits %d first %d second %d: one round per address, never two presentations in a round", waits, first.hits.Load(), second.hits.Load())
	}
}

// the real process: first address cuts after reading, second answers 403 -> exit status 78.
func TestMinionProcess_HalfDeadFirstThen403Exits78(t *testing.T) {
	first := cutAfterRead(t)
	second := forbidden(t)
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := filepath.Join(dir, "id_rsa")
	if err := enrollment.StorePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	ws := func(u string) string { return "ws" + strings.TrimPrefix(u, "http") + "/ws/agent" }
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), runMainEnv + "=1",
		"RELAY_SERVER_URL=" + first.URL + "," + second.URL, "RELAY_WS_URL=" + ws(first.URL) + "," + ws(second.URL),
		"RELAY_PRIVATE_KEY=" + keyPath, "RELAY_JWT_PATH=" + filepath.Join(dir, "token.jwt"),
		"RELAY_ENROLLMENT_TOKEN=PROCESS-TOKEN", "RELAY_AGENT_HOSTNAME=exit-test", "RELAY_ASYNC_DIR=" + filepath.Join(dir, "async"),
		"RELAY_INSECURE_TLS=true",
	}
	done := make(chan []byte, 1)
	var runErr error
	go func() { out, e := cmd.CombinedOutput(); runErr = e; done <- out }()
	select {
	case out := <-done:
		ee, ok := runErr.(*exec.ExitError)
		if !ok || ee.ExitCode() != 78 {
			t.Fatalf("exit = %v, want 78\n%s", runErr, out)
		}
		if strings.Contains(string(out), "PROCESS-TOKEN") {
			t.Error("token leaked")
		}
		if first.hits.Load() != 1 || second.hits.Load() != 1 {
			t.Errorf("first %d second %d", first.hits.Load(), second.hits.Load())
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the minion did not stop")
	}
}

func TestFirstEnrollment_MissingTokenIsPermanentNotALoop(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfg := agentConfig{jwtPath: filepath.Join(dir, "none.jwt"), serverURL: "https://x", serverRotor: rotorOf(t, "https://127.0.0.1:1")}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // a missing check would retry forever
	defer cancel()
	if _, err := loadOrEnroll(ctx, cfg, "h", key); !errors.Is(err, errNoEnrollmentToken) {
		t.Fatalf("got %v", err)
	}
}
