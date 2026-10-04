package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"secagent-server/cmd/secagent-server/internal/ws"
)

type pushCalls struct {
	mu      sync.Mutex
	started []string // relayID|url|token
	stopped []string
}

func setPushHooks(t *testing.T) *pushCalls {
	t.Helper()
	if os.Getenv("RSA_MASTER_KEY") == "" {
		t.Setenv("RSA_MASTER_KEY", "unit-test-master-key") // push registration fails closed without it
	}
	c := &pushCalls{}
	SetRelayPushHooks(func(relayID, url, token string) error {
		c.mu.Lock()
		c.started = append(c.started, relayID+"|"+url+"|"+token)
		c.mu.Unlock()
		return nil
	}, func(relayID string) {
		c.mu.Lock()
		c.stopped = append(c.stopped, relayID)
		c.mu.Unlock()
	})
	t.Cleanup(func() { SetRelayPushHooks(nil, nil) })
	return c
}

func createPush(t *testing.T, id, url, token string) *httptest.ResponseRecorder {
	t.Helper()
	return doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": id, "mode": "push", "url": url, "token": token,
	})
}

func TestPushRelay_HotStartWithClearToken(t *testing.T) {
	useFreshStores(t)
	calls := setPushHooks(t)
	rr := createPush(t, "dmz1", "wss://dmz1.example.com:7772", "child-signed-jwt")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if len(calls.started) != 1 || calls.started[0] != "dmz1|wss://dmz1.example.com:7772|child-signed-jwt" {
		t.Errorf("started = %v", calls.started)
	}
	if strings.Contains(rr.Body.String(), "child-signed-jwt") {
		t.Error("token echoed in the response")
	}
}

func TestPushRelay_RejectsInsecureOrMalformedTargets(t *testing.T) {
	useFreshStores(t)
	calls := setPushHooks(t)
	for name, url := range map[string]string{
		"ws":       "ws://dmz1:7772",
		"https":    "https://dmz1:7772",
		"http":     "http://dmz1:7770",
		"userinfo": "wss://alice:hunter2@dmz1:7772",
		"no host":  "wss://",
	} {
		rr := createPush(t, "dmz1", url, "tok")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "hunter2") || strings.Contains(rr.Body.String(), "alice") {
			t.Errorf("%s: userinfo echoed: %s", name, rr.Body.String())
		}
	}
	if rr := createPush(t, "bad id!", "wss://dmz1:7772", "tok"); rr.Code != http.StatusBadRequest {
		t.Errorf("bad relay_id: status %d", rr.Code)
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if len(calls.started) != 0 {
		t.Errorf("no dialer must start for rejected targets: %v", calls.started)
	}
}

func TestPushRelay_RefusesLoopingRelayID(t *testing.T) {
	useFreshStores(t)
	setPushHooks(t)
	ws.SetRelayLocalIDFunc(func() string { return "central" })
	ws.SetRelayAncestorsFunc(func() []string { return []string{"root"} })
	t.Cleanup(func() { ws.SetRelayLocalIDFunc(nil); ws.SetRelayAncestorsFunc(nil) })
	for _, id := range []string{"central", "root"} {
		if rr := createPush(t, id, "wss://x:7772", "tok"); rr.Code != http.StatusBadRequest {
			t.Errorf("relay_id %q: status %d, want 400 (loop)", id, rr.Code)
		}
	}
	if rr := createPush(t, "dmz1", "wss://x:7772", "tok"); rr.Code != http.StatusCreated {
		t.Errorf("non-looping id: status %d", rr.Code)
	}
}

func TestPushRelay_TokenEncryptedAtRestWithMasterKey(t *testing.T) {
	useFreshStores(t)
	t.Setenv("RSA_MASTER_KEY", "unit-test-master-key")
	setPushHooks(t)
	if rr := createPush(t, "dmz1", "wss://dmz1:7772", "child-signed-jwt"); rr.Code != http.StatusCreated {
		t.Fatalf("status %d", rr.Code)
	}
	node, err := adminStore.GetRelayNode("dmz1")
	if err != nil || node == nil {
		t.Fatalf("node: %v %v", node, err)
	}
	if strings.Contains(node.TokenHash, "child-signed-jwt") || !strings.HasPrefix(node.TokenHash, "enc:") {
		t.Errorf("token not encrypted at rest: %q", node.TokenHash)
	}
	got, err := OpenPushToken(node.TokenHash)
	if err != nil || got != "child-signed-jwt" {
		t.Errorf("OpenPushToken = %q, %v", got, err)
	}
	// encrypted row without the master key must fail closed, not return garbage
	t.Setenv("RSA_MASTER_KEY", "")
	if _, err := OpenPushToken(node.TokenHash); err == nil {
		t.Error("expected an error when the master key is missing")
	}
	// legacy plaintext rows still open
	if got, err := OpenPushToken("legacy-token"); err != nil || got != "legacy-token" {
		t.Errorf("legacy = %q %v", got, err)
	}
}

func TestPushRelay_TokenNeverListed(t *testing.T) {
	useFreshStores(t)
	setPushHooks(t)
	createPush(t, "dmz1", "wss://dmz1:7772", "child-signed-jwt")
	rr := doAdminRelayRequest(t, AdminListRelays, "GET", "/api/admin/relays", nil)
	if strings.Contains(rr.Body.String(), "child-signed-jwt") || strings.Contains(rr.Body.String(), "token") {
		t.Errorf("token exposed by the list: %s", rr.Body.String())
	}
}

func TestPushRelay_DeleteStopsDialer(t *testing.T) {
	useFreshStores(t)
	calls := setPushHooks(t)
	rr := createPush(t, "dmz1", "wss://dmz1:7772", "tok")
	var resp RelayCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/relays/"+resp.ID, nil)
	req.SetPathValue("id", resp.ID)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	AdminDeleteRelay(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status %d: %s", rec.Code, rec.Body.String())
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if len(calls.stopped) != 1 || calls.stopped[0] != "dmz1" {
		t.Errorf("stopped = %v", calls.stopped)
	}
}

func TestPushRelay_RefusedWithoutMasterKey(t *testing.T) {
	useFreshStores(t)
	calls := setPushHooks(t)
	t.Setenv("RSA_MASTER_KEY", "")
	rr := createPush(t, "dmz1", "wss://dmz1:7772", "child-signed-jwt")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (fail closed): %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "child-signed-jwt") {
		t.Error("token echoed")
	}
	if node, _ := adminStore.GetRelayNode("dmz1"); node != nil {
		t.Errorf("no row may be stored without the master key: %+v", node)
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if len(calls.started) != 0 {
		t.Error("no dialer may start")
	}
}

func TestPushToken_SealOpenRoundTripWrongKeyAndTamper(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "key-one")
	sealed, err := SealPushToken("secret-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "secret-jwt") || !strings.HasPrefix(sealed, "enc:") {
		t.Fatalf("not sealed: %q", sealed)
	}
	if got, err := OpenPushToken(sealed); err != nil || got != "secret-jwt" {
		t.Fatalf("round trip = %q %v", got, err)
	}
	// two seals of the same token differ (random nonce)
	if again, _ := SealPushToken("secret-jwt"); again == sealed {
		t.Error("sealing must be randomized")
	}
	// altered ciphertext is rejected (GCM authentication)
	b := []byte(sealed)
	b[len(b)-3] ^= 0x01
	if got, err := OpenPushToken(string(b)); err == nil {
		t.Errorf("tampered data accepted: %q", got)
	}
	// wrong key
	t.Setenv("RSA_MASTER_KEY", "key-two")
	if got, err := OpenPushToken(sealed); err == nil {
		t.Errorf("wrong key accepted: %q", got)
	}
	// missing key
	t.Setenv("RSA_MASTER_KEY", "")
	if _, err := OpenPushToken(sealed); err == nil {
		t.Error("missing key must fail")
	}
	if _, err := SealPushToken("x"); !errors.Is(err, ErrPushTokenKeyMissing) {
		t.Errorf("seal without key: %v", err)
	}
}
