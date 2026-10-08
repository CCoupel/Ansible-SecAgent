package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"secagent-server/cmd/secagent-server/internal/auth"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// wsHooks holds the per-test implementations of the ws integration callbacks.
// ws.Relay*Func globals are assigned exactly once (TestMain), before any server
// goroutine exists, to dispatchers that read wsHooks under wsHooksMu. Tests only
// swap wsHooks, so a relay handler goroutine left over from a previous test
// (hijacked WebSocket, not awaited by httptest.Server.Close) never races with
// the setup of the next test.
type wsHooks struct {
	routing func(relayID string, hostnames []string) error
	status  func(relayID, status string, lastSeen int64) error
	isProxy func(relayID string, isProxy bool) error
}

var (
	wsHooksMu  sync.RWMutex
	curWSHooks wsHooks
)

func currentWSHooks() wsHooks {
	wsHooksMu.RLock()
	defer wsHooksMu.RUnlock()
	return curWSHooks
}

// /ws/relay fails closed without a link verifier: the test root key is installed once in TestMain.

// Link tokens (v3.0.4): /ws/relay verifies Ed25519 tokens signed by this test root.
var testRootPub, testRootPriv = func() (ed25519.PublicKey, ed25519.PrivateKey) {
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return p, k
}()

func signTestLink(sub, jti string) string {
	id, _ := ws.RelayIdentity()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "test-root", "sub": sub, "aud": id, "role": "relay-child", "jti": jti,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = auth.LinkKID(testRootPub)
	raw, err := tok.SignedString(testRootPriv)
	if err != nil {
		panic(err)
	}
	return raw
}

func installTestLinkTrust() {
	ws.SetLinkTrustFunc(func() (auth.LinkTrust, string, error) {
		return auth.LinkTrust{Current: testRootPub}, "test-root", nil
	})
}

func TestMain(m *testing.M) {
	ws.SetRelayJTIBlacklistFunc(func(string) (bool, error) { return false, nil }) // nothing revoked
	ws.SetRelayRevokedFunc(func(string) (bool, error) { return false, nil })
	installTestLinkTrust()
	ws.RelayRoutingBulkUpsertFunc = func(relayID string, hostnames []string) error {
		if fn := currentWSHooks().routing; fn != nil {
			return fn(relayID, hostnames)
		}
		return nil
	}
	ws.RelayStatusUpdateFunc = func(relayID, status string, lastSeen int64) error {
		if fn := currentWSHooks().status; fn != nil {
			return fn(relayID, status, lastSeen)
		}
		return nil
	}
	ws.RelayIsProxyUpdateFunc = func(relayID string, isProxy bool) error {
		if fn := currentWSHooks().isProxy; fn != nil {
			return fn(relayID, isProxy)
		}
		return nil
	}
	os.Exit(m.Run())
}

// setWSHooks installs h for the current test and restores the previous hooks
// on cleanup.
func setWSHooks(t *testing.T, h wsHooks) {
	t.Helper()
	wsHooksMu.Lock()
	prev := curWSHooks
	curWSHooks = h
	wsHooksMu.Unlock()
	t.Cleanup(func() {
		wsHooksMu.Lock()
		curWSHooks = prev
		wsHooksMu.Unlock()
	})
}

// awaitCond polls fn until it returns true or timeout expires, then fails the
// test. It replaces fixed sleeps used to wait for asynchronous server-side
// effects (routing DB updates, is_proxy persistence).
func awaitCond(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !fn() {
		t.Fatalf("timeout after %s waiting for: %s", timeout, what)
	}
}

// awaitInventoryLen waits until the aggregated relay inventory holds n entries.
func awaitInventoryLen(t *testing.T, r *ProxyRouter, n int) {
	t.Helper()
	awaitCond(t, 2*time.Second, "aggregated inventory size", func() bool {
		entries, err := r.AggregateRelayInventory()
		return err == nil && len(entries) == n
	})
}
