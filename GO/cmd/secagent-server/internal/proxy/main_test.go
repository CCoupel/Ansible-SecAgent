package proxy

import (
	"os"
	"sync"
	"testing"

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

func TestMain(m *testing.M) {
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
