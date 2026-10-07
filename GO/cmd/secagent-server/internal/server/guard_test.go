package server

// The write guard of a REAL instance (#163b): RunInstance wires lock.CheckOwnership on EVERY state
// write. A master whose lock was taken (another instance_id), or deleted, must write NOTHING: the
// refusal is visible (503 / error), relay.state is unchanged byte for byte and the engine counts no
// write. This is the core of "never two masters writing" and is pinned at the server level: with
// `cfg.WriteGuard = func() error { return nil }` in RunInstance every case below fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
)

// slowCheckParams keep the master's own identity check (Maintain) out of the test window: it ticks
// every 10 s, the test replaces the lock and writes within milliseconds, so ONLY the guard of the
// write can refuse. All Params invariants hold.
func slowCheckParams() lock.Params {
	return lock.Params{
		Beat: 12 * time.Second, Check: 10 * time.Second, SelfRetire: 30 * time.Second, MasterStale: 40 * time.Second,
		CandidateStale: 11 * time.Second, PauseMin: 350 * time.Millisecond, PauseMax: 600 * time.Millisecond,
		MaxWriteLatency: 250 * time.Millisecond,
	}
}

type instance struct {
	node     *Node
	stateDir string
	done     chan int
}

// startInstance runs RunInstance (real lock, real guard) until the node serves.
func startInstance(t *testing.T) *instance {
	t.Helper()
	t.Setenv("JWT_SECRET_KEY", "node-test-secret")
	t.Setenv("ADMIN_TOKEN", "node-test-admin")
	t.Setenv("RSA_MASTER_KEY", "node-test-master-key")
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent-hooks.json")
	t.Setenv("RELAY_ACTION_LOG", t.TempDir()+"/actions.log")
	dir := testStateDir(t)
	ready := make(chan *Node, 1)
	cfg := Config{
		TLSDisable: true, JWTSecret: "node-test-secret", AdminToken: "node-test-admin",
		StateDir: dir, InsecureTestState: true, LogLevel: "INFO",
		AdminAddr:  "127.0.0.1:0",
		StatusFile: filepath.Join(t.TempDir(), "status.json"),
		LockParams: slowCheckParams(),
		Listen: func(string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
		OnReady: func(n *Node) { ready <- n },
	}
	ctx, cancel := context.WithCancel(context.Background())
	in := &instance{stateDir: dir, done: make(chan int, 1)}
	go func() {
		code, _ := RunInstance(ctx, cfg)
		in.done <- code
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-in.done:
		case <-time.After(40 * time.Second):
			t.Error("RunInstance did not return")
		}
	})
	select {
	case in.node = <-ready:
	case code := <-in.done:
		t.Fatalf("instance exited with %d before serving", code)
	case <-time.After(30 * time.Second):
		t.Fatal("instance not ready")
	}
	return in
}

// stealLock replaces relay.lock the way another instance that took the lock would: a NEW file
// (new inode) carrying another instance_id.
func stealLock(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, lock.FileName)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"instance_id": "intruder-instance", "role": "master", "beat": 1})
	b = append(b, bytes.Repeat([]byte{' '}, 256-len(b))...)
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
}

func deleteLock(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, lock.FileName)); err != nil {
		t.Fatal(err)
	}
}

// call sends an admin request straight to the node's admin handler (the listeners are closed by the
// abort that follows the first refusal; the handlers are the same code).
func (in *instance) call(method, path string, body any) (int, string) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer node-test-admin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	in.node.AdminHandler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (in *instance) stateBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(in.stateDir, state.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGuard_AMasterWhoseLockWasTakenWritesNothing(t *testing.T) {
	type op struct {
		name string
		do   func(t *testing.T, in *instance) []int // HTTP statuses (or nil for a store-level op)
	}
	authorize := func(host string) func(*testing.T, *instance) []int {
		return func(t *testing.T, in *instance) []int {
			code, _ := in.call("POST", "/api/admin/authorize", map[string]any{"hostname": host, "public_key_pem": "pem", "approved_by": "ci"})
			return []int{code}
		}
	}
	ops := []op{
		{"authorize a key", authorize("guard-host")},
		{"create an enrollment token", func(t *testing.T, in *instance) []int {
			code, _ := in.call("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "hostname_pattern": ".*"})
			return []int{code}
		}},
		{"create a plugin token", func(t *testing.T, in *instance) []int {
			code, _ := in.call("POST", "/api/admin/tokens", map[string]any{"role": "plugin", "description": "x"})
			return []int{code}
		}},
		{"revoke an agent", func(t *testing.T, in *instance) []int {
			code, _ := in.call("POST", "/api/admin/revoke/victim", nil)
			return []int{code}
		}},
		{"register a relay", func(t *testing.T, in *instance) []int {
			code, _ := in.call("POST", "/api/admin/relays", map[string]any{"relay_id": "relay-x", "mode": "pull"})
			return []int{code}
		}},
		{"burst of 20 concurrent writes (group commit)", func(t *testing.T, in *instance) []int {
			codes := make([]int, 20)
			var wg sync.WaitGroup
			for i := range codes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					codes[i], _ = in.call("POST", "/api/admin/authorize", map[string]any{"hostname": "burst-" + string(rune('a'+i)), "public_key_pem": "pem", "approved_by": "ci"})
				}()
			}
			wg.Wait()
			return codes
		}},
		{"volatile update (status / last_seen: memory only, persisted by the next guarded write)", func(t *testing.T, in *instance) []int {
			// never a disk write by itself: it only rides on the next write, which the guard refuses
			_ = in.node.store.UpdateAgentStatus(context.Background(), "victim", "connected", "")
			return nil
		}},
		{"purge of the expired blacklist entries", func(t *testing.T, in *instance) []int {
			if _, err := in.node.store.PurgeExpiredBlacklist(context.Background()); err == nil {
				t.Error("the purge wrote through a lost lock")
			}
			return nil
		}},
	}
	steals := map[string]func(*testing.T, string){"another instance took the lock": stealLock, "the lock file was deleted": deleteLock}

	for stealName, steal := range steals {
		for _, o := range ops {
			t.Run(stealName+"/"+o.name, func(t *testing.T) {
				in := startInstance(t)
				ctx := context.Background()
				// state the operations act on, written while the lock is ours
				if err := in.node.store.UpsertAgent(ctx, "victim", "pem", "jti-victim"); err != nil {
					t.Fatal(err)
				}
				past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				reason := "t"
				if err := in.node.store.AddToBlacklist(ctx, "jti-expired", "victim", past, &reason); err != nil {
					t.Fatal(err)
				}
				if code, _ := in.call("POST", "/api/admin/authorize", map[string]any{"hostname": "baseline", "public_key_pem": "pem", "approved_by": "ci"}); code >= 300 {
					t.Fatalf("a write under our own lock must work: %d", code)
				}
				before, writes, seq := in.stateBytes(t), in.node.store.Engine().Writes(), in.node.store.WriteSeq()

				steal(t, in.stateDir)
				for _, code := range o.do(t, in) {
					if code >= 200 && code < 300 {
						t.Fatalf("a write was ACKNOWLEDGED (%d) by a master that no longer holds the lock", code)
					}
					// only a refusal is acceptable: a 400/404 would mean the request never reached the write
					if code != http.StatusServiceUnavailable && code != http.StatusInternalServerError {
						t.Errorf("status %d: the request must reach the write and be refused (503), not fail earlier", code)
					}
				}
				if after := in.stateBytes(t); !bytes.Equal(before, after) {
					t.Error("relay.state changed although the lock was lost")
				}
				if w := in.node.store.Engine().Writes(); w != writes {
					t.Errorf("the engine wrote %d time(s) after the loss", w-writes)
				}
				if s := in.node.store.WriteSeq(); s != seq {
					t.Errorf("write_seq moved %d -> %d", seq, s)
				}
				if _, err := os.Stat(filepath.Join(in.stateDir, state.StateFile+".tmp")); err == nil {
					t.Error("a temporary state file was created after the loss")
				}
			})
		}
	}
}

// The refusal is the visible 503 of the QA #160 R2 (the first refused write also aborts the node).
func TestGuard_RefusedWriteIsTheVisible503(t *testing.T) {
	in := startInstance(t)
	stealLock(t, in.stateDir)
	code, body := in.call("POST", "/api/admin/authorize", map[string]any{"hostname": "h", "public_key_pem": "pem", "approved_by": "ci"})
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "state_read_only") {
		t.Fatalf("%d %s, want 503 state_read_only", code, body)
	}
}
