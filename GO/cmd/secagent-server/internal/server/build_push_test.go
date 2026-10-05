package server

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// ── Build starts a Dialer for every push relay stored in the database (#155, qa H5) ──

// countingListener is a fake child: it counts TCP connection attempts and drops them.
type countingListener struct {
	ln       net.Listener
	attempts atomic.Int32
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &countingListener{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.attempts.Add(1)
			_ = conn.Close()
		}
	}()
	return c
}

func (c *countingListener) wssURL() string { return "wss://" + c.ln.Addr().String() }

// seedDB pre-populates a database file with relay rows and returns its URL.
func seedDB(t *testing.T, seed func(st *storage.Store)) string {
	t.Helper()
	path := testStateDir(t)
	st, err := openSeedStore(path)
	if err != nil {
		t.Fatal(err)
	}
	seed(st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildWith(t *testing.T, dbPath string, tune func(*Config)) *Node {
	t.Helper()
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	cfg := Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: dbPath, InsecureTestState: true, WriteGuard: allowWrites}
	if tune != nil {
		tune(&cfg)
	}
	n, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(n.Close)
	return n
}

func TestBuild_StartsADialerForEachStoredPushRelay(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "build-push-master-key")
	child := newCountingListener(t)
	sealed, err := handlers.SealPushToken("dmz-push", "child-signed-jwt")
	if err != nil {
		t.Fatal(err)
	}
	db := seedDB(t, func(st *storage.Store) {
		seedRelay(t, st, "dmz-push", "push", child.wssURL(), sealed)
		seedRelay(t, st, "dmz-pull", "pull", "", "sha256-of-jwt") // pull rows are never dialed
	})
	n := buildWith(t, db, nil)

	statuses := n.dialers.Statuses()
	if len(statuses) != 1 || statuses[0].RelayID != "dmz-push" {
		t.Fatalf("dialers = %+v, want exactly one for dmz-push (started by Build from the database)", statuses)
	}
	deadline := time.Now().Add(5 * time.Second)
	for child.attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if child.attempts.Load() == 0 {
		t.Error("the Dialer must actually dial the child")
	}
}

// A push row with an insecure URL is skipped with a warning and the node still starts.
func TestBuild_SkipsInsecurePushRowsWithoutBlockingStartup(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "build-push-master-key")
	sealed, err := handlers.SealPushToken("dmz-insecure", "child-signed-jwt")
	if err != nil {
		t.Fatal(err)
	}
	db := seedDB(t, func(st *storage.Store) {
		seedRelay(t, st, "dmz-insecure", "push", "ws://insecure:7772", sealed)
	})
	n := buildWith(t, db, nil)
	if got := n.dialers.Statuses(); len(got) != 0 {
		t.Errorf("no dialer may start for an insecure row: %+v", got)
	}
}

// A state sealed under another master key is refused as a whole (fail closed): the node does not
// start with secrets it can not authenticate.
func TestBuild_RefusesAStateSealedUnderAnotherMasterKey(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "key-at-registration-time")
	child := newCountingListener(t)
	sealed, _ := handlers.SealPushToken("dmz-sealed", "child-signed-jwt")
	db := seedDB(t, func(st *storage.Store) {
		seedRelay(t, st, "dmz-sealed", "push", child.wssURL(), sealed)
	})
	t.Setenv("RSA_MASTER_KEY", "another-key")
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	if _, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: db, WriteGuard: allowWrites}); err == nil {
		t.Fatal("a state that does not open with the configured master key must refuse to start")
	}
	time.Sleep(100 * time.Millisecond)
	if child.attempts.Load() != 0 {
		t.Errorf("the child must not be dialed (%d attempts)", child.attempts.Load())
	}
}

// openSeedStore opens the test state of dir the way Build will (same master key, if any).
func openSeedStore(dir string) (*storage.Store, error) {
	return storage.Open(state.Options{Dir: dir, MasterKey: os.Getenv("RSA_MASTER_KEY"), InsecureTestMode: os.Getenv("RSA_MASTER_KEY") == "",
		BeforeWrite: func() error { return nil }})
}
