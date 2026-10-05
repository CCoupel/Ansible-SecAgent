package server

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// testStateDir returns a directory holding an initial state: encrypted with RSA_MASTER_KEY when the
// test sets one (as `state init` does), in clear test mode otherwise. Builds in tests also pass
// InsecureTestState (ignored with a master key) and an allow-all WriteGuard: the lock of #163 is
// not part of these tests.
func testStateDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	key := os.Getenv("RSA_MASTER_KEY")
	if key == "" {
		s, err := storage.OpenTestDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		return dir
	}
	tpl := sealedTemplate(t, key)
	data, err := os.ReadFile(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, state.StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

var (
	sealedMu  sync.Mutex
	sealedTpl = map[string]string{}
)

func sealedTemplate(t testing.TB, key string) string {
	sealedMu.Lock()
	defer sealedMu.Unlock()
	if p, ok := sealedTpl[key]; ok {
		return p
	}
	dir, err := os.MkdirTemp("", "secagent-sealed-template-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Init(state.InitOptions{Dir: dir, MasterKey: key, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, state.StateFile)
	sealedTpl[key] = p
	return p
}

func allowWrites() error { return nil }

// serverJWTSecret is the secret the running node signs and verifies with: it comes from the state
// (created by `state init`), not from JWT_SECRET_KEY, which only bootstraps a state without one.
func serverJWTSecret() string {
	cur, _, _ := handlers.GetServerJWTSecrets()
	return cur
}
