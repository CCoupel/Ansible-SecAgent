package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCreatesTheStateThenTheServerCanOpenIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fresh", "state") // the directory is created too
	if err := Init(InitOptions{Dir: dir, MasterKey: "k", RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, StateFile)); m != 0o600 {
		t.Errorf("relay.state mode %o", m)
	}
	e, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("a freshly initialized state must open: %v", err)
	}
	snap := e.Snapshot()
	rsaKey, _ := snap.Config("rsa_key_current")
	jwtSecret, _ := snap.Config("jwt_secret_current")
	if !strings.HasPrefix(rsaKey, EncPrefix) || !strings.HasPrefix(jwtSecret, EncPrefix) {
		t.Errorf("secrets must be encrypted: %.12q %.12q", rsaKey, jwtSecret)
	}
	if snap.WriteSeq() != 1 {
		t.Errorf("write_seq %d", snap.WriteSeq())
	}
	// two inits produce different secrets (nothing deterministic)
	dir2 := t.TempDir()
	if err := Init(InitOptions{Dir: dir2, MasterKey: "k", RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e2, _ := Open(Options{Dir: dir2})
	j2, _ := e2.Snapshot().Config("jwt_secret_current")
	if j2 == jwtSecret {
		t.Error("two initializations share a JWT secret")
	}
}

func TestInitRefusesWhenAnythingAlreadyThere(t *testing.T) {
	for _, existing := range []string{StateFile, PrevFile, LockFile} {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, existing)
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := Init(InitOptions{Dir: dir, MasterKey: "k", RSABits: 2048})
			if err == nil || !strings.Contains(err.Error(), "refusing to initialize") || !strings.Contains(err.Error(), existing) {
				t.Fatalf("init over %s: %v", existing, err)
			}
			if got := string(mustFile(t, path)); got != "x" {
				t.Errorf("%s was modified", existing)
			}
			for _, other := range []string{StateFile, TmpFile} {
				if other == existing {
					continue
				}
				if _, err := os.Stat(filepath.Join(dir, other)); err == nil {
					t.Errorf("init created %s despite refusing", other)
				}
			}
		})
	}
}

func TestInitRequiresTheMasterKeyOutsideTestMode(t *testing.T) {
	dir := t.TempDir()
	err := Init(InitOptions{Dir: dir, RSABits: 2048})
	if err == nil || !strings.Contains(err.Error(), "RSA_MASTER_KEY") {
		t.Fatalf("init without a master key: %v", err)
	}
	if names := listDir(t, dir); len(names) != 0 {
		t.Errorf("nothing may be written: %v", names)
	}
	if err := Init(InitOptions{Dir: dir, AllowPlaintext: true, RSABits: 2048}); err != nil {
		t.Fatalf("test mode: %v", err)
	}
	e, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := e.Snapshot().Config("jwt_secret_current"); strings.HasPrefix(v, EncPrefix) {
		t.Error("test mode without key writes in clear")
	}
}
