package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── #159b: HMAC of the state file, AAD-bound secrets, clear secrets, init, limits ──

const hmKey = "hardening-master-key"

// keyedState writes a valid, HMAC-authenticated state with sealed secrets into dir (via Init).
func keyedState(t *testing.T, dir string) {
	t.Helper()
	if err := Init(InitOptions{Dir: dir, MasterKey: hmKey, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
}

func openKeyed(dir string) (*Engine, error) {
	return Open(Options{Dir: dir, MasterKey: hmKey, BeforeWrite: allowAll, Instance: "t"})
}

// rewriteEnvelope lets a test act as an attacker with write access to the directory: it edits the
// raw envelope map and writes it back (with whatever checksum/HMAC the test chooses).
func rewriteEnvelope(t *testing.T, path string, edit func(env map[string]any, payload map[string]any)) {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(mustFile(t, path), &env); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, env["payload"])), &payload); err != nil {
		t.Fatal(err)
	}
	edit(env, payload)
	env["payload"] = payload
	if err := os.WriteFile(path, []byte(mustJSON(t, env)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// recomputeSHA gives the tampered payload a matching checksum (anyone can do that).
func recomputeSHA(t *testing.T, env map[string]any) {
	t.Helper()
	sum := sha256.Sum256([]byte(mustJSON(t, env["payload"])))
	env["sha256"] = hex.EncodeToString(sum[:])
}

func TestHMAC_WrittenAndVerified(t *testing.T) {
	dir := t.TempDir()
	keyedState(t, dir)
	var env struct {
		HMAC string `json:"hmac"`
	}
	if err := json.Unmarshal(mustFile(t, filepath.Join(dir, StateFile)), &env); err != nil || len(env.HMAC) != 64 {
		t.Fatalf("init with a master key must write an HMAC: %q %v", env.HMAC, err)
	}
	e, err := openKeyed(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustMutate(t, e, addAgent("h1")) // the engine keeps authenticating what it writes
	if _, err := openKeyed(dir); err != nil {
		t.Fatalf("a state written by the engine must reload: %v", err)
	}
	// another master key cannot open it
	if _, err := Open(Options{Dir: dir, MasterKey: "another"}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("wrong master key: %v", err)
	}
}

func TestHMAC_TamperedStateWithRecomputedChecksumIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyedState(t, dir)
	e, _ := openKeyed(dir)
	mustMutate(t, e, addAgent("victim")) // generation N (relay.state), N-1 in .prev
	mustMutate(t, e, func(tx *Tx) error {
		return tx.PutBlacklist(BlacklistEntry{JTI: "revoked", Hostname: "victim", ExpiresAt: time.Now().Add(time.Hour)})
	})
	path := filepath.Join(dir, StateFile)

	// attacker: drops the revocation (rollback of the blacklist) and recomputes the checksum,
	// without the master key => the HMAC no longer matches
	rewriteEnvelope(t, path, func(env, payload map[string]any) {
		payload["blacklist"] = map[string]any{}
		env["payload"] = payload
		recomputeSHA(t, env)
	})
	_, err := openKeyed(dir)
	if !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("tampered state with a recomputed checksum: %v, want ErrSecurityInvariant", err)
	}
	if strings.Contains(err.Error(), hmKey) {
		t.Error("the error leaks the master key")
	}
}

func TestHMAC_MissingOrFlippedIsRefusedWithoutFallbackOnAValidPrev(t *testing.T) {
	for name, edit := range map[string]func(env map[string]any){
		"hmac removed":    func(env map[string]any) { delete(env, "hmac") },
		"hmac flipped":    func(env map[string]any) { env["hmac"] = strings.Repeat("0", 64) },
		"hmac not hex":    func(env map[string]any) { env["hmac"] = "zz" },
		"seq bumped":      func(env map[string]any) { env["write_seq"] = float64(9999) },
		"writer replaced": func(env map[string]any) { env["writer_instance"] = "evil" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			keyedState(t, dir)
			e, _ := openKeyed(dir)
			mustMutate(t, e, addAgent("a")) // creates a VALID relay.state.prev
			if _, err := os.Stat(filepath.Join(dir, PrevFile)); err != nil {
				t.Fatal("test needs a valid .prev")
			}
			rewriteEnvelope(t, filepath.Join(dir, StateFile), func(env, _ map[string]any) { edit(env) })
			if _, err := openKeyed(dir); !errors.Is(err, ErrSecurityInvariant) {
				t.Fatalf("%s: %v, want ErrSecurityInvariant (a valid .prev must not mask a forgery)", name, err)
			}
		})
	}
}

func TestHMAC_PrevFollowsTheSameRule(t *testing.T) {
	dir := t.TempDir()
	keyedState(t, dir)
	e, _ := openKeyed(dir)
	mustMutate(t, e, addAgent("a"))
	// relay.state unreadable JSON (genuine corruption) -> .prev is used ... if it is authentic
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openKeyed(dir); err != nil {
		t.Fatalf("an authentic .prev must be usable after a corrupt relay.state: %v", err)
	}
	// ... but a forged .prev is refused (never silently accepted)
	rewriteEnvelope(t, filepath.Join(dir, PrevFile), func(env, payload map[string]any) { recomputeSHA(t, env); env["hmac"] = strings.Repeat("a", 64) })
	if _, err := openKeyed(dir); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("forged .prev: %v", err)
	}
	// interrupted write: relay.state absent, authentic .prev present -> automatic recovery
	dir2 := t.TempDir()
	keyedState(t, dir2)
	e2, _ := openKeyed(dir2)
	mustMutate(t, e2, addAgent("a"))
	if err := os.Remove(filepath.Join(dir2, StateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := openKeyed(dir2); err != nil {
		t.Fatalf("relay.state absent + authentic .prev must recover: %v", err)
	}
}

func TestHMAC_NoMasterKeyMeansNoHMAC(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir) // test-mode file, no HMAC
	if _, err := Open(Options{Dir: dir}); err != nil {
		t.Fatalf("test mode without key: %v", err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("a master key configured + a file without HMAC must be refused: %v", err)
	}
}

// swapping two ciphertexts between fields, even by an attacker who could re-authenticate the
// file, is rejected by the field binding (AAD).
func TestAAD_CiphertextSwappedBetweenFieldsIsRefused(t *testing.T) {
	c, err := (&Options{MasterKey: hmKey}).codec()
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := SealSecret("current-secret", hmKey, ConfigAAD("jwt_secret_current"))
	prev, _ := SealSecret("previous-secret", hmKey, ConfigAAD("jwt_secret_previous"))
	build := func(a, b string) string {
		dir := t.TempDir()
		p := newPayload()
		p.ServerConfig["jwt_secret_current"], p.ServerConfig["jwt_secret_previous"] = a, b
		data, err := c.encode(&p, 1, "t", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	if _, err := openKeyed(build(cur, prev)); err != nil {
		t.Fatalf("correctly bound secrets must load: %v", err)
	}
	if _, err := openKeyed(build(prev, cur)); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("swapped ciphertexts: %v, want ErrSecurityInvariant", err)
	}
	// a relay token_secret is bound to its relay: moving it to another relay is refused
	ts, _ := SealSecret("hmac-secret", hmKey, RelayTokenSecretAAD("relay-a"))
	p := newPayload()
	n := newRelay("relay-b", ModePush)
	n.TokenSecret = ts
	p.RelayNodes["relay-b"] = n
	data, _ := c.encode(&p, 1, "t", time.Now())
	dir := t.TempDir()
	if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := openKeyed(dir); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("token_secret moved to another relay: %v", err)
	}
}

func TestClearSecretsAreRefusedAtLoadWithoutFallback(t *testing.T) {
	mk := func(t *testing.T, prevValid bool) string {
		dir := t.TempDir()
		p := newPayload()
		p.ServerConfig["rsa_key_current"] = "-----BEGIN PRIVATE KEY-----clear"
		data, _ := encode(&p, 2, "t", time.Now())
		if prevValid {
			good := newPayload()
			gd, _ := encode(&good, 1, "t", time.Now())
			if err := atomicWrite(OSFS{}, dir, gd, false, nil); err != nil {
				t.Fatal(err)
			}
			if err := atomicWrite(OSFS{}, dir, data, true, nil); err != nil { // good one becomes .prev
				t.Fatal(err)
			}
		} else if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	dir := mk(t, true)
	for name, o := range map[string]Options{
		"no master key, no test mode (RequireEncryptedSecrets false)": {},
		"master key":                   {MasterKey: hmKey},
		"RequireEncryptedSecrets":      {RequireEncryptedSecrets: true},
		"test mode WITH a master key":  {MasterKey: hmKey, InsecureTestMode: true},
		"test mode + RequireEncrypted": {InsecureTestMode: true, RequireEncryptedSecrets: true},
	} {
		o.Dir = dir
		_, err := Open(o)
		if !errors.Is(err, ErrSecurityInvariant) {
			t.Errorf("%s: %v, want ErrSecurityInvariant (no fallback on the valid .prev)", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "BEGIN PRIVATE KEY") {
			t.Errorf("%s: the error leaks the secret", name)
		}
	}
	// the explicit test mode, without master key, accepts it
	if _, err := Open(Options{Dir: dir, InsecureTestMode: true}); err != nil {
		t.Fatalf("explicit test mode: %v", err)
	}
}

func TestInsecureTestModeIsRefusedWithAMasterKeyAtStartup(t *testing.T) {
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, AllowPlaintext: true, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, InsecureTestMode: true}); err != nil {
		t.Fatalf("a state init --insecure-test-mode state stays usable in test mode: %v", err)
	}
	if _, err := Open(Options{Dir: dir, InsecureTestMode: true, MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("test mode with a master key: %v", err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("clear state with a master key: %v", err)
	}
	// an otherwise perfectly valid, authenticated state does not make the mix acceptable
	good := t.TempDir()
	keyedState(t, good)
	if _, err := Open(Options{Dir: good, InsecureTestMode: true, MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("test mode with a master key on a valid state: %v", err)
	}
	// init itself refuses to mix them
	if err := Init(InitOptions{Dir: t.TempDir(), AllowPlaintext: true, MasterKey: hmKey, RSABits: 2048}); err == nil {
		t.Fatal("init --insecure-test-mode with RSA_MASTER_KEY must be refused")
	}
}

func TestInitConcurrentOnlyOneWins(t *testing.T) {
	dir := t.TempDir()
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Init(InitOptions{Dir: dir, MasterKey: hmKey, RSABits: 2048})
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !strings.Contains(err.Error(), "refusing to initialize") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d concurrent inits succeeded, want exactly 1", wins)
	}
	if names := listDir(t, dir); len(names) != 1 || names[0] != StateFile {
		t.Errorf("only relay.state may remain (no temporary file): %v", names)
	}
	if _, err := openKeyed(dir); err != nil {
		t.Fatalf("the winner's state must be valid: %v", err)
	}
}

func TestAtomicCreateNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	if err := atomicCreate(OSFS{}, dir, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := atomicCreate(OSFS{}, dir, []byte("second")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second create: %v", err)
	}
	if got := string(mustFile(t, filepath.Join(dir, StateFile))); got != "first" {
		t.Errorf("relay.state was replaced: %q", got)
	}
	if m := mode(t, filepath.Join(dir, StateFile)); m != 0o600 {
		t.Errorf("mode %o", m)
	}
}

func TestOversizedStateIsRejectedBeforeReading(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	if _, err := Open(Options{Dir: dir, MaxBytes: 50}); err == nil || !strings.Contains(err.Error(), "size ceiling") {
		t.Fatalf("state larger than the ceiling: %v", err)
	}
	// OSFS.ReadFileMax refuses before reading
	if _, err := (OSFS{}).ReadFileMax(filepath.Join(dir, StateFile), 10); !errors.Is(err, errTooBig) {
		t.Fatalf("ReadFileMax: %v", err)
	}
	if b, err := (OSFS{}).ReadFileMax(filepath.Join(dir, StateFile), 1<<20); err != nil || len(b) == 0 {
		t.Fatalf("ReadFileMax within the ceiling: %v", err)
	}
}

func TestSymlinkedStateIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	real := filepath.Join(dir, "elsewhere")
	if err := os.Rename(filepath.Join(dir, StateFile), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, StateFile)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Open(Options{Dir: dir}); err == nil {
		t.Fatal("a symbolic link in place of relay.state must be refused")
	}
}

// R4: the guard is re-checked right before the rename.
func TestGuardIsRecheckedJustBeforeTheRename(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	calls := 0
	e := openEngine(t, dir, func(o *Options) {
		o.BeforeWrite = func() error {
			calls++
			if calls >= 2 {
				return errors.New("lock lost")
			}
			return nil
		}
	})
	before := mustFile(t, filepath.Join(dir, StateFile))
	err := e.Mutate(addAgent("late"))
	if err == nil || !strings.Contains(err.Error(), "lock lost") {
		t.Fatalf("a guard that fails at the second check must cancel the write: %v", err)
	}
	if calls != 2 {
		t.Errorf("guard called %d times, want 2 (before the batch and before the rename)", calls)
	}
	if string(mustFile(t, filepath.Join(dir, StateFile))) != string(before) {
		t.Error("relay.state changed")
	}
	if _, ok := e.Snapshot().Agent("late"); ok {
		t.Error("memory ahead of the disk")
	}
	for _, n := range listDir(t, dir) {
		if strings.HasPrefix(n, TmpFile) {
			t.Errorf("temporary file left: %s", n)
		}
	}
}

func TestPullRelayWithoutTokenHashIsLogged(t *testing.T) {
	buf := captureSlog(t)
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	n := newRelay("pull-1", ModePull)
	n.TokenHash = ""
	mustMutate(t, e, func(tx *Tx) error { return tx.PutRelayNode(n) })
	if !strings.Contains(buf.String(), `pull relay \"pull-1\" registered without token_hash`) {
		t.Errorf("INFO log missing: %s", buf.String())
	}
}
