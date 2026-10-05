package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
)

const toolsKey = "state-tools-master-key"

// toolsState builds a real state with two generations in a temporary directory.
func toolsState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := state.Init(state.InitOptions{Dir: dir, MasterKey: toolsKey, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey, BeforeWrite: func() error { return nil }, Instance: "tools"})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"alpha", "beta"} {
		h := h
		if err := e.Mutate(func(tx *state.Tx) error {
			return tx.PutAgent(state.Agent{Hostname: h, PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n" + strings.Repeat(h+"A", 60) + "\n-----END PUBLIC KEY-----\n", TokenJTI: "jti-" + h, EnrolledAt: time.Now()})
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		out[e.Name()] = string(b)
	}
	return out
}

func sameDir(t *testing.T, a, b map[string]string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("the directory changed: %d files before, %d after", len(a), len(b))
	}
	for k, v := range a {
		if b[k] != v {
			t.Errorf("%s was modified", k)
		}
	}
}

func execVerify(t *testing.T, minSeq uint64, args ...string) (string, int) {
	t.Helper()
	prev := stateVerifyMinSeq
	stateVerifyMinSeq = minSeq
	defer func() { stateVerifyMinSeq = prev }()
	var out bytes.Buffer
	stateVerifyCmd.SetOut(&out)
	stateVerifyCmd.SetErr(&out)
	err := stateVerifyCmd.RunE(stateVerifyCmd, args)
	return out.String() + errText(err), exitCodeOf(err)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error() + "\n"
}

func exitCodeOf(err error) int {
	var ee *ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.Code
	default:
		return 1
	}
}

func TestStateVerify_AuthenticStateExitsZeroWithoutAnySecret(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	dir := toolsState(t)
	out, code := execVerify(t, 0, filepath.Join(dir, state.StateFile))
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"schema_version: 1", "write_seq: 3", "writer_instance: tools", "agents: 2", "verdict: OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// walk the file for every secret-looking value: none may appear in the output
	raw := string(mustRead(t, filepath.Join(dir, state.StateFile)))
	for _, secret := range extractSecrets(raw) {
		if strings.Contains(out, secret) {
			t.Errorf("the output leaks %.20q", secret)
		}
	}
	if strings.Contains(out, "enc:") || strings.Contains(out, toolsKey) || strings.Contains(out, "jti-alpha") {
		t.Errorf("secret material in the output:\n%s", out)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// extractSecrets returns the long opaque values of the file (enc: values, hashes, hmac).
func extractSecrets(raw string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool { return r == '"' || r == ',' || r == ':' && false }) {
		if strings.HasPrefix(tok, "enc:") || (len(tok) >= 40 && !strings.ContainsAny(tok, " {}[]")) {
			out = append(out, tok)
		}
	}
	return out
}

func TestStateVerify_ExitCodes(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	dir := toolsState(t)
	state1 := filepath.Join(dir, state.StateFile)
	raw := string(mustRead(t, state1))
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "f")
		_ = os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	before := snapshotDir(t, dir)

	t.Run("payload tampered", func(t *testing.T) {
		out, code := execVerify(t, 0, write(strings.Replace(raw, `"alpha"`, `"alphb"`, 1)))
		if code != ExitAuthFailed || !strings.Contains(out, "falsifié") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})
	t.Run("sha256 field only", func(t *testing.T) {
		i := strings.Index(raw, `"sha256":"`) + len(`"sha256":"`)
		forged := raw[:i] + strings.Repeat("0", 64) + raw[i+64:]
		if _, code := execVerify(t, 0, write(forged)); code != ExitAuthFailed {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("wrong master key", func(t *testing.T) {
		t.Setenv("RSA_MASTER_KEY", "another-key")
		out, code := execVerify(t, 0, state1)
		if code != ExitAuthFailed || !strings.Contains(out, "clé maître incorrecte ou fichier falsifié") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})
	t.Run("no master key", func(t *testing.T) {
		t.Setenv("RSA_MASTER_KEY", "")
		if _, code := execVerify(t, 0, state1); code != ExitNoMasterKey {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("unknown schema", func(t *testing.T) {
		if _, code := execVerify(t, 0, write(strings.Replace(raw, `"schema_version":1`, `"schema_version":9`, 1))); code != ExitSchema {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("unreadable or absent", func(t *testing.T) {
		if _, code := execVerify(t, 0, filepath.Join(dir, "absent")); code != ExitUnreadable {
			t.Errorf("absent: exit %d", code)
		}
		if _, code := execVerify(t, 0, write("not a state file")); code != ExitUnreadable {
			t.Errorf("garbage: exit %d", code)
		}
	})
	t.Run("min-write-seq", func(t *testing.T) {
		prev := filepath.Join(dir, state.PrevFile) // write_seq 2
		if out, code := execVerify(t, 3, prev); code != ExitSeqTooLow || !strings.Contains(out, "too old") {
			t.Errorf("exit %d:\n%s", code, out)
		}
		if _, code := execVerify(t, 2, prev); code != ExitOK {
			t.Errorf("exit %d", code)
		}
	})
	sameDir(t, before, snapshotDir(t, dir)) // verify never writes
}

func TestVerifyExitMapsInvariants(t *testing.T) {
	for err, want := range map[error]int{
		state.ErrSecurityInvariant:                                       ExitInvariant,
		state.ErrStructure:                                               ExitInvariant,
		errors.Join(state.ErrCorrupt, state.ErrStructure):                ExitInvariant,
		errors.Join(state.ErrSecurityInvariant, state.ErrAuthentication): ExitAuthFailed,
		errors.Join(state.ErrCorrupt, state.ErrChecksum):                 ExitAuthFailed,
		state.ErrSchemaVersion:                                           ExitSchema,
		state.ErrNoMasterKey:                                             ExitNoMasterKey,
		errors.New("boom"):                                               ExitUnreadable,
	} {
		if got, _ := verifyExit(err); got != want {
			t.Errorf("%v -> %d, want %d", err, got, want)
		}
	}
}

// ── restore ──────────────────────────────────────────────────────────────────

func execRestore(t *testing.T, dir, from string, force bool) (string, int) {
	t.Helper()
	pd, pf, pm, pfo := stateRestoreDir, stateRestoreFrom, stateRestoreMinSeq, stateRestoreForce
	stateRestoreDir, stateRestoreFrom, stateRestoreMinSeq, stateRestoreForce = dir, from, 0, force
	defer func() { stateRestoreDir, stateRestoreFrom, stateRestoreMinSeq, stateRestoreForce = pd, pf, pm, pfo }()
	var out bytes.Buffer
	stateRestoreCmd.SetOut(&out)
	stateRestoreCmd.SetErr(&out)
	err := stateRestoreCmd.RunE(stateRestoreCmd, nil)
	return out.String() + errText(err), exitCodeOf(err)
}

func fastLockParams(t *testing.T) {
	t.Helper()
	prev := stateLockParams
	stateLockParams = func() lock.Params {
		return lock.Params{Check: 5 * time.Millisecond, CandidateStale: 40 * time.Millisecond, MasterStale: 120 * time.Millisecond}
	}
	t.Cleanup(func() { stateLockParams = prev })
}

func TestStateRestore_FromAValidPrevReplacesAtomicallyWithBackupAndJournal(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := toolsState(t)
	prevBytes := mustRead(t, filepath.Join(dir, state.PrevFile))
	out, code := execRestore(t, dir, filepath.Join(dir, state.PrevFile), false)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if string(mustRead(t, filepath.Join(dir, state.StateFile))) != string(prevBytes) {
		t.Error("relay.state must be the restored file")
	}
	fi, _ := os.Stat(filepath.Join(dir, state.StateFile))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
	var backups int
	for name := range snapshotDir(t, dir) {
		if strings.Contains(name, ".bak-") {
			backups++
		}
	}
	if backups != 2 {
		t.Errorf("%d backup files, want 2 (relay.state and relay.state.prev)", backups)
	}
	if !strings.Contains(out, "write_seq 3 -> 2") || !strings.Contains(out, "Restart the instances") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(dir, state.RestoreLogFile))), `"write_seq_after":2`) {
		t.Error("the intervention is not journaled")
	}
	// the server restarts on the restored state
	e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey})
	if err != nil || e.Snapshot().WriteSeq() != 2 {
		t.Fatalf("open after restore: %v", err)
	}
}

func TestStateRestore_RefusesATamperedSourceAndModifiesNothing(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := toolsState(t)
	raw := string(mustRead(t, filepath.Join(dir, state.PrevFile)))
	forged := filepath.Join(t.TempDir(), "forged")
	_ = os.WriteFile(forged, []byte(strings.Replace(raw, `"alpha"`, `"evil1"`, 1)), 0o600)
	before := snapshotDir(t, dir)
	out, code := execRestore(t, dir, forged, false)
	if code != ExitAuthFailed || !strings.Contains(out, "nothing modified") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
}

func TestStateRestore_RefusesWhileAnInstanceHoldsAFreshLock(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := toolsState(t)
	lockPath := filepath.Join(dir, lock.FileName)
	writeLockFile := func(beat uint64) {
		b := []byte(`{"instance_id":"live","role":"master","beat":` + itoa(beat) + `}`)
		pad := make([]byte, 256)
		copy(pad, b)
		for i := len(b); i < 256; i++ {
			pad[i] = ' '
		}
		_ = os.WriteFile(lockPath, pad, 0o700)
	}
	writeLockFile(1)
	var beat atomic.Uint64
	stop := make(chan struct{})
	go func() { // a live master: the beat counter keeps changing
		for {
			select {
			case <-stop:
				return
			case <-time.After(15 * time.Millisecond):
				writeLockFile(2 + beat.Add(1))
			}
		}
	}()
	before := snapshotDir(t, dir)
	out, code := execRestore(t, dir, filepath.Join(dir, state.PrevFile), false)
	if code != ExitInstanceAlive || !strings.Contains(out, "nothing modified") {
		close(stop)
		t.Fatalf("exit %d:\n%s", code, out)
	}
	// the live lock keeps changing the directory: compare only what restore could have touched
	after := snapshotDir(t, dir)
	for _, n := range []string{state.StateFile, state.PrevFile} {
		if before[n] != after[n] {
			t.Errorf("%s changed while refusing", n)
		}
	}
	for name := range after {
		if strings.Contains(name, ".bak-") || name == state.RestoreLogFile {
			t.Errorf("refused restore left %s", name)
		}
	}

	// the explicit option passes over it, loudly, and the journal records it
	out, code = execRestore(t, dir, filepath.Join(dir, state.PrevFile), true)
	close(stop)
	if code != 0 || !strings.Contains(out, "[SECURITY WARNING]") {
		t.Fatalf("with the override: exit %d:\n%s", code, out)
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(dir, state.RestoreLogFile))), `"lock_override":true`) {
		t.Error("the override must be recorded in the journal")
	}
}

func itoa(n uint64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestStateRestore_AStaleLockDoesNotBlock(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := toolsState(t)
	pad := make([]byte, 256)
	copy(pad, `{"instance_id":"dead","role":"master","beat":9}`)
	for i := range pad {
		if pad[i] == 0 {
			pad[i] = ' '
		}
	}
	_ = os.WriteFile(filepath.Join(dir, lock.FileName), pad, 0o700) // never changes again
	if out, code := execRestore(t, dir, filepath.Join(dir, state.PrevFile), false); code != 0 {
		t.Fatalf("a lock proven stale must not block: exit %d:\n%s", code, out)
	}
}

func TestStateRestore_RequiresFromAndTheMasterKey(t *testing.T) {
	fastLockParams(t)
	dir := toolsState(t)
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	if _, code := execRestore(t, dir, "", false); code != 1 {
		t.Errorf("no --from: exit %d", code)
	}
	t.Setenv("RSA_MASTER_KEY", "")
	if _, code := execRestore(t, dir, filepath.Join(dir, state.PrevFile), false); code != ExitNoMasterKey {
		t.Errorf("no master key: exit %d", code)
	}
}

// the command does not write or rename files itself: the replacement is the engine's.
func TestStateToolsDoNotWriteDirectly(t *testing.T) {
	src, err := os.ReadFile("state_tools.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"os.WriteFile", "os.Rename", "os.Create(", "ioutil."} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("state_tools.go uses %s", forbidden)
		}
	}
}
