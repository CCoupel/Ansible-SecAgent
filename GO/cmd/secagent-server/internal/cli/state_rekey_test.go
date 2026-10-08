package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/link"
	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

const rekeyNewKey = "state-tools-NEW-master-key"

func execRekey(t *testing.T, dir string, yes, tty bool, stdin string) (string, int) {
	t.Helper()
	pd, py, pt, pf := stateRekeyDir, stateRekeyYes, stateLTStdinTTY, stateRestoreForce
	stateRekeyDir, stateRekeyYes, stateLTStdinTTY, stateRestoreForce = dir, yes, func() bool { return tty }, false
	defer func() { stateRekeyDir, stateRekeyYes, stateLTStdinTTY, stateRestoreForce = pd, py, pt, pf }()
	var out bytes.Buffer
	stateRekeyCmd.SetOut(&out)
	stateRekeyCmd.SetErr(&out)
	stateRekeyCmd.SetIn(strings.NewReader(stdin))
	err := stateRekeyCmd.RunE(stateRekeyCmd, nil)
	return out.String() + errText(err), exitCodeOf(err)
}

func rekeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	t.Setenv("RSA_MASTER_KEY_FILE", "")
	t.Setenv("NEW_RSA_MASTER_KEY", rekeyNewKey)
	t.Setenv("NEW_RSA_MASTER_KEY_FILE", "")
	fastLockParams(t)
}

func TestStateRekey_RefusesWithoutConfirmationInNonInteractiveUse(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	before := snapshotDir(t, dir)
	out, code := execRekey(t, dir, false, false, "")
	if code != ExitRefused || !strings.Contains(out, "--yes") || !strings.Contains(out, "nothing modified") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
	if out, code := execRekey(t, dir, false, true, "yes\n"); code != ExitRefused || !strings.Contains(out, "cancelled") {
		t.Fatalf("a wrong answer must cancel: exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
}

func TestStateRekey_YesRotatesAndNamesNoKey(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	out, code := execRekey(t, dir, true, false, "")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"master key rotated", "relay.state.rekey.", "OLD key", "destroy"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, rekeyNewKey) || strings.Contains(out, toolsKey) {
		t.Error("the output must not carry a key")
	}
	if _, err := state.VerifyFile(filepath.Join(dir, state.StateFile), state.VerifyOptions{MasterKey: rekeyNewKey}); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if _, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey}); err == nil {
		t.Error("the old key must be refused")
	}
	// second run (new -> new) is refused cleanly
	t.Setenv("RSA_MASTER_KEY", rekeyNewKey)
	if out, code := execRekey(t, dir, true, false, ""); code != ExitRefused || !strings.Contains(out, "identical") {
		t.Errorf("re-run: exit %d:\n%s", code, out)
	}
}

func TestStateRekey_RefusesMissingSameOrBothNewKeys_WrongCurrentKey(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	before := snapshotDir(t, dir)

	t.Setenv("NEW_RSA_MASTER_KEY", "")
	if out, code := execRekey(t, dir, true, false, ""); code != ExitRefused || !strings.Contains(out, "NEW_RSA_MASTER_KEY") {
		t.Errorf("missing new key: exit %d:\n%s", code, out)
	}
	t.Setenv("NEW_RSA_MASTER_KEY", toolsKey)
	if out, code := execRekey(t, dir, true, false, ""); code != ExitRefused || !strings.Contains(out, "identical") {
		t.Errorf("same key: exit %d:\n%s", code, out)
	}
	// both the variable and the _FILE of the new key
	f := filepath.Join(t.TempDir(), "new.key")
	if err := os.WriteFile(f, []byte(rekeyNewKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEW_RSA_MASTER_KEY", rekeyNewKey)
	t.Setenv("NEW_RSA_MASTER_KEY_FILE", f)
	if out, code := execRekey(t, dir, true, false, ""); code == ExitOK {
		t.Errorf("both set must be refused:\n%s", out)
	}
	// a key file readable by others
	t.Setenv("NEW_RSA_MASTER_KEY", "")
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := execRekey(t, dir, true, false, ""); code == ExitOK {
		t.Errorf("a world-readable key file must be refused:\n%s", out)
	}
	// wrong current key
	t.Setenv("NEW_RSA_MASTER_KEY_FILE", "")
	t.Setenv("NEW_RSA_MASTER_KEY", rekeyNewKey)
	t.Setenv("RSA_MASTER_KEY", "not-the-current-key")
	if out, code := execRekey(t, dir, true, false, ""); code != ExitAuthFailed {
		t.Errorf("wrong current key: exit %d:\n%s", code, out)
	}
	t.Setenv("RSA_MASTER_KEY", "")
	if out, code := execRekey(t, dir, true, false, ""); code != ExitNoMasterKey {
		t.Errorf("no current key: exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
}

func TestStateRekey_NewKeyFromFile(t *testing.T) {
	rekeyEnv(t)
	t.Setenv("NEW_RSA_MASTER_KEY", "")
	f := filepath.Join(t.TempDir(), "new.key")
	if err := os.WriteFile(f, []byte(rekeyNewKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEW_RSA_MASTER_KEY_FILE", f)
	dir := toolsState(t)
	if out, code := execRekey(t, dir, true, false, ""); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if _, err := state.VerifyFile(filepath.Join(dir, state.StateFile), state.VerifyOptions{MasterKey: rekeyNewKey}); err != nil {
		t.Fatal(err)
	}
}

func TestStateRekey_RefusesWhileAnInstanceHoldsAFreshLock(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	lockPath := filepath.Join(dir, lock.FileName)
	write := func(beat uint64) {
		b := []byte(`{"instance_id":"live","role":"master","beat":` + itoa(beat) + `}`)
		pad := make([]byte, 256)
		copy(pad, b)
		for i := len(b); i < 256; i++ {
			pad[i] = ' '
		}
		_ = os.WriteFile(lockPath, pad, 0o700)
	}
	write(1)
	var beat uint64
	prevClock := stateLockClock
	stateLockClock = &virtualClock{now: time.Unix(1000, 0), onSleep: func(n int) {
		if n%3 == 0 {
			beat++
			write(2 + beat)
		}
	}}
	t.Cleanup(func() { stateLockClock = prevClock })
	before := snapshotDir(t, dir)
	out, code := execRekey(t, dir, true, false, "")
	if code != ExitInstanceAlive || !strings.Contains(out, "Stop every instance") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	after := snapshotDir(t, dir)
	for _, n := range []string{state.StateFile, state.PrevFile} {
		if before[n] != after[n] {
			t.Errorf("%s changed while refusing", n)
		}
	}
	for name := range after {
		if strings.Contains(name, "rekey") {
			t.Errorf("a refused rekey left %s", name)
		}
	}
}

// TOCTOU: a node takes relay.lock between the probe and the replacement.
func TestStateRekey_AbandonsWhenANodeTakesTheLockAfterTheProbe(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	stateBefore := mustRead(t, filepath.Join(dir, state.StateFile))
	stateRekeyAfterProbe = func() {
		_ = os.WriteFile(filepath.Join(dir, lock.FileName), []byte(`{"instance_id":"late","role":"candidate","beat":1}`), 0o700)
	}
	t.Cleanup(func() { stateRekeyAfterProbe = nil })
	out, code := execRekey(t, dir, true, false, "")
	if code != ExitInstanceAlive || !strings.Contains(out, "NOT modified") || !strings.Contains(out, "backup") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, state.StateFile)), stateBefore) {
		t.Error("relay.state must be untouched")
	}
	if _, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey}); err != nil {
		t.Errorf("the old key must still open the state: %v", err)
	}
}

// Integration: after the rotation a node started with the NEW key still serves its agents and still
// verifies the link tokens issued before (the signing key keeps its value, only its sealing changed).
func TestStateRekey_NodeRestartsWithNewKey_LinkTokensAndAgentsSurvive(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	open := func(key string) *storage.Store {
		s, err := storage.Open(state.Options{Dir: dir, MasterKey: key, BeforeWrite: func() error { return nil }, Instance: "rekey-it"})
		if err != nil {
			t.Fatalf("open with %q: %v", key, err)
		}
		return s
	}
	mgr := func(s *storage.Store, key string) *link.Manager {
		return &link.Manager{Store: s, MasterKey: func() (string, bool) { return key, true }, LocalID: func() string { return "central" }, IsRoot: func() bool { return true }}
	}
	s1 := open(toolsKey)
	m1 := mgr(s1, toolsKey)
	minted, err := m1.Mint(context.Background(), link.MintRequest{Role: auth.RoleRelayChild, Sub: "child", Aud: "central-parent", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	info1, err := m1.PublicInfo()
	if err != nil {
		t.Fatal(err)
	}

	if out, code := execRekey(t, dir, true, false, ""); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	s2 := open(rekeyNewKey)
	m2 := mgr(s2, rekeyNewKey)
	info2, err := m2.PublicInfo()
	if err != nil || info2.CurrentKID != info1.CurrentKID || info2.CurrentPEM != info1.CurrentPEM {
		t.Fatalf("the link signing key must keep its value: %+v vs %+v (%v)", info2, info1, err)
	}
	trust, rootID, err := m2.Trust()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.VerifyLinkToken(trust, minted.Token, auth.LinkWant{LocalID: "central-parent", RootID: rootID, Role: auth.RoleRelayChild}, time.Now()); err != nil {
		t.Errorf("a link token issued before the rotation must stay valid: %v", err)
	}
	if ags, err := s2.ListAgents(context.Background(), false); err != nil || len(ags) != 2 {
		t.Errorf("agents after rotation: %d (%v)", len(ags), err)
	}
}
