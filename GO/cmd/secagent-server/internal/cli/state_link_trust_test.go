package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
)

// anchoredToolsState is toolsState plus the trust anchor of a non-root relay.
func anchoredToolsState(t *testing.T) string {
	t.Helper()
	dir := toolsState(t)
	e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey, BeforeWrite: func() error { return nil }, Instance: "tools"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Mutate(func(tx *state.Tx) error {
		return tx.SetLinkTrust(state.LinkTrust{RootID: "root", CurrentPub: strings.Repeat("A", 43), CurrentKID: "AAAAAAAAAAAAAAAAAAAAAA", Seq: 3})
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func execLTReset(t *testing.T, dir string, yes bool, tty bool, stdin string) (string, int) {
	t.Helper()
	pd, py, pt, pf := stateLTResetDir, stateLTResetYes, stateLTStdinTTY, stateRestoreForce
	stateLTResetDir, stateLTResetYes, stateLTStdinTTY, stateRestoreForce = dir, yes, func() bool { return tty }, false
	defer func() { stateLTResetDir, stateLTResetYes, stateLTStdinTTY, stateRestoreForce = pd, py, pt, pf }()
	var out bytes.Buffer
	stateLinkTrustResetCmd.SetOut(&out)
	stateLinkTrustResetCmd.SetErr(&out)
	stateLinkTrustResetCmd.SetIn(strings.NewReader(stdin))
	err := stateLinkTrustResetCmd.RunE(stateLinkTrustResetCmd, nil)
	return out.String() + errText(err), exitCodeOf(err)
}

func TestStateLinkTrustReset_RefusesWithoutConfirmationInNonInteractiveUse(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
	before := snapshotDir(t, dir)
	out, code := execLTReset(t, dir, false, false, "")
	if code != ExitRefused || !strings.Contains(out, "--yes") || !strings.Contains(out, "nothing modified") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
}

func TestStateLinkTrustReset_InteractiveAnswerIsChecked(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
	before := snapshotDir(t, dir)
	if out, code := execLTReset(t, dir, false, true, "yes\n"); code != ExitRefused || !strings.Contains(out, "cancelled") {
		t.Fatalf("a wrong answer must cancel: exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
	out, code := execLTReset(t, dir, false, true, "reset\n")
	if code != ExitOK || !strings.Contains(out, "cleared") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestStateLinkTrustReset_YesClearsOnlyTheAnchorAndNamesNoKey(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
	out, code := execLTReset(t, dir, true, false, "")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"cleared", "relay.state.linktrust-reset.", "REPEATER_ROOT_LINK_KEY_FILE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, strings.Repeat("A", 43)) {
		t.Error("the output must not carry a key")
	}
	e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey})
	if err != nil || !e.Snapshot().LinkTrust().IsZero() || e.Snapshot().AgentCount() != 2 {
		t.Fatalf("after reset: %v trust=%+v", err, e.Snapshot().LinkTrust())
	}
	// idempotent
	if out, code := execLTReset(t, dir, true, false, ""); code != ExitOK || !strings.Contains(out, "nothing to reset") {
		t.Errorf("second run: exit %d:\n%s", code, out)
	}
}

func TestStateLinkTrustReset_RefusesARootAndAWrongKey(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
	e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey, BeforeWrite: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Mutate(func(tx *state.Tx) error {
		v, _ := state.SealSecret("k", toolsKey, state.ConfigAAD(state.ConfigLinkSigningKeyCurrent))
		return tx.SetConfig(state.ConfigLinkSigningKeyCurrent, v)
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, dir)
	if out, code := execLTReset(t, dir, true, false, ""); code != ExitRefused || !strings.Contains(out, "root") {
		t.Fatalf("root: exit %d:\n%s", code, out)
	}
	t.Setenv("RSA_MASTER_KEY", "another-key")
	if out, code := execLTReset(t, dir, true, false, ""); code != ExitAuthFailed {
		t.Fatalf("wrong key: exit %d:\n%s", code, out)
	}
	sameDir(t, before, snapshotDir(t, dir))
}

func TestStateLinkTrustReset_RefusesWhileAnInstanceHoldsAFreshLock(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
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
	out, code := execLTReset(t, dir, true, false, "")
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
		if strings.Contains(name, "linktrust-reset") {
			t.Errorf("a refused reset left %s", name)
		}
	}
}

func TestStateLinkTrustReset_NoMasterKey(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "")
	dir := anchoredToolsState(t)
	if out, code := execLTReset(t, dir, true, false, ""); code != ExitNoMasterKey {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// A node that takes relay.lock between the probe and the replacement: the offline operation is
// abandoned, relay.state is untouched, the backup is kept (the guard re-reads the lock before the rename).
func TestStateLinkTrustReset_AbandonsWhenANodeTakesTheLockAfterTheProbe(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := anchoredToolsState(t)
	stateBefore := mustRead(t, filepath.Join(dir, state.StateFile))
	prevBefore := mustRead(t, filepath.Join(dir, state.PrevFile))
	stateLTAfterProbe = func() { // the node starts and takes the lock right after the probe concluded "absent"
		_ = os.WriteFile(filepath.Join(dir, lock.FileName), []byte(`{"instance_id":"late","role":"candidate","beat":1}`), 0o700)
	}
	t.Cleanup(func() { stateLTAfterProbe = nil })
	out, code := execLTReset(t, dir, true, false, "")
	if code != ExitInstanceAlive || !strings.Contains(out, "NOT modified") || !strings.Contains(out, "backup") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, state.StateFile)), stateBefore) || !bytes.Equal(mustRead(t, filepath.Join(dir, state.PrevFile)), prevBefore) {
		t.Error("relay.state / relay.state.prev must be untouched")
	}
	backups := 0
	for name := range snapshotDir(t, dir) {
		if strings.Contains(name, "linktrust-reset") && strings.HasSuffix(name, ".bak") {
			backups++
		}
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("leftover temporary file %s", name)
		}
	}
	if backups != 1 {
		t.Errorf("the backup must be kept: %d found", backups)
	}
	if e, err := state.Open(state.Options{Dir: dir, MasterKey: toolsKey}); err != nil || e.Snapshot().LinkTrust().IsZero() {
		t.Errorf("the anchor must still be there: %v", err)
	}
}

// The same guard protects 'state restore'.
func TestStateRestore_AbandonsWhenANodeTakesTheLockAfterTheProbe(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", toolsKey)
	fastLockParams(t)
	dir := toolsState(t)
	stateBefore := mustRead(t, filepath.Join(dir, state.StateFile))
	stateRestoreAfterProbe = func() {
		_ = os.WriteFile(filepath.Join(dir, lock.FileName), []byte(`{"instance_id":"late","role":"candidate","beat":1}`), 0o700)
	}
	t.Cleanup(func() { stateRestoreAfterProbe = nil })
	out, code := execRestore(t, dir, filepath.Join(dir, state.PrevFile), false)
	if code != ExitInstanceAlive || !strings.Contains(out, "NOT replaced") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(dir, state.StateFile)), stateBefore) {
		t.Error("relay.state must be untouched")
	}
}
