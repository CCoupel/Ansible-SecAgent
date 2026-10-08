package state

// QA v3.0.4 survivors of `state rekey` — the end-to-end verification must catch what the HMAC alone does not:
// a rewritten state that is AUTHENTIC (valid HMAC under the new key) and DECRYPTABLE but WRONG. The test seam
// afterWrite replaces the freshly written file by such a state; the expectation is always the same: rollback,
// the original bytes back, an unchanged ability to open it with the old key.
//
// Not testable, and why: the check "the old key no longer opens the new state" cannot fail with real keys —
// the HMAC key is HKDF(master key), so no file is valid under two different keys; only a bug that wrote the
// new state with the old key would reach it, and that one is already caught one step earlier ("does not verify
// with the new key"). It is a belt-and-braces line, equivalent to its removal for every reachable input.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// forgeAfterWrite replaces the new state by a file that is valid for the NEW key (HMAC, schema, secrets that
// open with their binding) after `mutate` altered its decrypted payload.
func forgeAfterWrite(t *testing.T, mutate func(p *Payload)) func(FS, string) {
	t.Helper()
	return func(_ FS, dir string) {
		nopts := Options{MasterKey: rekeyNew}
		c, err := nopts.codec()
		if err != nil {
			t.Error(err)
			return
		}
		path := filepath.Join(dir, StateFile)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		m, env, err := c.decode(b, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		p := clonePayloadSecrets(m.Payload)
		mutate(&p)
		forged, err := c.encode(&p, env.WriteSeq, "forged", time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(path, forged, 0o600); err != nil {
			t.Error(err)
		}
	}
}

func expectRolledBack(t *testing.T, dir string, raw []byte, res *RekeyResult, err error) {
	t.Helper()
	if !errors.Is(err, ErrRekeyVerify) || res == nil || !res.Restored {
		t.Fatalf("res=%+v err=%v, want ErrRekeyVerify and Restored", res, err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("the original state must be put back byte for byte")
	}
	if _, verr := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyOld}); verr != nil {
		t.Errorf("the restored state must open with the OLD key: %v", verr)
	}
	if _, verr := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyNew}); verr == nil {
		t.Error("the restored state must NOT open with the new key")
	}
}

// Mutant: the comparison of the cleartexts (reflect.DeepEqual) removed.
func TestRekey_AnAuthenticButWrongRewrittenStateIsRolledBack(t *testing.T) {
	cases := map[string]func(p *Payload){
		"a secret re-sealed with an ALTERED cleartext": func(p *Payload) {
			sealed, err := SealSecret("ALTERED-"+"clear-"+ConfigLinkSigningKeyCurrent, rekeyNew, ConfigAAD(ConfigLinkSigningKeyCurrent))
			if err != nil {
				panic(err)
			}
			p.ServerConfig[ConfigLinkSigningKeyCurrent] = sealed
		},
		"the token_secret of a push relay re-sealed with another token": func(p *Payload) {
			n := p.RelayNodes["pushy"]
			sealed, err := SealSecret("another-push-token", rekeyNew, RelayTokenSecretAAD("pushy"))
			if err != nil {
				panic(err)
			}
			n.TokenSecret = sealed
			p.RelayNodes["pushy"] = n
		},
		"an encrypted field OMITTED": func(p *Payload) { delete(p.ServerConfig, "rsa_key_previous") },
		"a non-secret section altered (an agent dropped)": func(p *Payload) {
			delete(p.Agents, "alpha")
		},
		"a blacklist entry dropped": func(p *Payload) { delete(p.Blacklist, "revoked-1") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir, _ := rekeyState(t)
			raw := mustFile(t, filepath.Join(dir, StateFile))
			o := rekeyOpts(dir)
			o.afterWrite = forgeAfterWrite(t, mutate)
			res, err := Rekey(o)
			expectRolledBack(t, dir, raw, res, err)
		})
	}
}

// Control: the very same seam with a mutation that changes nothing is NOT a failure (the test above fails for
// the right reason, not because the seam breaks the file).
func TestRekey_TheForgingSeamAloneDoesNotFailAHonestRewrite(t *testing.T) {
	dir, _ := rekeyState(t)
	o := rekeyOpts(dir)
	o.afterWrite = forgeAfterWrite(t, func(*Payload) {})
	if res, err := Rekey(o); err != nil || res.Restored {
		t.Fatalf("res=%+v err=%v: an identical rewrite must verify", res, err)
	}
}

// (The refusal of a schema 1 state that this file used to test no longer exists: `state rekey` migrates a
// v1 state to v2 in the same atomic write. Its tests — v1.bak identical to the original, schema 2 under the
// new key, v3.0.3 refuses the result, backup/verification failure leaves the v1 usable, link data in a v1
// refused — are in rekey_v1_test.go; the CLI output in cli/state_rekey_v1_migrated_test.go.)

// failSyncDirFS fails the first SyncDir: the backup is written but not proven durable.
type failSyncDirFS struct {
	OSFS
	calls int
}

func (f *failSyncDirFS) SyncDir(d string) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("fsync of the directory failed (injected)")
	}
	return f.OSFS.SyncDir(d)
}

// "No durable backup, no rekey": the failure of SyncDir after the backup must surface and relay.state must
// not be replaced. Mutant: the error ignored.
func TestRekey_ABackupThatIsNotDurableStopsTheRekey(t *testing.T) {
	dir, _ := rekeyState(t)
	raw := mustFile(t, filepath.Join(dir, StateFile))
	o := rekeyOpts(dir)
	fs := &failSyncDirFS{}
	o.FS = fs
	res, err := Rekey(o)
	if err == nil || res != nil || !strings.Contains(err.Error(), "not durable") {
		t.Fatalf("res=%+v err=%v, want an error saying the backup is not durable", res, err)
	}
	if !bytes.Equal(raw, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("relay.state must be untouched when the backup is not durable")
	}
	if fs.calls != 1 {
		t.Errorf("SyncDir called %d times: nothing may go on after the failure", fs.calls)
	}
}

// noV1BackupFS fails the creation of relay.state.v1.bak(.tmp) only: the rekey backup itself works.
type noV1BackupFS struct{ OSFS }

func (f noV1BackupFS) CreateExclusive(name string, perm os.FileMode) (File, error) {
	if strings.HasPrefix(filepath.Base(name), V1BackupFile) {
		return nil, errors.New("disk full (injected)")
	}
	return f.OSFS.CreateExclusive(name, perm)
}

// "No v1 backup, no migration": when relay.state.v1.bak cannot be written, the v1 relay.state is not replaced
// (the rollback to v3.0.3 would be impossible). Mutant: the error of writeV1BackupData ignored.
func TestRekey_SchemaV1_WithoutTheV1BackupModifiesNothing(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1Keyed(t, dir, rekeyOld)
	o := rekeyOpts(dir)
	o.FS = noV1BackupFS{}
	res, err := Rekey(o)
	if err == nil || !strings.Contains(err.Error(), "v1 backup failed") {
		t.Fatalf("res=%+v err=%v, want a 'v1 backup failed' error", res, err)
	}
	if !bytes.Equal(v1, mustFile(t, filepath.Join(dir, StateFile))) {
		t.Error("relay.state must still be the original v1 file")
	}
	if _, serr := os.Stat(filepath.Join(dir, V1BackupFile)); serr == nil {
		t.Error("a partial relay.state.v1.bak was left")
	}
}
