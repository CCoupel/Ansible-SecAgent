package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const resetKey = "link-trust-reset-master-key"

// anchoredState builds a sealed state of a NON-ROOT relay: two agents, a blacklist entry and an anchor.
func anchoredState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: resetKey, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e, err := Open(Options{Dir: dir, MasterKey: resetKey, BeforeWrite: func() error { return nil }, Instance: "reset-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Mutate(func(tx *Tx) error {
		for _, h := range []string{"alpha", "beta"} {
			if err := tx.PutAgent(Agent{Hostname: h, PublicKeyPEM: testPEM(h), TokenJTI: "jti-" + h, EnrolledAt: time.Unix(1700000000, 0).UTC()}); err != nil {
				return err
			}
		}
		if err := tx.PutBlacklist(BlacklistEntry{JTI: "revoked-1", RevokedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
			return err
		}
		return tx.SetLinkTrust(LinkTrust{RootID: "root", CurrentPub: pub32(1), CurrentKID: "AAAAAAAAAAAAAAAAAAAAAA", PreviousPub: pub32(2), PreviousKID: "BBBBBBBBBBBBBBBBBBBBBB", Seq: 5})
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func resetOpts(dir string) LinkTrustResetOptions {
	return LinkTrustResetOptions{Dir: dir, MasterKey: resetKey, Operator: "tester"}
}

func TestResetLinkTrust_ClearsOnlyTheAnchor_BackupFirst_HMACValid(t *testing.T) {
	dir := anchoredState(t)
	before := mustFile(t, filepath.Join(dir, StateFile))
	res, err := ResetLinkTrust(resetOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.RootID != "root" || res.Seq != 5 || res.SeqAfter != res.SeqBefore+1 {
		t.Fatalf("result = %+v", res)
	}
	// the backup is the exact file that was verified, 0600
	bak := filepath.Join(dir, res.BackupFile)
	if !strings.HasPrefix(res.BackupFile, StateFile+".linktrust-reset.") || !strings.HasSuffix(res.BackupFile, ".bak") {
		t.Errorf("backup name %q", res.BackupFile)
	}
	if !bytes.Equal(mustFile(t, bak), before) || mode(t, bak) != 0o600 {
		t.Error("the backup must be the verified file, mode 0600")
	}
	// HMAC / schema / invariants valid, anchor gone, everything else intact
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: resetKey})
	if err != nil || rep.WriteSeq != res.SeqAfter || rep.LinkTrustCurrentKID != "" || rep.LinkTrustSeq != 0 {
		t.Fatalf("verify after: %+v %v", rep, err)
	}
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = resetKey })
	snap := e.Snapshot()
	if !snap.LinkTrust().IsZero() || snap.AgentCount() != 2 || !snap.Blacklisted("revoked-1") {
		t.Errorf("only link_trust may change: trust=%+v agents=%d", snap.LinkTrust(), snap.AgentCount())
	}
	if _, ok := snap.Config("rsa_key_current"); !ok {
		t.Error("server_config must be untouched")
	}
	// the journal names no key
	j := string(mustFile(t, filepath.Join(dir, RestoreLogFile)))
	if !strings.Contains(j, `"source":"link-trust-reset"`) || strings.Contains(j, pub32(1)) {
		t.Errorf("journal = %s", j)
	}
	// relay.state.prev keeps the previous generation (rollback of the rollback)
	if !bytes.Equal(mustFile(t, filepath.Join(dir, PrevFile)), before) {
		t.Error("relay.state.prev must be the state before the reset")
	}
}

func TestResetLinkTrust_IsIdempotent(t *testing.T) {
	dir := anchoredState(t)
	if _, err := ResetLinkTrust(resetOpts(dir)); err != nil {
		t.Fatal(err)
	}
	snapshot := listDir(t, dir)
	state1 := mustFile(t, filepath.Join(dir, StateFile))
	res, err := ResetLinkTrust(resetOpts(dir))
	if err != nil || res.Changed || res.BackupFile != "" {
		t.Fatalf("second reset: %+v %v", res, err)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), state1) || len(listDir(t, dir)) != len(snapshot) {
		t.Error("an idempotent reset must write nothing (no backup, no new generation)")
	}
}

func TestResetLinkTrust_RefusesARootAndWritesNothing(t *testing.T) {
	dir := anchoredState(t)
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = resetKey })
	if err := e.Mutate(func(tx *Tx) error {
		sealed, _ := SealSecret("k", resetKey, ConfigAAD(ConfigLinkSigningKeyCurrent))
		return tx.SetConfig(ConfigLinkSigningKeyCurrent, sealed)
	}); err != nil {
		t.Fatal(err)
	}
	before := mustFile(t, filepath.Join(dir, StateFile))
	files := listDir(t, dir)
	if _, err := ResetLinkTrust(resetOpts(dir)); !errors.Is(err, ErrResetOnRoot) {
		t.Fatalf("got %v, want ErrResetOnRoot", err)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), before) || len(listDir(t, dir)) != len(files) {
		t.Error("nothing may be written for a root")
	}
}

func TestResetLinkTrust_WrongKeyTamperedOrFromPrevIsRefused(t *testing.T) {
	dir := anchoredState(t)
	before := mustFile(t, filepath.Join(dir, StateFile))
	bad := resetOpts(dir)
	bad.MasterKey = "another-key"
	if _, err := ResetLinkTrust(bad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := ResetLinkTrust(LinkTrustResetOptions{Dir: dir}); !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("no key: %v", err)
	}
	// a damaged relay.state with a valid .prev: the state would come from .prev -> refused
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetLinkTrust(resetOpts(dir)); !errors.Is(err, ErrResetFromPrev) {
		t.Errorf("from prev: %v", err)
	}
	if string(mustFile(t, filepath.Join(dir, StateFile))) != "garbage" {
		t.Error("a refused reset must not touch relay.state")
	}
	_ = before
}

// A failure at ANY step leaves relay.state untouched; a failed backup leaves no reset at all.
func TestResetLinkTrust_AFailureAtAnyStepLeavesTheStateIntact(t *testing.T) {
	for failAt := 1; failAt <= 14; failAt++ {
		dir := anchoredState(t)
		before := mustFile(t, filepath.Join(dir, StateFile))
		o := resetOpts(dir)
		o.FS = &faultFS{failAt: failAt}
		res, err := ResetLinkTrust(o)
		if err == nil {
			continue // beyond the last step
		}
		_ = res
		cur := mustFile(t, filepath.Join(dir, StateFile))
		// either the old state is intact, or a COMPLETE new one was installed (the failure came after the rename)
		if !bytes.Equal(cur, before) {
			if _, verr := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: resetKey}); verr != nil {
				t.Fatalf("failAt=%d: relay.state damaged: %v", failAt, verr)
			}
			continue
		}
		// and in every case a reset cannot have happened without a backup
		if failAt == 1 {
			for _, n := range listDir(t, dir) {
				if strings.Contains(n, "linktrust-reset") {
					t.Errorf("failAt=1: a failed backup left %s", n)
				}
			}
		}
	}
	// a retry on a clean filesystem still works
	dir := anchoredState(t)
	if _, err := ResetLinkTrust(resetOpts(dir)); err != nil {
		t.Fatal(err)
	}
}
