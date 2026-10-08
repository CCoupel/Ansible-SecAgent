package state

// QA v3.0.4 survivors of `state link-trust reset`: (1) PeekLinkTrust — the path of the CLI — must refuse a
// root like ResetLinkTrust does (a root without link_trust would otherwise be told "nothing to reset", exit
// 0, instead of the refusal, exit 9); (2) "no backup, no reset": when the backup cannot be written, relay.state
// is not modified at all.
//
// A third survivor ("link_tokens erased as well") is EQUIVALENT: a state that has link tokens necessarily has
// a link signing key (the invariant of checkLinks), i.e. is a root, which the reset refuses before it looks
// at anything: there is no reachable state where the two differ.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type noBackupFS struct{ OSFS }

func (f noBackupFS) CreateExclusive(name string, perm os.FileMode) (File, error) {
	if strings.Contains(filepath.Base(name), ".linktrust-reset.") {
		return nil, errors.New("disk full (injected)")
	}
	return f.OSFS.CreateExclusive(name, perm)
}

func TestResetLinkTrust_WithoutABackupModifiesNothing(t *testing.T) {
	dir := anchoredState(t)
	before := mustFile(t, filepath.Join(dir, StateFile))
	files := listDir(t, dir)
	o := resetOpts(dir)
	o.FS = noBackupFS{}
	if _, err := ResetLinkTrust(o); err == nil {
		t.Fatal("the reset succeeded although its backup could not be written")
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), before) {
		t.Error("relay.state was modified although the backup failed")
	}
	if got := listDir(t, dir); len(got) != len(files) {
		t.Errorf("files changed: %v -> %v", files, got)
	}
}

func TestPeekLinkTrust_ReportsTheAnchorOfANonRootAndWritesNothing(t *testing.T) {
	dir := anchoredState(t)
	files, before := listDir(t, dir), mustFile(t, filepath.Join(dir, StateFile))
	p, err := PeekLinkTrust(dir, resetKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Present || p.RootID != "root" || p.Seq != 5 || p.CurrentKID == "" || p.PreviousKID == "" {
		t.Errorf("probe = %+v", p)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), before) || len(listDir(t, dir)) != len(files) {
		t.Error("peeking must write nothing")
	}
	// a non-root without anchor: reported absent, not an error
	if _, err := ResetLinkTrust(resetOpts(dir)); err != nil {
		t.Fatal(err)
	}
	if p, err := PeekLinkTrust(dir, resetKey, nil); err != nil || p.Present {
		t.Errorf("after the reset: %+v %v, want an absent anchor", p, err)
	}
}

func TestPeekLinkTrust_RefusesARootWhetherOrNotItHoldsAnAnchor(t *testing.T) {
	for _, withAnchor := range []bool{true, false} {
		dir := anchoredState(t)
		e := openEngine(t, dir, func(o *Options) { o.MasterKey = resetKey })
		if err := e.Mutate(func(tx *Tx) error {
			sealed, _ := SealSecret("k", resetKey, ConfigAAD(ConfigLinkSigningKeyCurrent))
			if err := tx.SetConfig(ConfigLinkSigningKeyCurrent, sealed); err != nil {
				return err
			}
			if !withAnchor {
				return tx.SetLinkTrust(LinkTrust{})
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := PeekLinkTrust(dir, resetKey, nil); !errors.Is(err, ErrResetOnRoot) {
			t.Errorf("anchor=%v: got %v, want ErrResetOnRoot (a root has nothing to reset: refusal, not 'nothing to do')", withAnchor, err)
		}
	}
}

func TestPeekLinkTrust_WrongKeyNoKeyAndStateFromPrevAreRefused(t *testing.T) {
	dir := anchoredState(t)
	if _, err := PeekLinkTrust(dir, "another-key", nil); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := PeekLinkTrust(dir, "", nil); !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("no key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PeekLinkTrust(dir, resetKey, nil); !errors.Is(err, ErrResetFromPrev) {
		t.Errorf("from prev: %v", err)
	}
}
