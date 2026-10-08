package state

// Offline reset of the trust anchor of a NON-ROOT relay (`state link-trust reset`, v3.0.4): the
// persisted link_trust (root id, current/previous public key, last accepted seq) takes precedence over
// the pinned REPEATER_ROOT_LINK_KEY_FILE and nothing else can replace it, so a relay that missed a key
// rotation (or whose root was rebuilt) could never be re-pinned. This function clears ONLY that
// section, with a mandatory backup, on a stopped node. The caller has already checked that no instance
// holds relay.lock.

import (
	"errors"
	"fmt"
	"log/slog"
	"os/user"
	"path/filepath"
	"time"
)

// LinkTrustResetPrefix / suffix of the backup written before the reset.
const (
	linkTrustResetBackupPrefix = StateFile + ".linktrust-reset."
	linkTrustResetBackupSuffix = ".bak"
)

var (
	// ErrResetOnRoot: the node holds a link signing key, it is the root: it has no anchor to reset.
	ErrResetOnRoot = errors.New("state: this node holds a link signing key (it is the root): it has no trust anchor to reset")
	// ErrResetFromPrev: relay.state is not usable and the state would come from relay.state.prev.
	ErrResetFromPrev = errors.New("state: relay.state is not usable as is (the state comes from relay.state.prev): fix it first, for example with 'state restore'")
)

// LinkTrustResetOptions configures ResetLinkTrust.
type LinkTrustResetOptions struct {
	Dir       string
	MasterKey string
	FS        FS // default OSFS
	MaxBytes  int64
	Now       func() time.Time
	Operator  string // journal (default: the system user)
	// BeforeRename: last check before the replacement (see RestoreOptions.BeforeRename).
	BeforeRename func() error
}

// LinkTrustResetResult is what ResetLinkTrust did. It carries public identifiers only.
type LinkTrustResetResult struct {
	Changed     bool   // false: there was no link_trust (idempotent no-op: nothing written, no backup)
	RootID      string // anchor that was cleared
	CurrentKID  string
	PreviousKID string
	Seq         uint64
	SeqBefore   uint64 // write_seq of the state before / after
	SeqAfter    uint64
	BackupFile  string // base name, "" when nothing was written
}

// ResetLinkTrust verifies relay.state (HMAC, invariants), refuses a root and a state that does not come
// from relay.state itself, writes the backup (0600, fsync) BEFORE any change, then rewrites the file
// with link_trust cleared (everything else byte-identical in meaning), through the engine's atomic write
// and a recomputed HMAC. A failure at any step leaves relay.state untouched.
func ResetLinkTrust(o LinkTrustResetOptions) (*LinkTrustResetResult, error) {
	if o.Dir == "" {
		o.Dir = DefaultStateDir
	}
	if o.FS == nil {
		o.FS = OSFS{}
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.MasterKey == "" {
		return nil, ErrNoMasterKey
	}
	opts := Options{MasterKey: o.MasterKey}
	c, err := opts.codec()
	if err != nil {
		return nil, err
	}
	ld, err := load(o.FS, o.Dir, now(), c, o.MaxBytes)
	if err != nil {
		return nil, err
	}
	if ld.fromPrev {
		return nil, ErrResetFromPrev
	}
	m := ld.m
	if m.ServerConfig[ConfigLinkSigningKeyCurrent] != "" || m.ServerConfig[ConfigLinkSigningKeyPrevious] != "" {
		return nil, ErrResetOnRoot
	}
	res := &LinkTrustResetResult{SeqBefore: m.seq, SeqAfter: m.seq}
	if m.LinkTrust.IsZero() {
		return res, nil // idempotent: nothing to clear, nothing written
	}
	res.Changed = true
	res.RootID, res.CurrentKID, res.PreviousKID, res.Seq = m.LinkTrust.RootID, m.LinkTrust.CurrentKID, m.LinkTrust.PreviousKID, m.LinkTrust.Seq

	// 1. the backup of the exact file we verified, BEFORE any change; no backup, no reset
	statePath := filepath.Join(o.Dir, StateFile)
	raw, err := o.FS.ReadFileMax(statePath, o.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("state link-trust reset: cannot read the state to back it up: %w", err)
	}
	stamp := now().UTC().Format("20060102T150405Z")
	backup := linkTrustResetBackupPrefix + stamp + linkTrustResetBackupSuffix
	if err := writeBackup(o.FS, filepath.Join(o.Dir, backup), raw); err != nil {
		return nil, fmt.Errorf("state link-trust reset: backup failed, nothing modified: %w", err)
	}
	if err := o.FS.SyncDir(o.Dir); err != nil {
		return nil, fmt.Errorf("state link-trust reset: backup not durable, nothing modified: %w", err)
	}
	res.BackupFile = backup

	// 2. clear link_trust only, re-encode with a fresh HMAC and a higher write_seq (anti-replay guard)
	p := m.Payload
	p.LinkTrust = LinkTrust{}
	res.SeqAfter = m.seq + 1
	data, err := c.encode(&p, res.SeqAfter, "state-link-trust-reset", now())
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > o.MaxBytes {
		return nil, ErrTooLarge
	}
	if err := atomicWrite(o.FS, o.Dir, data, true, o.BeforeRename); err != nil {
		if errors.Is(err, ErrInstanceAppeared) {
			return res, err // relay.state untouched; the result names the backup that was kept
		}
		return nil, err
	}

	operator := o.Operator
	if operator == "" {
		if u, uerr := user.Current(); uerr == nil {
			operator = u.Username
		} else {
			operator = "unknown"
		}
	}
	slog.Warn("[SECURITY WARNING] link trust anchor reset", "dir", o.Dir, "backup", backup, "at", now().UTC().Format(time.RFC3339), "operator", operator)
	if jerr := appendRestoreLog(o.Dir, restoreLogLine{
		At: now().UTC().Format(time.RFC3339), Operator: operator, Source: "link-trust-reset",
		SeqBefore: res.SeqBefore, SeqAfter: res.SeqAfter, Backup: backup,
	}); jerr != nil {
		return res, fmt.Errorf("link trust reset done, but the intervention could not be journaled: %w", jerr)
	}
	return res, nil
}

// LinkTrustProbe describes the persisted anchor (public identifiers only).
type LinkTrustProbe struct {
	Present     bool
	RootID      string
	CurrentKID  string
	PreviousKID string
	Seq         uint64
}

// PeekLinkTrust verifies relay.state (HMAC, invariants) and reports the persisted anchor without
// writing anything. It returns the same refusals as ResetLinkTrust (root, state from relay.state.prev).
func PeekLinkTrust(dir, masterKey string, fs FS) (*LinkTrustProbe, error) {
	if fs == nil {
		fs = OSFS{}
	}
	if masterKey == "" {
		return nil, ErrNoMasterKey
	}
	opts := Options{MasterKey: masterKey}
	c, err := opts.codec()
	if err != nil {
		return nil, err
	}
	ld, err := load(fs, dir, time.Now(), c, DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	if ld.fromPrev {
		return nil, ErrResetFromPrev
	}
	if ld.m.ServerConfig[ConfigLinkSigningKeyCurrent] != "" || ld.m.ServerConfig[ConfigLinkSigningKeyPrevious] != "" {
		return nil, ErrResetOnRoot
	}
	lt := ld.m.LinkTrust
	return &LinkTrustProbe{Present: !lt.IsZero(), RootID: lt.RootID, CurrentKID: lt.CurrentKID, PreviousKID: lt.PreviousKID, Seq: lt.Seq}, nil
}
