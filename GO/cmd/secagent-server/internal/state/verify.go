package state

// Operator tools (#187): `state verify` checks a state file without writing anything, `state
// restore` replaces relay.state by a verified file with the engine's own atomic procedure.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// Report describes a verified state file. It carries counts and metadata only: never a secret,
// a token hash or a key.
type Report struct {
	SchemaVersion  int
	WriteSeq       uint64
	WrittenAt      time.Time
	WriterInstance string
	Counts         map[string]int // entity type -> number of entries
}

// VerifyOptions configures VerifyFile.
type VerifyOptions struct {
	FS        FS // default OSFS
	MasterKey string
	MaxBytes  int64 // 0 = DefaultMaxBytes
	Now       time.Time
}

// ErrNoMasterKey: verification needs RSA_MASTER_KEY (the HMAC key derives from it).
var ErrNoMasterKey = errors.New("state: RSA_MASTER_KEY is required to verify a state file")

// VerifyFile reads path and applies EVERY check the server applies when it opens a state:
// schema_version, HMAC (key derived from the master key), sha256, entries and invariants, secrets
// ("enc:" prefix, field binding). It writes nothing. The error wraps the sentinels of this
// package (ErrSchemaVersion, ErrAuthentication, ErrChecksum, ErrStructure, ErrSecurityInvariant,
// ErrCorrupt, ErrNoMasterKey) so that callers can classify the failure.
func VerifyFile(path string, o VerifyOptions) (*Report, error) {
	if o.MasterKey == "" {
		return nil, ErrNoMasterKey
	}
	if o.FS == nil {
		o.FS = OSFS{}
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	data, err := o.FS.ReadFileMax(path, o.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("state: cannot read %s: %w", path, err)
	}
	return verifyData(data, o)
}

func verifyData(data []byte, o VerifyOptions) (*Report, error) {
	opts := Options{MasterKey: o.MasterKey}
	c, err := opts.codec()
	if err != nil {
		return nil, err
	}
	m, env, err := c.decode(data, o.Now)
	if err != nil {
		return nil, err
	}
	return &Report{
		SchemaVersion: env.SchemaVersion, WriteSeq: env.WriteSeq, WrittenAt: env.WrittenAt, WriterInstance: env.WriterInstance,
		Counts: map[string]int{
			"agents": len(m.Agents), "authorized_keys": len(m.AuthorizedKeys), "enrollment_tokens": len(m.EnrollmentTokens),
			"plugin_tokens": len(m.PluginTokens), "relay_parent_tokens": len(m.RelayParentTokens),
			"blacklist": len(m.Blacklist), "relay_nodes": len(m.RelayNodes), "server_config": len(m.ServerConfig),
		},
	}, nil
}

// ── restore ──────────────────────────────────────────────────────────────────

// RestoreLogFile is the intervention journal, next to relay.state. The server never reads it.
const RestoreLogFile = "state-restore.log"

// backupInfix marks the copies made before a replacement: names the server never opens.
const backupInfix = ".bak-"

// RestoreOptions configures Restore.
type RestoreOptions struct {
	Dir       string
	From      string
	MasterKey string
	FS        FS // default OSFS
	MaxBytes  int64
	Now       func() time.Time
	// MinWriteSeq, when > 0, refuses a source whose write_seq is lower.
	MinWriteSeq uint64
	// Operator is recorded in the journal (default: the system user).
	Operator string
	// LockOverride records in the journal that the operator passed over a lock that was not proven
	// stale (the caller already logged the [SECURITY WARNING]).
	LockOverride bool
}

// RestoreResult is what Restore did.
type RestoreResult struct {
	Report     *Report
	SeqBefore  uint64 // write_seq of the replaced relay.state (0 when none or unreadable)
	SeqAfter   uint64
	BackupFile string // base name of the copy of the previous relay.state ("" when there was none)
	BackupPrev string // base name of the copy of the previous relay.state.prev ("" when there was none)
}

// ErrWriteSeqTooLow: the source is older than the requested minimum.
var ErrWriteSeqTooLow = errors.New("state: write_seq below the requested minimum")

// Restore replaces relay.state in o.Dir by the file o.From after verifying it with VerifyFile
// (an inauthentic or invalid source is refused and nothing is modified). The caller has already
// established that no instance holds the master lock. The current relay.state and relay.state.prev
// are first copied to timestamped, 0600, never-reloaded files; the replacement then uses the
// engine's atomic procedure (temporary file, fsync, link/rename, directory fsync) with the BYTES of
// the verified file (its HMAC stays valid: nothing is re-encoded). relay.state.prev is kept as is.
// The intervention is appended to state-restore.log (no secret).
func Restore(o RestoreOptions) (*RestoreResult, error) {
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
	rep, err := VerifyFile(o.From, VerifyOptions{FS: o.FS, MasterKey: o.MasterKey, MaxBytes: o.MaxBytes, Now: now()})
	if err != nil {
		return nil, err
	}
	if o.MinWriteSeq > 0 && rep.WriteSeq < o.MinWriteSeq {
		return nil, fmt.Errorf("%w: the file has write_seq %d, the minimum is %d", ErrWriteSeqTooLow, rep.WriteSeq, o.MinWriteSeq)
	}
	data, err := o.FS.ReadFileMax(o.From, o.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("state: cannot read %s: %w", o.From, err)
	}
	if err := o.FS.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("state restore: %w", err)
	}

	res := &RestoreResult{Report: rep, SeqAfter: rep.WriteSeq}
	statePath, prevPath := filepath.Join(o.Dir, StateFile), filepath.Join(o.Dir, PrevFile)
	stamp := now().UTC().Format("20060102T150405Z")
	if cur, rerr := o.FS.ReadFileMax(statePath, o.MaxBytes); rerr == nil {
		res.SeqBefore = peekWriteSeq(cur)
		res.BackupFile = StateFile + backupInfix + stamp
		if err := writeBackup(o.FS, filepath.Join(o.Dir, res.BackupFile), cur); err != nil {
			return nil, err
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return nil, fmt.Errorf("state restore: cannot back up the current relay.state: %w", rerr)
	}
	if cur, rerr := o.FS.ReadFileMax(prevPath, o.MaxBytes); rerr == nil {
		res.BackupPrev = PrevFile + backupInfix + stamp
		if err := writeBackup(o.FS, filepath.Join(o.Dir, res.BackupPrev), cur); err != nil {
			return nil, err
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return nil, fmt.Errorf("state restore: cannot back up the current relay.state.prev: %w", rerr)
	}

	// replacement by the engine's atomic write; rotate=false keeps the existing relay.state.prev
	if err := atomicWrite(o.FS, o.Dir, data, false, nil); err != nil {
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
	if err := appendRestoreLog(o.Dir, restoreLogLine{
		At: now().UTC().Format(time.RFC3339), Operator: operator, Source: filepath.Base(o.From),
		SeqBefore: res.SeqBefore, SeqAfter: res.SeqAfter, Backup: res.BackupFile, BackupPrev: res.BackupPrev,
		LockOverride: o.LockOverride,
	}); err != nil {
		// the state is replaced: report, do not pretend it failed
		return res, fmt.Errorf("state restored, but the intervention could not be journaled: %w", err)
	}
	return res, nil
}
