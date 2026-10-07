package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// peekWriteSeq reads write_seq from an envelope WITHOUT verifying anything (display only).
func peekWriteSeq(data []byte) uint64 {
	var e struct {
		WriteSeq uint64 `json:"write_seq"`
	}
	if json.Unmarshal(data, &e) != nil {
		return 0
	}
	return e.WriteSeq
}

// writeBackup writes a copy 0600, exclusive (never overwrites an earlier backup), fsynced.
func writeBackup(fs FS, path string, data []byte) error {
	f, err := fs.CreateExclusive(path, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type restoreLogLine struct {
	At         string `json:"at"`
	Operator   string `json:"operator"`
	Source     string `json:"source"`
	SeqBefore  uint64 `json:"write_seq_before"`
	SeqAfter   uint64 `json:"write_seq_after"`
	Backup     string `json:"backup,omitempty"`
	BackupPrev string `json:"backup_prev,omitempty"`
	// LockOverride: the operator explicitly passed over a relay.lock that was not proven stale.
	LockOverride bool `json:"lock_override,omitempty"`
}

// appendRestoreLog appends one JSON line (0600, no symbolic link followed). No secret is written.
func appendRestoreLog(dir string, l restoreLogLine) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, RestoreLogFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
