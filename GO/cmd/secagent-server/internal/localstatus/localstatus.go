// Package localstatus is the local health file of a relay process (#163, decision #158 Q4): the
// process writes its role and the freshness of its lock activity to a file OUTSIDE the shared
// STATE_DIR (default /run/secagent/status.json, mode 0600), and `secagent-server status --local`
// judges it without opening a port nor calling the API. It holds no secret.
package localstatus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnvStatusFile overrides the path of the status file.
const EnvStatusFile = "RELAY_STATUS_FILE"

// DefaultPath is where the status file lives without RELAY_STATUS_FILE (a per-host tmpfs).
const DefaultPath = "/run/secagent/status.json"

// Write modes of the state (File.StateMode, /api/admin/status).
const (
	ModeReadOnly  = "read_only"
	ModeReadWrite = "read_write"
)

// States of the process (File.State).
const (
	StateWaiting = "waiting" // secondary or candidate: no port, no state loaded
	StateLoading = "loading" // master, loading the state / building
	StateReady   = "ready"   // master, serving
	StateFailed  = "failed"  // start refused (invalid state, certificate, replay): exiting
	StateLost    = "lost"    // the lock was lost: exiting
)

// File is the content of the status file.
type File struct {
	Role       string `json:"role"` // secondary | candidate | master | lost
	InstanceID string `json:"instance_id"`
	State      string `json:"state"`
	Detail     string `json:"detail,omitempty"` // a short non-secret reason (failed / lost)
	Pid        int    `json:"pid"`
	Beat       uint64 `json:"beat"`
	// StateMode: "read_write" only for a ready master whose write guard passes, else "read_only";
	// WriteSeq: the write_seq of the state held (ready master only).
	StateMode string `json:"state_mode"`
	WriteSeq  uint64 `json:"write_seq,omitempty"`
	// LastBeatAt (master) / LastCheckAt (secondary, and master identity checks): unix milliseconds
	// of the last SUCCESSFUL lock activity, taken from the lock itself (not from this file's write
	// time): a frozen process stops refreshing them.
	LastBeatAt  int64 `json:"last_beat_at_ms,omitempty"`
	LastCheckAt int64 `json:"last_check_at_ms,omitempty"`
	// periods of the lock this process runs with (the verdict scales with them)
	BeatPeriodMS  int64 `json:"beat_period_ms"`
	CheckPeriodMS int64 `json:"check_period_ms"`
	UpdatedAt     int64 `json:"updated_at_ms"`
}

// PathFromEnv returns RELAY_STATUS_FILE, else DefaultPath.
func PathFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(EnvStatusFile)); v != "" {
		return v
	}
	return DefaultPath
}

// CheckOutside refuses a status path inside the shared state directory: the file is local to the
// process and must never reach the shared storage.
func CheckOutside(statusPath, stateDir string) error {
	sp, err := filepath.Abs(statusPath)
	if err != nil {
		return fmt.Errorf("%s: %w", EnvStatusFile, err)
	}
	dp, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("STATE_DIR: %w", err)
	}
	if rel, err := filepath.Rel(dp, sp); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s (%s) must be outside STATE_DIR (%s): the status file is local to the process, never on the shared storage", EnvStatusFile, statusPath, stateDir)
	}
	return nil
}

// Write replaces the file atomically (temp + rename), mode 0600, creating the directory (0700).
func Write(path string, f File) error {
	if f.UpdatedAt == 0 {
		f.UpdatedAt = time.Now().UnixMilli()
	}
	if f.Pid == 0 {
		f.Pid = os.Getpid()
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("status file: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".status-*")
	if err != nil {
		return fmt.Errorf("status file: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Read parses the file (O_NOFOLLOW is not needed: it is local and only read for a verdict).
func Read(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("unreadable status file: %w", err)
	}
	return f, nil
}

// Verdict judges a status file at time now. ok=false carries the reason.
//   - failed / lost, or role lost: unhealthy;
//   - master: healthy when its last successful lock write is younger than 2 × the beat period;
//   - secondary / candidate: healthy when its last check is younger than 3 × the check period.
func Verdict(f File, now time.Time) (ok bool, reason string) {
	if f.State == StateFailed || f.State == StateLost || f.Role == "lost" {
		r := f.Detail
		if r == "" {
			r = f.State
		}
		return false, fmt.Sprintf("process %s: %s", f.State, r)
	}
	age := func(ms int64) time.Duration { return now.Sub(time.UnixMilli(ms)) }
	switch f.Role {
	case "master":
		limit := 2 * time.Duration(f.BeatPeriodMS) * time.Millisecond
		if f.LastBeatAt == 0 || limit <= 0 {
			return false, "master without a successful heartbeat"
		}
		if a := age(f.LastBeatAt); a >= limit {
			return false, fmt.Sprintf("last heartbeat %s ago (limit %s): process frozen?", a.Round(time.Second), limit)
		}
	case "secondary", "candidate":
		limit := 3 * time.Duration(f.CheckPeriodMS) * time.Millisecond
		if f.LastCheckAt == 0 || limit <= 0 {
			return false, "secondary without a lock check yet"
		}
		if a := age(f.LastCheckAt); a >= limit {
			return false, fmt.Sprintf("last lock check %s ago (limit %s): process frozen?", a.Round(time.Second), limit)
		}
	default:
		return false, fmt.Sprintf("unknown role %q", f.Role)
	}
	return true, ""
}
