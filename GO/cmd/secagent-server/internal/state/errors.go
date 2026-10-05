package state

import (
	"errors"
	"fmt"
)

// File names inside STATE_DIR.
const (
	StateFile = "relay.state"
	PrevFile  = "relay.state.prev"
	TmpFile   = "relay.state.tmp"
	// LockFile is the master lease of the instance (#162); the state package only needs its name
	// so that `state init` refuses to run over an existing lock.
	LockFile = "relay.lock"
)

// Environment variables and defaults.
const (
	EnvStateDir     = "STATE_DIR"
	DefaultStateDir = "/data"
	EnvMaxBytes     = "STATE_MAX_BYTES"
	DefaultMaxBytes = 64 << 20 // hard ceiling of the state file: 64 MiB
)

// SchemaVersion is the only format version this build reads and writes.
const SchemaVersion = 1

var (
	// ErrNoWriteGuard: the engine refuses every write until a guard (the lock identity check of
	// #163) is connected and confirms that this instance is the master. Nothing is created on disk.
	ErrNoWriteGuard = errors.New("state: write refused: no write guard connected (this instance is not the confirmed master)")
	// ErrTooLarge: the written file would exceed the configured ceiling.
	ErrTooLarge = errors.New("state: write refused: the state file would exceed the size ceiling")
	// ErrSchemaVersion: unknown or newer schema_version: refusing to start, never downgrading silently.
	ErrSchemaVersion = errors.New("state: unsupported schema_version")
	// ErrSecurityInvariant: a security invariant of the file is violated (e.g. a clear-text
	// token_secret). It is NOT a corruption: no silent fallback on relay.state.prev.
	ErrSecurityInvariant = errors.New("state: security invariant violated")
	// ErrAuthentication: the HMAC of the file is missing or invalid (tampered, another master key, or
	// written without one). Always wrapped together with ErrSecurityInvariant.
	ErrAuthentication = errors.New("state: file authentication failed")
	// ErrChecksum: the stored sha256 does not match the payload (always wrapped with ErrCorrupt).
	ErrChecksum = errors.New("state: checksum mismatch")
	// ErrStructure: the payload breaks an invariant of the model (duplicates, dangling references,
	// revoked relay not blacklisted...); always wrapped with ErrCorrupt.
	ErrStructure = errors.New("state: invariant of the model violated")
	// ErrCorrupt: unreadable, truncated or invalid-checksum state file.
	ErrCorrupt = errors.New("state: corrupt state file")
	// ErrInvalid: a mutation violates an invariant of the model; the mutation is rejected.
	ErrInvalid = errors.New("state: invalid mutation")
	// ErrAlreadyExists: relay.state already exists (state init never replaces a state).
	ErrAlreadyExists = errors.New("state: relay.state already exists")
	// ErrDuplicate: a unique key (hostname, jti, token_hash, relay_id) is already used.
	ErrDuplicate = errors.New("state: duplicate key")
)

// NotFoundError is returned when no state exists: the server refuses to start (a missing shared
// volume must never silently create a twin relay with new keys).
type NotFoundError struct{ Dir string }

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("FATAL: relay.state not found in STATE_DIR=%s — run 'secagent-server state init' to initialize", e.Dir)
}
