package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// envelope is the on-disk format: a checksummed payload plus the write metadata.
type envelope struct {
	SchemaVersion  int             `json:"schema_version"`
	WrittenAt      time.Time       `json:"written_at"`
	WriterInstance string          `json:"writer_instance"`
	WriteSeq       uint64          `json:"write_seq"`
	SHA256         string          `json:"sha256"`
	Payload        json.RawMessage `json:"payload"`
}

// encode serializes the model. The payload is marshalled once (maps in key order: deterministic)
// and its SHA-256 is computed on exactly those bytes, which decode re-reads verbatim.
func encode(p *Payload, seq uint64, instance string, now time.Time) ([]byte, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("state: marshal payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return json.Marshal(envelope{
		SchemaVersion:  SchemaVersion,
		WrittenAt:      now.UTC(),
		WriterInstance: instance,
		WriteSeq:       seq,
		SHA256:         hex.EncodeToString(sum[:]),
		Payload:        payload,
	})
}

// decode parses and verifies a state file: format, schema version, checksum, entries, indexes
// and invariants. ErrSchemaVersion and ErrSecurityInvariant are final (no fallback on .prev).
func decode(data []byte, now time.Time) (*model, envelope, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, env, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if env.SchemaVersion != SchemaVersion {
		return nil, env, fmt.Errorf("%w: file has %d, this build supports %d", ErrSchemaVersion, env.SchemaVersion, SchemaVersion)
	}
	sum := sha256.Sum256(env.Payload)
	if hex.EncodeToString(sum[:]) != env.SHA256 {
		return nil, env, fmt.Errorf("%w: sha256 mismatch", ErrCorrupt)
	}
	p := newPayload()
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, env, fmt.Errorf("%w: payload: %v", ErrCorrupt, err)
	}
	m := &model{Payload: p, seq: env.WriteSeq}
	if m.Agents == nil || m.AuthorizedKeys == nil || m.EnrollmentTokens == nil || m.PluginTokens == nil ||
		m.RelayParentTokens == nil || m.Blacklist == nil || m.RelayNodes == nil || m.ServerConfig == nil {
		// "null" sections are tolerated as empty
		fill := newPayload()
		if m.Agents == nil {
			m.Agents = fill.Agents
		}
		if m.AuthorizedKeys == nil {
			m.AuthorizedKeys = fill.AuthorizedKeys
		}
		if m.EnrollmentTokens == nil {
			m.EnrollmentTokens = fill.EnrollmentTokens
		}
		if m.PluginTokens == nil {
			m.PluginTokens = fill.PluginTokens
		}
		if m.RelayParentTokens == nil {
			m.RelayParentTokens = fill.RelayParentTokens
		}
		if m.Blacklist == nil {
			m.Blacklist = fill.Blacklist
		}
		if m.RelayNodes == nil {
			m.RelayNodes = fill.RelayNodes
		}
		if m.ServerConfig == nil {
			m.ServerConfig = fill.ServerConfig
		}
	}
	if err := m.validateAll(now); err != nil {
		if errors.Is(err, ErrSecurityInvariant) {
			return nil, env, err
		}
		return nil, env, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return m, env, nil
}

func isFinal(err error) bool {
	return errors.Is(err, ErrSchemaVersion) || errors.Is(err, ErrSecurityInvariant)
}

// loaded is the result of loading STATE_DIR.
type loaded struct {
	m        *model
	env      envelope
	fromPrev bool // relay.state was missing or invalid: the model comes from relay.state.prev
}

// load reads relay.state (falling back on relay.state.prev with a SECURITY WARNING when it is
// invalid or missing while the previous generation exists).
func load(fs FS, dir string, now time.Time) (*loaded, error) {
	statePath, prevPath := filepath.Join(dir, StateFile), filepath.Join(dir, PrevFile)
	data, err := fs.ReadFile(statePath)
	switch {
	case err == nil:
		m, env, derr := decode(data, now)
		if derr == nil {
			return &loaded{m: m, env: env}, nil
		}
		if isFinal(derr) {
			return nil, fmt.Errorf("state: %s: %w", statePath, derr)
		}
		slog.Warn("[SECURITY WARNING] relay.state is invalid, trying relay.state.prev", "path", statePath, "error", derr)
		return loadPrev(fs, prevPath, now, derr)
	case errors.Is(err, os.ErrNotExist):
		if ok, _ := exists(fs, prevPath); ok {
			slog.Warn("[SECURITY WARNING] relay.state is missing but relay.state.prev exists (interrupted write?): recovering from relay.state.prev", "path", prevPath)
			return loadPrev(fs, prevPath, now, err)
		}
		return nil, &NotFoundError{Dir: dir}
	default:
		return nil, fmt.Errorf("state: read %s: %w", statePath, err)
	}
}

func loadPrev(fs FS, prevPath string, now time.Time, cause error) (*loaded, error) {
	data, err := fs.ReadFile(prevPath)
	if err != nil {
		return nil, fmt.Errorf("state: relay.state is unusable (%v) and relay.state.prev cannot be read: %w", cause, err)
	}
	m, env, derr := decode(data, now)
	if derr != nil {
		return nil, fmt.Errorf("state: both relay.state (%v) and relay.state.prev (%v) are invalid: refusing to start (no automatic re-initialization)", cause, derr)
	}
	return &loaded{m: m, env: env, fromPrev: true}, nil
}

// atomicWrite replaces relay.state with data without ever leaving the directory without a valid
// file: write relay.state.tmp (0600) + fsync, keep the current file as relay.state.prev (hard
// link: no instant without relay.state; a plain rename when links are unsupported), rename tmp
// over relay.state, fsync the directory. rotate=false keeps the existing relay.state.prev (used
// right after a recovery from .prev, so that the good generation is not overwritten by a bad one).
func atomicWrite(fs FS, dir string, data []byte, rotate bool) (err error) {
	statePath, prevPath, tmpPath := filepath.Join(dir, StateFile), filepath.Join(dir, PrevFile), filepath.Join(dir, TmpFile)
	if rerr := fs.Remove(tmpPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return fmt.Errorf("state: remove stale %s: %w", TmpFile, rerr)
	}
	f, err := fs.CreateExclusive(tmpPath, 0o600)
	if err != nil {
		return fmt.Errorf("state: create %s: %w", TmpFile, err)
	}
	defer func() {
		if err != nil {
			_ = fs.Remove(tmpPath) // best effort: a crash leaves it, the next write removes it
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return fmt.Errorf("state: write %s: %w", TmpFile, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("state: fsync %s: %w", TmpFile, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("state: close %s: %w", TmpFile, cerr)
	}
	if rotate {
		if ok, _ := exists(fs, statePath); ok {
			if rerr := fs.Remove(prevPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				return fmt.Errorf("state: remove %s: %w", PrevFile, rerr)
			}
			if lerr := fs.Link(statePath, prevPath); lerr != nil {
				slog.Warn("state: hard link unsupported, rotating by rename", "error", lerr)
				if rerr := fs.Rename(statePath, prevPath); rerr != nil {
					return fmt.Errorf("state: rotate %s: %w", StateFile, rerr)
				}
			}
		}
	}
	if rerr := fs.Rename(tmpPath, statePath); rerr != nil {
		return fmt.Errorf("state: rename %s over %s: %w", TmpFile, StateFile, rerr)
	}
	if serr := fs.SyncDir(dir); serr != nil {
		return fmt.Errorf("state: fsync directory %s: %w", dir, serr)
	}
	return nil
}
