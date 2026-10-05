package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"secagent-server/cmd/secagent-server/internal/crypto"
)

// envelope is the on-disk format: a checksummed payload plus the write metadata.
type envelope struct {
	SchemaVersion  int       `json:"schema_version"`
	WrittenAt      time.Time `json:"written_at"`
	WriterInstance string    `json:"writer_instance"`
	WriteSeq       uint64    `json:"write_seq"`
	// HMAC authenticates the payload and the metadata with a key derived from the master key
	// (HMAC-SHA-256, hex). Absent only in test mode (no master key). The SHA-256 below is a
	// plain checksum: anyone with write access to the directory can recompute it, not the HMAC.
	HMAC    string          `json:"hmac,omitempty"`
	SHA256  string          `json:"sha256"`
	Payload json.RawMessage `json:"payload"`
}

// codec carries what encoding and decoding need beyond the bytes: the HMAC key and the secret
// policy. The zero value is the test-mode codec (no HMAC, clear secrets refused at load).
type codec struct {
	macKey    []byte // nil: no HMAC written or required (no master key: test mode)
	masterKey string // RSA_MASTER_KEY: secrets must open with their field binding (AAD)
	insecure  bool   // InsecureTestMode (never with a master key): clear secrets allowed
}

// macInput is what the HMAC covers: schema version, sequence, timestamp, writer and payload, so
// none of them can be altered or moved between files without the key.
func macInput(e *envelope) []byte {
	var b bytes.Buffer
	b.WriteString("secagent-state-v1\n")
	b.WriteString(strconv.Itoa(e.SchemaVersion))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatUint(e.WriteSeq, 10))
	b.WriteByte('\n')
	b.WriteString(e.WrittenAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(len(e.WriterInstance)))
	b.WriteByte(':')
	b.WriteString(e.WriterInstance)
	b.WriteByte('\n')
	b.Write(e.Payload)
	return b.Bytes()
}

func computeMAC(key []byte, e *envelope) string {
	m := hmac.New(sha256.New, key)
	m.Write(macInput(e))
	return hex.EncodeToString(m.Sum(nil))
}

// encode serializes the model with the test-mode codec (no HMAC).
func encode(p *Payload, seq uint64, instance string, now time.Time) ([]byte, error) {
	return codec{}.encode(p, seq, instance, now)
}

// decode parses and verifies a state file with the test-mode codec.
func decode(data []byte, now time.Time) (*model, envelope, error) {
	return codec{}.decode(data, now)
}

// encode serializes the model. The payload is marshalled once (maps in key order: deterministic),
// its SHA-256 and, with a master key, its HMAC are computed on exactly those bytes, which decode
// re-reads verbatim.
func (c codec) encode(p *Payload, seq uint64, instance string, now time.Time) ([]byte, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("state: marshal payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	env := envelope{
		SchemaVersion:  SchemaVersion,
		WrittenAt:      now.UTC(),
		WriterInstance: instance,
		WriteSeq:       seq,
		SHA256:         hex.EncodeToString(sum[:]),
		Payload:        payload,
	}
	if c.macKey != nil {
		env.HMAC = computeMAC(c.macKey, &env)
	}
	return json.Marshal(env)
}

// decode parses and verifies a state file: format, schema version, HMAC (BEFORE the checksum),
// checksum, entries, indexes, secrets and invariants. ErrSchemaVersion and ErrSecurityInvariant
// are final (no fallback on .prev).
func (c codec) decode(data []byte, now time.Time) (*model, envelope, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, env, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if env.SchemaVersion != SchemaVersion {
		return nil, env, fmt.Errorf("%w: file has %d, this build supports %d", ErrSchemaVersion, env.SchemaVersion, SchemaVersion)
	}
	if c.macKey != nil {
		// A master key is configured: the file must carry a valid HMAC. A forgery cannot be told
		// from bit rot, and a valid relay.state.prev must never mask it, so this is final.
		got, err := hex.DecodeString(env.HMAC)
		if env.HMAC == "" || err != nil || !hmac.Equal(got, mustDecodeHex(computeMAC(c.macKey, &env))) {
			return nil, env, fmt.Errorf("%w: state file authentication (HMAC) is missing or invalid: tampered, written with another master key, or written without one", ErrSecurityInvariant)
		}
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
	if err := c.checkSecrets(m); err != nil {
		return nil, env, err
	}
	return m, env, nil
}

func mustDecodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// checkSecrets enforces the secret invariants of a loaded file (final refusals, never a fallback):
// every non-empty secret of server_config is "enc:"-prefixed (except in explicit test mode
// without master key) and, with a master key, opens with the binding of ITS field (AAD), which
// rejects ciphertexts swapped between fields. Messages never contain a value.
func (c codec) checkSecrets(m *model) error {
	for k := range secretConfigKeys {
		v := m.ServerConfig[k]
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, EncPrefix) {
			if c.masterKey == "" && c.insecure {
				continue
			}
			return fmt.Errorf("%w: server_config %q is stored in clear (only allowed in explicit test mode without a master key)", ErrSecurityInvariant, k)
		}
		if c.masterKey != "" {
			if _, err := OpenSecret(v, c.masterKey, ConfigAAD(k)); err != nil {
				return fmt.Errorf("%w: server_config %q does not open with the master key and its own field binding (moved, tampered or wrong key)", ErrSecurityInvariant, k)
			}
		}
	}
	if c.masterKey != "" {
		for id, n := range m.RelayNodes {
			if n.TokenSecret == "" {
				continue
			}
			if _, err := OpenSecret(n.TokenSecret, c.masterKey, RelayTokenSecretAAD(id)); err != nil {
				return fmt.Errorf("%w: relay %q token_secret does not open with the master key and its own field binding", ErrSecurityInvariant, id)
			}
		}
	}
	return nil
}

// ConfigAAD is the AES-GCM additional data of a server_config secret: its field name.
func ConfigAAD(key string) []byte { return []byte(key) }

// RelayTokenSecretAAD is the AES-GCM additional data of a push relay's token_secret.
func RelayTokenSecretAAD(relayID string) []byte {
	return []byte("relay_nodes/" + relayID + "/token_secret")
}

// SealSecret encrypts plain with the master key, bound to aad, and returns the "enc:"-prefixed
// value to store.
func SealSecret(plain, masterKey string, aad []byte) (string, error) {
	enc, err := crypto.EncryptWithAAD(plain, masterKey, aad)
	if err != nil {
		return "", fmt.Errorf("encrypt secret: %w", err)
	}
	return EncPrefix + enc, nil
}

// OpenSecret decrypts an "enc:"-prefixed value produced by SealSecret with the same aad.
func OpenSecret(value, masterKey string, aad []byte) (string, error) {
	if !strings.HasPrefix(value, EncPrefix) {
		return "", errors.New("secret is not encrypted")
	}
	return crypto.DecryptWithAAD(value[len(EncPrefix):], masterKey, aad)
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
func load(fs FS, dir string, now time.Time, c codec, maxBytes int64) (*loaded, error) {
	statePath, prevPath := filepath.Join(dir, StateFile), filepath.Join(dir, PrevFile)
	data, err := fs.ReadFileMax(statePath, maxBytes)
	switch {
	case errors.Is(err, errTooBig):
		slog.Warn("[SECURITY WARNING] relay.state exceeds the size ceiling, trying relay.state.prev", "path", statePath)
		return loadPrev(fs, prevPath, now, c, maxBytes, fmt.Errorf("%w: %v", ErrCorrupt, err))
	case err == nil:
		m, env, derr := c.decode(data, now)
		if derr == nil {
			return &loaded{m: m, env: env}, nil
		}
		if isFinal(derr) {
			return nil, fmt.Errorf("state: %s: %w", statePath, derr)
		}
		slog.Warn("[SECURITY WARNING] relay.state is invalid, trying relay.state.prev", "path", statePath, "error", derr)
		return loadPrev(fs, prevPath, now, c, maxBytes, derr)
	case errors.Is(err, os.ErrNotExist):
		if ok, _ := exists(fs, prevPath); ok {
			slog.Warn("[SECURITY WARNING] relay.state is missing but relay.state.prev exists (interrupted write?): recovering from relay.state.prev", "path", prevPath)
			return loadPrev(fs, prevPath, now, c, maxBytes, err)
		}
		return nil, &NotFoundError{Dir: dir}
	default:
		return nil, fmt.Errorf("state: read %s: %w", statePath, err)
	}
}

func loadPrev(fs FS, prevPath string, now time.Time, c codec, maxBytes int64, cause error) (*loaded, error) {
	data, err := fs.ReadFileMax(prevPath, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("state: relay.state is unusable (%v) and relay.state.prev cannot be read: %w", cause, err)
	}
	m, env, derr := c.decode(data, now)
	if isFinal(derr) {
		// relay.state.prev follows the same rules as relay.state: no fallback on a security refusal.
		return nil, fmt.Errorf("state: relay.state.prev: %w", derr)
	}
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
//
// beforeRename (may be nil) is the write guard re-checked as late as possible, right after the
// data is durable in the temporary file and before anything of relay.state is touched: a master
// lock lost during the (slow) fsync cancels the write (#159 R4).
func atomicWrite(fs FS, dir string, data []byte, rotate bool, beforeRename func() error) (err error) {
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
	if beforeRename != nil {
		if gerr := beforeRename(); gerr != nil {
			return fmt.Errorf("state: write guard refused the write before the rename: %w", gerr)
		}
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

// atomicCreate creates relay.state with data ONLY IF it does not exist, atomically: the content is
// written and fsynced to a private temporary name, then hard-linked to relay.state (link fails
// when the target exists, so of several concurrent creators exactly one wins and nobody ever
// replaces a state), then the temporary name is removed and the directory synced.
func atomicCreate(fs FS, dir string, data []byte) (err error) {
	statePath := filepath.Join(dir, StateFile)
	suffix := make([]byte, 8)
	if _, rerr := rand.Read(suffix); rerr != nil {
		return fmt.Errorf("state: random temporary name: %w", rerr)
	}
	tmpPath := filepath.Join(dir, TmpFile+"."+hex.EncodeToString(suffix))
	f, err := fs.CreateExclusive(tmpPath, 0o600)
	if err != nil {
		return fmt.Errorf("state: create %s: %w", filepath.Base(tmpPath), err)
	}
	defer func() { _ = fs.Remove(tmpPath) }() // success (the link keeps the data) or failure: the private name goes
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return fmt.Errorf("state: write %s: %w", filepath.Base(tmpPath), werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("state: fsync %s: %w", filepath.Base(tmpPath), serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("state: close %s: %w", filepath.Base(tmpPath), cerr)
	}
	if lerr := fs.Link(tmpPath, statePath); lerr != nil {
		if errors.Is(lerr, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrAlreadyExists, StateFile)
		}
		return fmt.Errorf("state: create %s (hard link): %w", StateFile, lerr)
	}
	if serr := fs.SyncDir(dir); serr != nil {
		return fmt.Errorf("state: fsync directory %s: %w", dir, serr)
	}
	return nil
}
