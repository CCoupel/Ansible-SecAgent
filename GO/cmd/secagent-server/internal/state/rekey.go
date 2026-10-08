package state

// Offline rotation of RSA_MASTER_KEY (`state rekey`, v3.0.4). The master key encrypts every secret at
// rest (AES-256-GCM, AAD = field binding) and derives the HMAC key of the file, so changing it means
// rewriting the WHOLE state: every "enc:" value is opened with the old key and sealed again with the new
// one (fresh nonce, same binding), the HMAC is recomputed, and the result is verified end to end. This
// rotates the key that protects the state at rest, NOT the secrets themselves (JWT_SECRET_KEY, the JWT
// secrets, the agent RSA key and the link signing key keep their value: issued tokens stay valid).
// The caller has already checked that no instance holds relay.lock.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/user"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	rekeyBackupPrefix = StateFile + ".rekey."
	rekeyBackupSuffix = ".bak"
)

var (
	// ErrRekeyNoNewKey: the new master key is missing or empty.
	ErrRekeyNoNewKey = errors.New("state rekey: the new master key is empty")
	// ErrRekeySameKey: the new key equals the old one (nothing to rotate; also an idempotent re-run).
	ErrRekeySameKey = errors.New("state rekey: the new master key is identical to the current one: nothing to rotate")
	// ErrRekeyKeyTooShort: the new master key is shorter than MinNewMasterKeyBytes (the AES key is a
	// plain SHA-256 of it, so a short key is a weak key). The message never echoes the key.
	ErrRekeyKeyTooShort = errors.New("state rekey: the new master key is too short (minimum 32 bytes; generate one with 'openssl rand -base64 48')")
	// ErrRekeyFromPrev: relay.state is not usable and the state would come from relay.state.prev.
	ErrRekeyFromPrev = errors.New("state rekey: relay.state is not usable as is (the state comes from relay.state.prev): fix it first, for example with 'state restore'")
	// ErrRekeySchema is no longer returned: a schema 1 state is migrated to 2 by the rekey itself.
	//
	// Deprecated: kept declared until the tests that referenced it are updated.
	ErrRekeySchema = errors.New("state rekey: unsupported schema_version")
	// ErrRekeyUncovered: an "enc:" value was found where the rekey does not know how to re-encrypt it.
	// Refusing is the only safe answer (the field would become unreadable after the rotation).
	ErrRekeyUncovered = errors.New("state rekey: an encrypted value was found in a field the rekey does not cover: nothing modified")
	// ErrRekeyVerify: the rewritten state did not verify with the new key; the original was restored.
	ErrRekeyVerify = errors.New("state rekey: the rewritten state failed its end-to-end verification")
)

// MinNewMasterKeyBytes is the minimum length of the NEW master key accepted by Rekey. It is not applied to
// the current key (historical keys may be shorter and must stay openable) nor to `state init`.
const MinNewMasterKeyBytes = 32

// ValidateNewMasterKey applies the rules on the new key of a rekey: not empty, not shorter than
// MinNewMasterKeyBytes, different from the current one.
func ValidateNewMasterKey(oldKey, newKey string) error {
	switch {
	case newKey == "":
		return ErrRekeyNoNewKey
	case newKey == oldKey:
		return ErrRekeySameKey
	case len(newKey) < MinNewMasterKeyBytes:
		return ErrRekeyKeyTooShort
	}
	return nil
}

// RekeyOptions configures Rekey.
type RekeyOptions struct {
	Dir      string
	OldKey   string
	NewKey   string
	FS       FS // default OSFS
	MaxBytes int64
	Now      func() time.Time
	Operator string // journal (default: the system user)
	// BeforeRename: last check before the replacement (see RestoreOptions.BeforeRename).
	BeforeRename func() error

	// afterWrite is a test seam, called after the new state is in place and before its verification.
	afterWrite func(fs FS, dir string)
}

// RekeyResult is what Rekey did. It carries counts and file names only, never a key or a value.
type RekeyResult struct {
	Fields     int    // number of encrypted fields re-encrypted
	SeqBefore  uint64 // write_seq before / after
	SeqAfter   uint64
	BackupFile string // base name, readable with the OLD key
	Restored   bool   // the verification failed and the original state was put back
	// Migrated: the state was schema 1 and is now schema 2 (written by this operation).
	Migrated     bool
	V1BackupFile string // relay.state.v1.bak (copy of the original v1 file) when Migrated
}

// rekeyedFields lists the encrypted fields of a payload: path (for the coverage guard) → value and
// the binding (AAD) of that field. It is the single place that knows where "enc:" values live.
func rekeyedFields(p *Payload) map[string]struct {
	Value string
	AAD   []byte
} {
	type f = struct {
		Value string
		AAD   []byte
	}
	out := map[string]f{}
	for k := range secretConfigKeys {
		if v := p.ServerConfig[k]; v != "" {
			out["server_config/"+k] = f{v, ConfigAAD(k)}
		}
	}
	for id, n := range p.RelayNodes {
		if n.TokenSecret != "" {
			out["relay_nodes/"+id+"/token_secret"] = f{n.TokenSecret, RelayTokenSecretAAD(id)}
		}
	}
	return out
}

// findEnc walks a JSON-decoded payload and records the path of every string that carries the "enc:"
// prefix, wherever it is.
func findEnc(v any, path string, out *[]string) {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, EncPrefix) {
			*out = append(*out, path)
		}
	case map[string]any:
		for k, c := range x {
			findEnc(c, path+"/"+k, out)
		}
	case []any:
		for i, c := range x {
			findEnc(c, fmt.Sprintf("%s/%d", path, i), out)
		}
	}
}

// checkRekeyCoverage fails when the payload holds an "enc:" value outside rekeyedFields.
func checkRekeyCoverage(p *Payload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("state rekey: marshal payload: %w", err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return fmt.Errorf("state rekey: decode payload: %w", err)
	}
	var found []string
	findEnc(generic, "", &found)
	known := rekeyedFields(p)
	var missing []string
	for _, path := range found {
		if _, ok := known[strings.TrimPrefix(path, "/")]; !ok {
			missing = append(missing, strings.TrimPrefix(path, "/"))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w (fields: %s)", ErrRekeyUncovered, strings.Join(missing, ", "))
	}
	return nil
}

// clonePayloadSecrets returns p with its own copies of the two maps that hold encrypted fields.
func clonePayloadSecrets(p Payload) Payload {
	cfg := make(map[string]string, len(p.ServerConfig))
	for k, v := range p.ServerConfig {
		cfg[k] = v
	}
	nodes := make(map[string]RelayNode, len(p.RelayNodes))
	for k, v := range p.RelayNodes {
		nodes[k] = v
	}
	p.ServerConfig, p.RelayNodes = cfg, nodes
	return p
}

// transformSecrets opens every encrypted field of p with `from` and seals it with `to`; with to == "" it
// only opens (plain view for the end-to-end comparison: values replaced by their cleartext).
func transformSecrets(p Payload, from, to string) (Payload, int, error) {
	p = clonePayloadSecrets(p)
	n := 0
	for path, f := range rekeyedFields(&p) {
		plain, err := OpenSecret(f.Value, from, f.AAD)
		if err != nil {
			return Payload{}, 0, fmt.Errorf("state rekey: field %q does not open with the current master key and its own binding", path)
		}
		out := plain
		if to != "" {
			if out, err = SealSecret(plain, to, f.AAD); err != nil {
				return Payload{}, 0, fmt.Errorf("state rekey: field %q: %w", path, err)
			}
		}
		switch {
		case strings.HasPrefix(path, "server_config/"):
			p.ServerConfig[strings.TrimPrefix(path, "server_config/")] = out
		default: // relay_nodes/<id>/token_secret
			id := strings.TrimSuffix(strings.TrimPrefix(path, "relay_nodes/"), "/token_secret")
			node := p.RelayNodes[id]
			node.TokenSecret = out
			p.RelayNodes[id] = node
		}
		n++
	}
	return p, n, nil
}

// Rekey rewrites relay.state so that it is encrypted and authenticated by NewKey instead of OldKey. A schema 1
// state is migrated to schema 2 by the same write (relay.state.v1.bak first).
// Order (nothing is modified before the backup is durable): verify with OldKey, refuse unknown
// encrypted fields, write the backup of the exact verified file (0600, fsync), build the new file,
// replace relay.state atomically (guarded by BeforeRename), then re-open it with NewKey and compare
// every cleartext against the original; on any failure the original bytes are put back.
func Rekey(o RekeyOptions) (*RekeyResult, error) {
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
	if o.OldKey == "" {
		return nil, ErrNoMasterKey
	}
	if err := ValidateNewMasterKey(o.OldKey, o.NewKey); err != nil {
		return nil, err
	}
	oldOpts := Options{MasterKey: o.OldKey}
	oldC, err := oldOpts.codec()
	if err != nil {
		return nil, err
	}
	newOpts := Options{MasterKey: o.NewKey}
	newC, err := newOpts.codec()
	if err != nil {
		return nil, err
	}

	statePath := filepath.Join(o.Dir, StateFile)
	raw, err := o.FS.ReadFileMax(statePath, o.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("state rekey: cannot read the state: %w", err)
	}
	// verify the exact bytes we are going to back up (HMAC, invariants, secrets) — not a possible fallback
	m, env, err := oldC.decode(raw, now())
	if err != nil {
		return nil, err
	}
	migrate := env.SchemaVersion == 1
	if migrate && (len(m.LinkTokens) > 0 || !m.LinkTrust.IsZero() ||
		m.ServerConfig[ConfigLinkSigningKeyCurrent] != "" || m.ServerConfig[ConfigLinkSigningKeyPrevious] != "") {
		return nil, fmt.Errorf("%w: a schema_version 1 state carries link data (link tokens, trust anchor or signing key)", ErrStructure)
	}
	if err := checkRekeyCoverage(&m.Payload); err != nil {
		return nil, err
	}
	res := &RekeyResult{SeqBefore: env.WriteSeq, SeqAfter: env.WriteSeq + 1, Migrated: migrate}

	newPayload, n, err := transformSecrets(m.Payload, o.OldKey, o.NewKey)
	if err != nil {
		return nil, err
	}
	res.Fields = n
	data, err := newC.encode(&newPayload, res.SeqAfter, "state-rekey", now())
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > o.MaxBytes {
		return nil, ErrTooLarge
	}

	// 1. the backup, BEFORE any change: no backup, no rekey
	backup := rekeyBackupPrefix + now().UTC().Format("20060102T150405Z") + rekeyBackupSuffix
	if err := writeBackup(o.FS, filepath.Join(o.Dir, backup), raw); err != nil {
		return nil, fmt.Errorf("state rekey: backup failed, nothing modified: %w", err)
	}
	if err := o.FS.SyncDir(o.Dir); err != nil {
		return nil, fmt.Errorf("state rekey: backup not durable, nothing modified: %w", err)
	}
	res.BackupFile = backup
	if migrate {
		// the v1 → v2 migration happens in this same write: relay.state.v1.bak (the original v1 file, what
		// a rollback to v3.0.3 restores) is durable BEFORE relay.state becomes v2, like the engine's own
		// migration; no backup, no rekey
		if err := writeV1BackupData(o.FS, o.Dir, raw); err != nil {
			return nil, fmt.Errorf("state rekey: v1 backup failed, nothing modified: %w", err)
		}
		res.V1BackupFile = V1BackupFile
	}

	// 2. replacement (the existing relay.state.prev is kept as is: it is readable with the OLD key only)
	if err := atomicWrite(o.FS, o.Dir, data, false, o.BeforeRename); err != nil {
		if errors.Is(err, ErrInstanceAppeared) {
			return res, err // relay.state untouched; the result names the backup that was kept
		}
		return nil, err
	}
	if o.afterWrite != nil {
		o.afterWrite(o.FS, o.Dir)
	}

	// 3. end-to-end verification with the NEW key; failure → the original bytes are put back
	if verr := verifyRekeyed(o, newC, m.Payload, now()); verr != nil {
		if rerr := atomicWrite(o.FS, o.Dir, raw, false, nil); rerr != nil {
			return res, fmt.Errorf("%w: %v; AND the original could not be put back (%v): restore %s with 'state restore --from %s' using the OLD key", ErrRekeyVerify, verr, rerr, backup, backup)
		}
		res.Restored = true
		return res, fmt.Errorf("%w: %v; the original state was restored", ErrRekeyVerify, verr)
	}

	operator := o.Operator
	if operator == "" {
		if u, uerr := user.Current(); uerr == nil {
			operator = u.Username
		} else {
			operator = "unknown"
		}
	}
	if migrate {
		slog.Info("state migration schema_version 1 -> 2 (done by state rekey)", "backup", V1BackupFile)
	}
	slog.Warn("[SECURITY WARNING] master key rekeyed", "dir", o.Dir, "backup", backup, "fields", n, "migrated_from_v1", migrate, "at", now().UTC().Format(time.RFC3339), "operator", operator)
	if jerr := appendRestoreLog(o.Dir, restoreLogLine{
		At: now().UTC().Format(time.RFC3339), Operator: operator, Source: "rekey",
		SeqBefore: res.SeqBefore, SeqAfter: res.SeqAfter, Backup: backup,
	}); jerr != nil {
		return res, fmt.Errorf("master key rekeyed, but the intervention could not be journaled: %w", jerr)
	}
	return res, nil
}

// verifyRekeyed re-reads relay.state from disk and checks it with the new key (HMAC, invariants, every
// secret opens with its binding), that the OLD key no longer opens it, and that the cleartext content
// (secrets included) equals the original.
func verifyRekeyed(o RekeyOptions, newC codec, original Payload, now time.Time) error {
	written, err := o.FS.ReadFileMax(filepath.Join(o.Dir, StateFile), o.MaxBytes)
	if err != nil {
		return fmt.Errorf("cannot re-read the new state: %w", err)
	}
	m2, env2, err := newC.decode(written, now)
	if err != nil {
		return fmt.Errorf("the new state does not verify with the new key: %w", err)
	}
	if env2.SchemaVersion != SchemaVersion {
		return fmt.Errorf("the new state has schema_version %d, expected %d", env2.SchemaVersion, SchemaVersion)
	}
	oldOpts := Options{MasterKey: o.OldKey}
	oldC, err := oldOpts.codec()
	if err != nil {
		return err
	}
	if _, _, err := oldC.decode(written, now); err == nil {
		return errors.New("the new state still opens with the old key")
	}
	wantPlain, _, err := transformSecrets(original, o.OldKey, "")
	if err != nil {
		return err
	}
	gotPlain, _, err := transformSecrets(m2.Payload, o.NewKey, "")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(wantPlain, gotPlain) {
		return errors.New("the content of the new state differs from the original once decrypted")
	}
	return nil
}
