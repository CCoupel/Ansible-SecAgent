package cli

// `state rekey` on a REAL schema 1 state (as v3.0.3 wrote it): the command migrates it to schema 2 under the
// new key in the same operation and says so — the operator must learn that the rollback to v3.0.3 is
// relay.state.v1.bak + the OLD key. The state package tests the operation (rekey_v1_test.go); this one tests
// what the CLI tells and leaves on disk.
//
// The fixture needs a v1 file with a VALID HMAC, which only the state package can compute: the helper below
// recomputes the envelope MAC with the same documented input (state/file.go macInput) and the fixture is
// verified with the public state.VerifyFile before use, so that any drift of the format fails loudly here
// ("fixture out of sync") instead of silently testing nothing.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/crypto"
	"secagent-server/cmd/secagent-server/internal/state"
)

type v1Envelope struct {
	SchemaVersion  int             `json:"schema_version"`
	WrittenAt      time.Time       `json:"written_at"`
	WriterInstance string          `json:"writer_instance"`
	WriteSeq       uint64          `json:"write_seq"`
	HMAC           string          `json:"hmac,omitempty"`
	SHA256         string          `json:"sha256"`
	Payload        json.RawMessage `json:"payload"`
}

// toSchemaOne turns the v2 state of dir into the file v3.0.3 would have written (schema_version 1, no link
// sections) and returns its bytes.
func toSchemaOne(t *testing.T, dir, key string) []byte {
	t.Helper()
	path := filepath.Join(dir, state.StateFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env v1Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &sections); err != nil {
		t.Fatal(err)
	}
	delete(sections, "link_tokens")
	delete(sections, "link_trust")
	if env.Payload, err = json.Marshal(sections); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(env.Payload)
	env.SHA256, env.SchemaVersion = hex.EncodeToString(sum[:]), 1
	macKey, err := crypto.DeriveStateHMACKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var in bytes.Buffer // state/file.go macInput
	in.WriteString("secagent-state-v2\n" + strconv.Itoa(env.SchemaVersion) + "\n" + strconv.FormatUint(env.WriteSeq, 10) + "\n" +
		env.WrittenAt.UTC().Format(time.RFC3339Nano) + "\n" +
		strconv.Itoa(len(env.WriterInstance)) + ":" + env.WriterInstance + "\n" + strconv.Itoa(len(env.SHA256)) + ":" + env.SHA256 + "\n")
	in.Write(env.Payload)
	m := hmac.New(sha256.New, macKey)
	m.Write(in.Bytes())
	env.HMAC = hex.EncodeToString(m.Sum(nil))
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, verr := state.VerifyFile(path, state.VerifyOptions{MasterKey: key})
	if verr != nil || rep.SchemaVersion != 1 || !rep.NeedsMigration {
		t.Fatalf("fixture out of sync with state/file.go (a schema 1 file with a valid HMAC could not be built): %+v %v", rep, verr)
	}
	return out
}

func TestStateRekey_ASchemaOneStateIsMigratedAndTheOperatorIsTold(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	v1 := toSchemaOne(t, dir, toolsKey)

	out, code := execRekey(t, dir, true, false, "")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"migrated to schema_version 2", state.V1BackupFile, "OLD key"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output must mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, toolsKey) || strings.Contains(out, rekeyNewKey) {
		t.Error("the output carries a key")
	}
	// on disk: the original v1, byte for byte, 0600; relay.state is v2 under the new key only
	bak := filepath.Join(dir, state.V1BackupFile)
	got, err := os.ReadFile(bak)
	if err != nil || !bytes.Equal(got, v1) {
		t.Errorf("%s must be the original v1 file (%v)", state.V1BackupFile, err)
	}
	if fi, err := os.Stat(bak); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode: %v %v", state.V1BackupFile, fi, err)
	}
	rep, err := state.VerifyFile(filepath.Join(dir, state.StateFile), state.VerifyOptions{MasterKey: rekeyNewKey})
	if err != nil || rep.SchemaVersion != state.SchemaVersion || rep.NeedsMigration {
		t.Fatalf("relay.state after the rekey: %+v %v", rep, err)
	}
	if _, err := state.VerifyFile(filepath.Join(dir, state.StateFile), state.VerifyOptions{MasterKey: toolsKey}); err == nil {
		t.Error("the old key must no longer open relay.state")
	}
}

// A schema 2 state is rekeyed without any migration message and without a v1 backup.
func TestStateRekey_ASchemaTwoStateSaysNothingOfMigration(t *testing.T) {
	rekeyEnv(t)
	dir := toolsState(t)
	out, code := execRekey(t, dir, true, false, "")
	if code != 0 || strings.Contains(out, "migrated") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, state.V1BackupFile)); err == nil {
		t.Error("no v1 backup for a schema 2 state")
	}
}
