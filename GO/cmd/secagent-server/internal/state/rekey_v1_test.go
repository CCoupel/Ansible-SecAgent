package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedV1Keyed writes a state exactly as v3.0.3 wrote it for a relay with a master key: schema_version 1,
// no link_tokens / link_trust section, secrets sealed with key, HMAC valid. It returns the file bytes.
func seedV1Keyed(t *testing.T, dir, key string) []byte {
	t.Helper()
	p := newPayload()
	p.Agents["host-a"] = Agent{Hostname: "host-a", PublicKeyPEM: testPEM("host-a"), TokenJTI: "jti-host-a", EnrolledAt: time.Unix(1700000000, 0).UTC()}
	p.Blacklist["old-jti"] = BlacklistEntry{JTI: "old-jti", Hostname: "gone", RevokedAt: time.Unix(1700000000, 0).UTC(), Reason: "test", ExpiresAt: time.Now().Add(24 * time.Hour).UTC()}
	for _, k := range []string{"rsa_key_current", "jwt_secret_current", "jwt_secret_previous"} {
		v, err := SealSecret("clear-"+k, key, ConfigAAD(k))
		if err != nil {
			t.Fatal(err)
		}
		p.ServerConfig[k] = v
	}
	push := newRelay("pushy", ModePush)
	sealed, err := SealSecret("push-token", key, RelayTokenSecretAAD("pushy"))
	if err != nil {
		t.Fatal(err)
	}
	push.TokenSecret = sealed
	p.RelayNodes["pushy"] = push

	opts := Options{MasterKey: key}
	c, err := opts.codec()
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.encode(&p, 7, "v303", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
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
	env.HMAC = computeMAC(c.macKey, &env)
	if data, err = json.Marshal(env); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
		t.Fatal(err)
	}
	return mustFile(t, filepath.Join(dir, StateFile))
}

func TestRekey_SchemaV1_MigratesToV2InTheSameOperation(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1Keyed(t, dir, rekeyOld)
	if schemaOf(t, filepath.Join(dir, StateFile)) != 1 || !v303Reads(1) {
		t.Fatal("fixture must be a v3.0.3 state")
	}
	res, err := Rekey(rekeyOpts(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Migrated || res.V1BackupFile != V1BackupFile || res.Fields != 4 || res.SeqAfter != res.SeqBefore+1 {
		t.Fatalf("result = %+v", res)
	}
	// relay.state.v1.bak = the original v1 bytes (0600), the rekey backup too; both readable with the old key
	if !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), v1) || mode(t, filepath.Join(dir, V1BackupFile)) != 0o600 {
		t.Error("relay.state.v1.bak must be the original v1 file, mode 0600")
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, res.BackupFile)), v1) {
		t.Error("the rekey backup must be the original file")
	}
	if _, err := VerifyFile(filepath.Join(dir, V1BackupFile), VerifyOptions{MasterKey: rekeyOld}); err != nil {
		t.Errorf("the v1 backup must open with the old key: %v", err)
	}
	// relay.state is now v2 under the new key, content intact, old key refused
	if schemaOf(t, filepath.Join(dir, StateFile)) != SchemaVersion {
		t.Fatal("relay.state must be schema 2")
	}
	if v303Reads(schemaOf(t, filepath.Join(dir, StateFile))) {
		t.Error("a v3.0.3 build must refuse the migrated state")
	}
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyOld}); err == nil {
		t.Error("old key must be refused")
	}
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: rekeyNew})
	if err != nil || rep.SchemaVersion != SchemaVersion || rep.NeedsMigration || rep.Counts["agents"] != 1 || rep.Counts["blacklist"] != 1 || rep.Counts["relay_nodes"] != 1 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	// a v3.0.4 node starts with the new key; the secrets are the original cleartexts; its next write
	// does not migrate again and does not touch the v1 backup
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = rekeyNew })
	if e.Snapshot().AgentCount() != 1 {
		t.Error("agent lost")
	}
	if v, _ := e.Snapshot().Config("rsa_key_current"); v == "" {
		t.Fatal("rsa_key_current lost")
	} else if got, err := OpenSecret(v, rekeyNew, ConfigAAD("rsa_key_current")); err != nil || got != "clear-rsa_key_current" {
		t.Errorf("secret changed: %v", err)
	}
	mustMutate(t, e, addAgent("host-b"))
	if !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), v1) {
		t.Error("a later write must not touch relay.state.v1.bak")
	}
}

func TestRekey_SchemaV1_BackupFailureOrVerificationFailureLeavesTheV1Usable(t *testing.T) {
	// the v1 backup cannot be written (3rd file creation: rekey backup, then v1 tmp) → nothing modified
	dir := t.TempDir()
	v1 := seedV1Keyed(t, dir, rekeyOld)
	o := rekeyOpts(dir)
	o.FS = &faultFS{failAt: 2}
	if _, err := Rekey(o); err == nil {
		t.Fatal("expected a failure")
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), v1) {
		t.Error("relay.state modified although the v1 backup failed")
	}
	if schemaOf(t, filepath.Join(dir, StateFile)) != 1 {
		t.Error("must still be v1")
	}
	// verification failure → original v1 put back
	dir2 := t.TempDir()
	v1b := seedV1Keyed(t, dir2, rekeyOld)
	o = rekeyOpts(dir2)
	o.afterWrite = corruptNewState
	res, err := Rekey(o)
	if !errors.Is(err, ErrRekeyVerify) || res == nil || !res.Restored {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir2, StateFile)), v1b) {
		t.Error("the original v1 must be restored")
	}
	if _, err := VerifyFile(filepath.Join(dir2, StateFile), VerifyOptions{MasterKey: rekeyOld}); err != nil {
		t.Errorf("restored v1 must open with the old key: %v", err)
	}
}

func TestRekey_SchemaV1_RefusesLinkDataInAV1State(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1Keyed(t, dir, rekeyOld)
	// forge a "v1" file that carries a link signing key: refused, nothing written
	opts := Options{MasterKey: rekeyOld}
	c, _ := opts.codec()
	var env envelope
	if err := json.Unmarshal(v1, &env); err != nil {
		t.Fatal(err)
	}
	var p Payload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		t.Fatal(err)
	}
	k, _ := SealSecret("x", rekeyOld, ConfigAAD(ConfigLinkSigningKeyCurrent))
	p.ServerConfig[ConfigLinkSigningKeyCurrent] = k
	raw, _ := json.Marshal(p)
	env.Payload = raw
	sum := sha256.Sum256(raw)
	env.SHA256 = hex.EncodeToString(sum[:])
	env.HMAC = computeMAC(c.macKey, &env)
	forged, _ := json.Marshal(env)
	if err := atomicWrite(OSFS{}, dir, forged, false, nil); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, dir)
	if _, err := Rekey(rekeyOpts(dir)); err == nil || !errors.Is(err, ErrStructure) || !strings.Contains(err.Error(), "link data") {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(before, ",") != strings.Join(listDir(t, dir), ",") {
		t.Error("nothing may be written")
	}
}

// corruptNewState flips a byte of the freshly written state (verification-failure injection).
func corruptNewState(fs FS, d string) {
	p := filepath.Join(d, StateFile)
	b, err := fs.ReadFileMax(p, DefaultMaxBytes)
	if err != nil {
		return
	}
	b[len(b)/2] ^= 0x01
	_ = os.WriteFile(p, b, 0o600)
}
