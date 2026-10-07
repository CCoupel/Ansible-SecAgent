package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const linkMaster = "link-test-master-key"

// v1File is a schema_version 1 file as v3.0.3 wrote it: a payload without link_tokens / link_trust.
func v1File(t testing.TB, c codec, p *Payload, seq uint64) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "link_tokens")
	delete(m, "link_trust")
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	env := envelope{SchemaVersion: 1, WrittenAt: time.Now().UTC(), WriterInstance: "v303", WriteSeq: seq, SHA256: hex.EncodeToString(sum[:]), Payload: payload}
	if c.macKey != nil {
		env.HMAC = computeMAC(c.macKey, &env)
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func seedLegacyV1(t testing.TB, dir string) []byte {
	t.Helper()
	p := newPayload()
	p.Agents["old"] = Agent{Hostname: "old", PublicKeyPEM: testPEM("old"), TokenJTI: "jti-old", EnrolledAt: time.Unix(1700000000, 0).UTC()}
	data := v1File(t, codec{}, &p, 7)
	if err := os.WriteFile(filepath.Join(dir, StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func fileSchema(t testing.TB, path string) int {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(mustFile(t, path), &env); err != nil {
		t.Fatal(err)
	}
	return env.SchemaVersion
}

func TestMigrationV1ToV2_BackupThenV2_Idempotent(t *testing.T) {
	dir := t.TempDir()
	orig := seedLegacyV1(t, dir)
	e := openEngine(t, dir, nil)
	if e.Snapshot().SchemaVersion() != 1 || e.Snapshot().AgentCount() != 1 {
		t.Fatal("a v1 state must load as is")
	}
	if _, err := os.Stat(filepath.Join(dir, V1BackupFile)); err == nil {
		t.Fatal("reading must not write the backup")
	}
	if err := e.Mutate(addAgent("new")); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(dir, V1BackupFile)
	if !bytes.Equal(mustFile(t, bak), orig) {
		t.Fatal("the backup must be the v1 file, byte for byte")
	}
	if m := mode(t, bak); m != 0o600 {
		t.Errorf("backup mode %o, want 600", m)
	}
	if fileSchema(t, filepath.Join(dir, StateFile)) != 2 || e.Snapshot().SchemaVersion() != 2 {
		t.Fatal("the first write must produce a schema_version 2 file")
	}
	// idempotent: a second write does not touch the backup
	if err := e.Mutate(addAgent("newer")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustFile(t, bak), orig) {
		t.Fatal("the backup must not change after the migration")
	}
	if names := listDir(t, dir); strings.Contains(strings.Join(names, ","), ".tmp") {
		t.Errorf("leftover temporary file: %v", names)
	}
	// reopened: both agents, v2
	e2 := openEngine(t, dir, nil)
	if e2.Snapshot().AgentCount() != 3 || e2.Snapshot().SchemaVersion() != 2 {
		t.Fatal("reopen after migration")
	}
}

func TestMigrationV1_ReadOnlyEngineWritesNothing(t *testing.T) {
	dir := t.TempDir()
	orig := seedLegacyV1(t, dir)
	e, err := Open(Options{Dir: dir}) // no write guard: a secondary
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Mutate(addAgent("x")); !errors.Is(err, ErrNoWriteGuard) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), orig) || len(listDir(t, dir)) != 1 {
		t.Fatalf("nothing may be written: %v", listDir(t, dir))
	}
}

func TestMigrationV1_BackupFailureLeavesV1Intact(t *testing.T) {
	dir := t.TempDir()
	orig := seedLegacyV1(t, dir)
	e := openEngine(t, dir, func(o *Options) { o.FS = &faultFS{failAt: 2} }) // first op of the backup = stale tmp remove (1), create (2)
	if err := e.Mutate(addAgent("x")); err == nil {
		t.Fatal("the write must fail when the backup fails")
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), orig) {
		t.Fatal("the v1 state must be intact")
	}
	if e.Snapshot().SchemaVersion() != 1 || e.Snapshot().AgentCount() != 1 {
		t.Fatal("memory must not run ahead of the disk")
	}
	if _, err := os.Stat(filepath.Join(dir, V1BackupFile)); err == nil {
		t.Fatal("no backup may be left half written")
	}
	// retry (new process): migrates
	e2 := openEngine(t, dir, nil)
	if err := e2.Mutate(addAgent("x")); err != nil {
		t.Fatal(err)
	}
	if fileSchema(t, filepath.Join(dir, StateFile)) != 2 || !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), orig) {
		t.Fatal("retry must migrate with the backup")
	}
}

func TestMigrationV1_FailedV2WriteLeavesV1IntactAndRetryIsIdempotent(t *testing.T) {
	for failAt := 8; failAt <= 14; failAt++ { // every step of the main write, after the 7 steps of the backup
		dir := t.TempDir()
		orig := seedLegacyV1(t, dir)
		e := openEngine(t, dir, func(o *Options) { o.FS = &faultFS{failAt: failAt} })
		if err := e.Mutate(addAgent("x")); err == nil {
			continue // fault beyond the last step of the write
		}
		if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), orig) && fileSchema(t, filepath.Join(dir, StateFile)) == 1 {
			t.Fatalf("failAt=%d: v1 altered", failAt)
		}
		if bak, err := os.ReadFile(filepath.Join(dir, V1BackupFile)); err != nil || !bytes.Equal(bak, orig) {
			t.Fatalf("failAt=%d: the backup must exist and equal the v1 (%v)", failAt, err)
		}
		e2 := openEngine(t, dir, nil)
		if err := e2.Mutate(addAgent("y")); err != nil {
			t.Fatalf("failAt=%d: retry: %v", failAt, err)
		}
		if !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), orig) || fileSchema(t, filepath.Join(dir, StateFile)) != 2 {
			t.Fatalf("failAt=%d: retry", failAt)
		}
	}
}

func TestMigrationV1_FromPrevBacksUpTheFileItLoaded(t *testing.T) {
	dir := t.TempDir()
	orig := seedLegacyV1(t, dir)
	if err := os.Rename(filepath.Join(dir, StateFile), filepath.Join(dir, PrevFile)); err != nil { // interrupted rotation
		t.Fatal(err)
	}
	e := openEngine(t, dir, nil)
	if err := e.Mutate(addAgent("x")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), orig) {
		t.Fatal("the backup must be the v1 content that was loaded")
	}
}

func TestMigrationV1_WithMasterKeyKeepsTheHMAC(t *testing.T) {
	dir := t.TempDir()
	opts := Options{MasterKey: linkMaster}
	c, err := opts.codec()
	if err != nil {
		t.Fatal(err)
	}
	p := newPayload()
	orig := v1File(t, c, &p, 3)
	if err := os.WriteFile(filepath.Join(dir, StateFile), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: linkMaster}); err != nil || !rep.NeedsMigration || rep.SchemaVersion != 1 {
		t.Fatalf("state verify must read a v1 file: %+v %v", rep, err)
	}
	e := openEngine(t, dir, func(o *Options) { o.MasterKey = linkMaster })
	if err := e.Mutate(addAgent("a")); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: linkMaster})
	if err != nil || rep.SchemaVersion != 2 || rep.NeedsMigration {
		t.Fatalf("after migration: %+v %v", rep, err)
	}
	if rep, err := VerifyFile(filepath.Join(dir, V1BackupFile), VerifyOptions{MasterKey: linkMaster}); err != nil || rep.SchemaVersion != 1 {
		t.Fatalf("the backup must stay an authentic v1: %+v %v", rep, err)
	}
}

func TestSchemaV1CannotCarryLinkData(t *testing.T) {
	p := newPayload()
	p.LinkTrust = LinkTrust{CurrentPub: pub32(1), CurrentKID: "k1"}
	raw, _ := json.Marshal(&p)
	sum := sha256.Sum256(raw)
	data, _ := json.Marshal(envelope{SchemaVersion: 1, WrittenAt: time.Now(), WriteSeq: 1, SHA256: hex.EncodeToString(sum[:]), Payload: raw})
	if _, _, err := (codec{}).decode(data, time.Now()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a v1 file with link data must be refused: %v", err)
	}
}

func TestV303RefusesAV2File_SchemaIs2(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	if fileSchema(t, filepath.Join(dir, StateFile)) != 2 || SchemaVersion != 2 {
		t.Fatal("this build writes schema_version 2: a v3.0.3 binary (SchemaVersion 1, strict equality) refuses it with ErrSchemaVersion")
	}
}

// ── link data ─────────────────────────────────────────────────────────────────

func pub32(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func linkTok(id string) LinkToken {
	now := time.Now().UTC()
	return LinkToken{ID: id, JTI: "jti-" + id, Role: RoleRelayChild, Sub: "x", Aud: "p", KID: "k1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func sealedEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: linkMaster, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	return openEngine(t, dir, func(o *Options) { o.MasterKey = linkMaster }), dir
}

func sealedKey(t *testing.T, field, plain string) string {
	t.Helper()
	v, err := SealSecret(plain, linkMaster, ConfigAAD(field))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLinkTokens_NeedTheSigningKey_RoundTrip(t *testing.T) {
	e, dir := sealedEngine(t)
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(linkTok("a")) }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a link token without signing key must be refused: %v", err)
	}
	if e.Snapshot().LinkTokens() != nil && len(e.Snapshot().LinkTokens()) != 0 {
		t.Fatal("rollback")
	}
	// key and token in the same mutation
	if err := e.Mutate(func(tx *Tx) error {
		if err := tx.SetConfig(ConfigLinkSigningKeyCurrent, sealedKey(t, ConfigLinkSigningKeyCurrent, "PRIVATE-KEY-MATERIAL")); err != nil {
			return err
		}
		return tx.PutLinkToken(linkTok("a"))
	}); err != nil {
		t.Fatal(err)
	}
	raw := string(mustFile(t, filepath.Join(dir, StateFile)))
	if strings.Contains(raw, "PRIVATE-KEY-MATERIAL") {
		t.Fatal("the signing key must be stored encrypted")
	}
	e2 := openEngine(t, dir, func(o *Options) { o.MasterKey = linkMaster })
	tk, ok := e2.Snapshot().LinkTokenByJTI("jti-a")
	if !ok || tk.ID != "a" || tk.Role != RoleRelayChild {
		t.Fatalf("reopen: %+v %v", tk, ok)
	}
	// the key cannot be removed while tokens depend on it
	if err := e2.Mutate(func(tx *Tx) error { tx.DeleteConfig(ConfigLinkSigningKeyCurrent); return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleting the key under a registry: %v", err)
	}
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: linkMaster})
	if err != nil || !rep.LinkSigningKeyCurrent || rep.LinkSigningKeyPrevious || rep.Counts["link_tokens"] != 1 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
}

func TestLinkTokens_RevocationBlacklistsTheJTIInTheSameMutation(t *testing.T) {
	e, _ := sealedEngine(t)
	if err := e.Mutate(func(tx *Tx) error {
		_ = tx.SetConfig(ConfigLinkSigningKeyCurrent, sealedKey(t, ConfigLinkSigningKeyCurrent, "k"))
		return tx.PutLinkToken(linkTok("a"))
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	revoked := linkTok("a")
	revoked.RevokedAt = &now
	// revoked without blacklist: refused, nothing kept
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(revoked) }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revocation without blacklist: %v", err)
	}
	if tk, _ := e.Snapshot().LinkToken("a"); tk.RevokedAt != nil {
		t.Fatal("the refused revocation must leave no trace")
	}
	// revoked + blacklisted in one mutation
	if err := e.Mutate(func(tx *Tx) error {
		if err := tx.PutBlacklist(BlacklistEntry{JTI: "jti-a", RevokedAt: now, Reason: "link_revoked", ExpiresAt: revoked.ExpiresAt}); err != nil {
			return err
		}
		return tx.PutLinkToken(revoked)
	}); err != nil {
		t.Fatal(err)
	}
	if tk, _ := e.Snapshot().LinkToken("a"); tk.RevokedAt == nil || !e.Snapshot().Blacklisted("jti-a") {
		t.Fatal("revoked and blacklisted")
	}
	// an EXPIRED revoked token needs no blacklist entry (it may have been purged)
	old := linkTok("old")
	old.ExpiresAt = now.Add(-time.Hour)
	old.RevokedAt = &now
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(old) }); err != nil {
		t.Fatalf("expired revoked token: %v", err)
	}
}

func TestLinkTokens_Validation(t *testing.T) {
	e, _ := sealedEngine(t)
	if err := e.Mutate(func(tx *Tx) error {
		return tx.SetConfig(ConfigLinkSigningKeyCurrent, sealedKey(t, ConfigLinkSigningKeyCurrent, "k"))
	}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*LinkToken){
		"role":       func(l *LinkToken) { l.Role = "relay" },
		"no sub":     func(l *LinkToken) { l.Sub = "" },
		"no aud":     func(l *LinkToken) { l.Aud = "" },
		"no kid":     func(l *LinkToken) { l.KID = "" },
		"no jti":     func(l *LinkToken) { l.JTI = "" },
		"no expires": func(l *LinkToken) { l.ExpiresAt = time.Time{} },
	}
	for name, mod := range bad {
		l := linkTok("v")
		mod(&l)
		if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(l) }); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(linkTok("a")) }); err != nil {
		t.Fatal(err)
	}
	dup := linkTok("b")
	dup.JTI = "jti-a"
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(dup) }); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate jti: %v", err)
	}
	if err := e.Mutate(func(tx *Tx) error { tx.DeleteLinkToken("a"); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Snapshot().LinkTokenByJTI("jti-a"); ok {
		t.Fatal("index not cleaned")
	}
}

func TestLinkSigningKey_PreviousNeedsCurrent_AndSecretRules(t *testing.T) {
	e, dir := sealedEngine(t)
	if err := e.Mutate(func(tx *Tx) error {
		return tx.SetConfig(ConfigLinkSigningKeyPrevious, sealedKey(t, ConfigLinkSigningKeyPrevious, "p"))
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("previous without current: %v", err)
	}
	// a clear value is refused (secret key)
	if err := e.Mutate(func(tx *Tx) error { return tx.SetConfig(ConfigLinkSigningKeyCurrent, "clear") }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clear signing key: %v", err)
	}
	if !IsSecretConfigKey(ConfigLinkSigningKeyCurrent) || !IsSecretConfigKey(ConfigLinkSigningKeyPrevious) {
		t.Fatal("both signing keys are secrets")
	}
	// ciphertext moved between fields: refused at load, final (AAD = field name)
	cur := sealedKey(t, ConfigLinkSigningKeyCurrent, "k")
	if err := e.Mutate(func(tx *Tx) error {
		if err := tx.SetConfig(ConfigLinkSigningKeyCurrent, cur); err != nil {
			return err
		}
		return tx.SetConfig(ConfigLinkSigningKeyPrevious, cur) // current's ciphertext in the previous field
	}); err != nil {
		t.Fatal(err) // the engine does not open secrets at write; the load does
	}
	if _, err := Open(Options{Dir: dir, MasterKey: linkMaster}); !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("a swapped signing key must be a security refusal at load: %v", err)
	}
}

func TestLinkTrust_Coherence_RoundTrip(t *testing.T) {
	e, dir := sealedEngine(t)
	cases := map[string]LinkTrust{
		"pub without kid":     {CurrentPub: pub32(1)},
		"kid without pub":     {CurrentKID: "k"},
		"not base64":          {CurrentPub: "%%%", CurrentKID: "k"},
		"wrong length":        {CurrentPub: base64.StdEncoding.EncodeToString([]byte("short")), CurrentKID: "k"},
		"previous no current": {PreviousPub: pub32(2), PreviousKID: "k2"},
		"seq no current":      {Seq: 4},
		"same kid":            {CurrentPub: pub32(1), CurrentKID: "k", PreviousPub: pub32(2), PreviousKID: "k"},
	}
	for name, lt := range cases {
		if err := e.Mutate(func(tx *Tx) error { return tx.SetLinkTrust(lt) }); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !e.Snapshot().LinkTrust().IsZero() {
		t.Fatal("refused anchors must leave no trace")
	}
	good := LinkTrust{CurrentPub: pub32(1), CurrentKID: "k1", PreviousPub: pub32(2), PreviousKID: "k0", Seq: 9}
	if err := e.Mutate(func(tx *Tx) error { return tx.SetLinkTrust(good) }); err != nil {
		t.Fatal(err)
	}
	e2 := openEngine(t, dir, func(o *Options) { o.MasterKey = linkMaster })
	if e2.Snapshot().LinkTrust() != good {
		t.Fatalf("round trip: %+v", e2.Snapshot().LinkTrust())
	}
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: linkMaster})
	if err != nil || rep.LinkTrustCurrentKID != "k1" || rep.LinkTrustPreviousKID != "k0" || rep.LinkTrustSeq != 9 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	if err := e2.Mutate(func(tx *Tx) error { return tx.SetLinkTrust(LinkTrust{}) }); err != nil || !e2.Snapshot().LinkTrust().IsZero() {
		t.Fatalf("clearing: %v", err)
	}
}
