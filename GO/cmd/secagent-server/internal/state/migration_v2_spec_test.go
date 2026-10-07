package state

// #141 / #146 (L1b) — SPECIFICATION of the v1 → v2 state migration (plan rev2 §2 option A, tests 8, 9
// and 10): SchemaVersion 2, a v3.0.3 build refuses the v2 file, the migration takes a backup of the v1
// file BEFORE the first v2 write, is idempotent, and a failure at ANY step leaves the v1 usable.
//
// Decision of the user: no backward compatibility (a v3.0.3 binary refuses a v2 state).

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v303Reads is the compatibility rule of a v3.0.3 build, copied from its decoder:
// `if env.SchemaVersion != SchemaVersion(=1) { ErrSchemaVersion }`.
func v303Reads(schemaVersion int) bool { return schemaVersion == 1 }

// seedV1 writes into dir a state exactly as v3.0.3 wrote it: schema_version 1 and NO link_tokens /
// link_trust section. It returns the exact bytes of the file.
func seedV1(t testing.TB, dir string) []byte {
	t.Helper()
	p := newPayload()
	p.Agents["host-a"] = Agent{Hostname: "host-a", PublicKeyPEM: testPEM("host-a"), TokenJTI: "jti-host-a", EnrolledAt: time.Unix(1700000000, 0).UTC()}
	p.Blacklist["old-jti"] = BlacklistEntry{JTI: "old-jti", Hostname: "gone", RevokedAt: time.Unix(1700000000, 0).UTC(), Reason: "test", ExpiresAt: time.Now().Add(24 * time.Hour).UTC()}
	data, err := encode(&p, 3, "v303", time.Now())
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
	if data, err = json.Marshal(env); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
		t.Fatal(err)
	}
	return mustFile(t, filepath.Join(dir, StateFile))
}

func schemaOf(t testing.TB, path string) int {
	t.Helper()
	var env struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(mustFile(t, path), &env); err != nil {
		t.Fatal(err)
	}
	return env.SchemaVersion
}

func TestSpecV2_BuildWritesSchema2AndAV303BuildRefusesIt(t *testing.T) {
	if SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, the link tokens (#141/#146) are format 2", SchemaVersion)
	}
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, addAgent("a"))
	got := schemaOf(t, filepath.Join(dir, StateFile))
	if got != 2 {
		t.Fatalf("a v3.0.4 write must produce schema_version 2, got %d", got)
	}
	if v303Reads(got) {
		t.Fatal("a v3.0.3 build must refuse this file (ErrSchemaVersion, no silent downgrade)")
	}
}

func TestSpecV2_UnknownSchemaVersionsAreRefusedWithoutFallback(t *testing.T) {
	for _, v := range []int{0, 3, 99, -1} {
		p := newPayload()
		data, err := encode(&p, 1, "t", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		_ = json.Unmarshal(data, &env)
		env.SchemaVersion = v
		bad, _ := json.Marshal(env)
		if _, _, err := decode(bad, time.Now()); !errors.Is(err, ErrSchemaVersion) {
			t.Errorf("schema_version %d: %v, want ErrSchemaVersion", v, err)
		}
	}
}

func TestSpecV2_ReadingAV1StateNeverWritesAnything(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1(t, dir)
	before := listDir(t, dir)

	e, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("a v1 state must load (it is migrated by the first write, not by the read): %v", err)
	}
	if _, ok := e.Snapshot().Agent("host-a"); !ok || !e.Snapshot().Blacklisted("old-jti") {
		t.Fatal("the v1 content must be fully readable")
	}
	if !bytes.Equal(mustFile(t, filepath.Join(dir, StateFile)), v1) {
		t.Error("opening must not rewrite relay.state")
	}
	if after := listDir(t, dir); len(after) != len(before) {
		t.Errorf("opening created files: %v → %v", before, after)
	}
	if _, err := os.Stat(filepath.Join(dir, V1BackupFile)); err == nil {
		t.Error("no backup before the first write")
	}
}

func TestSpecV2_FirstWriteBacksUpTheV1ThenMigrates(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, addAgent("host-b"))

	if got := schemaOf(t, filepath.Join(dir, StateFile)); got != 2 {
		t.Fatalf("after the first write the state is schema_version %d, want 2", got)
	}
	bak := filepath.Join(dir, V1BackupFile)
	if !bytes.Equal(mustFile(t, bak), v1) {
		t.Fatal("relay.state.v1.bak must be the v1 file, byte for byte (rollback = restore it + v3.0.3 binaries)")
	}
	if m := mode(t, bak); m != 0o600 {
		t.Errorf("the backup holds the whole state: mode %v, want 0600", m)
	}
	// nothing of the v1 content is lost, nothing is added but the empty v2 sections
	r, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("the migrated state must load: %v", err)
	}
	s := r.Snapshot()
	for _, h := range []string{"host-a", "host-b"} {
		if _, ok := s.Agent(h); !ok {
			t.Errorf("agent %s lost by the migration", h)
		}
	}
	if !s.Blacklisted("old-jti") {
		t.Error("blacklist entry lost by the migration")
	}
	var env struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	_ = json.Unmarshal(mustFile(t, filepath.Join(dir, StateFile)), &env)
	if string(env.Payload["link_tokens"]) != "{}" {
		t.Errorf("link_tokens must be an empty section after migration, got %s", env.Payload["link_tokens"])
	}
	if _, ok := env.Payload["link_trust"]; !ok {
		t.Error("link_trust section must exist after migration")
	}
}

func TestSpecV2_MigrationIsIdempotentAndNeverOverwritesTheV1Backup(t *testing.T) {
	dir := t.TempDir()
	v1 := seedV1(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, addAgent("host-b"))
	mustMutate(t, e, addAgent("host-c"))
	mustMutate(t, e, addAgent("host-d"))
	// a restart, then more writes
	e2 := openEngine(t, dir, nil)
	mustMutate(t, e2, addAgent("host-e"))

	if !bytes.Equal(mustFile(t, filepath.Join(dir, V1BackupFile)), v1) {
		t.Fatal("the v1 backup must survive every later write unchanged (it is the only way back)")
	}
	for _, n := range listDir(t, dir) {
		if n == V1BackupFile+".tmp" {
			t.Error("a temporary backup file is left behind")
		}
	}
	if got := schemaOf(t, filepath.Join(dir, StateFile)); got != 2 {
		t.Errorf("schema_version %d", got)
	}
}

func TestSpecV2_AFailureAtAnyStepNeverLosesTheV1(t *testing.T) {
	for k := 1; ; k++ {
		dir := t.TempDir()
		v1 := seedV1(t, dir)
		fs := &faultFS{failAt: k}
		e := openEngine(t, dir, func(o *Options) { o.FS = fs })
		err := e.Mutate(addAgent("host-b"))
		if err == nil {
			if k == 1 {
				t.Fatal("the first step must fail")
			}
			return // went past the last step: every step was exercised
		}
		if !errors.Is(err, errInjected) {
			t.Fatalf("step %d: error %v", k, err)
		}
		if _, ok := e.Snapshot().Agent("host-b"); ok {
			t.Fatalf("step %d: the failed migration is visible in memory", k)
		}
		// a fresh process reads the directory: the data is intact whatever the step
		buf := captureSlog(t)
		r, oerr := Open(Options{Dir: dir})
		if oerr != nil {
			t.Fatalf("step %d: the directory must always hold a loadable state: %v\n%s", k, oerr, buf.String())
		}
		if _, ok := r.Snapshot().Agent("host-a"); !ok || !r.Snapshot().Blacklisted("old-jti") {
			t.Fatalf("step %d: v1 data lost", k)
		}
		// invariant: relay.state is only ever v2 if the v1 backup was written BEFORE
		sp := filepath.Join(dir, StateFile)
		if _, serr := os.Stat(sp); serr == nil && schemaOf(t, sp) == 2 {
			bak, berr := os.ReadFile(filepath.Join(dir, V1BackupFile))
			if berr != nil || !bytes.Equal(bak, v1) {
				t.Fatalf("step %d: relay.state is v2 but the v1 backup is missing or altered (%v)", k, berr)
			}
		} else if serr == nil && !bytes.Equal(mustFile(t, sp), v1) {
			t.Fatalf("step %d: relay.state is neither the untouched v1 nor a complete v2", k)
		}
		if k > 60 {
			t.Fatal("the write never completes")
		}
	}
}

func TestSpecV2_LinkSigningKeysAreSecretsEncryptedAtRest(t *testing.T) {
	for _, k := range []string{ConfigLinkSigningKeyCurrent, ConfigLinkSigningKeyPrevious} {
		if !IsSecretConfigKey(k) {
			t.Errorf("%s must be a secret config key (enc:, AAD = field name)", k)
		}
	}
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, func(o *Options) { o.RequireEncryptedSecrets = true })
	for _, k := range []string{ConfigLinkSigningKeyCurrent, ConfigLinkSigningKeyPrevious} {
		if err := e.Mutate(func(tx *Tx) error { return tx.SetConfig(k, "MC4CAQAwBQYDK2VwBCIEIA-clear-ed25519-private-key") }); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted in clear: %v", k, err)
		}
		mustMutate(t, e, func(tx *Tx) error { return tx.SetConfig(k, EncPrefix+"abc") })
	}
}

// ── link token registry and trust anchor (Tx.PutLinkToken / SetLinkTrust, L1b) ─────────────────────

func specLinkToken(id string, exp time.Time) LinkToken {
	return LinkToken{ID: id, JTI: "jti-" + id, Role: RoleRelayChild, Sub: "relay-x", Aud: "relay-p", KID: "kid-1",
		CreatedAt: time.Now().UTC(), ExpiresAt: exp.UTC()}
}

// writeRaw puts a crafted payload on disk as a (test-mode) state file and opens it.
func openCrafted(t *testing.T, p *Payload) error {
	t.Helper()
	dir := t.TempDir()
	data, err := encode(p, 5, "crafted", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(OSFS{}, dir, data, false, nil); err != nil {
		t.Fatal(err)
	}
	_, err = Open(Options{Dir: dir})
	return err
}

func specSigningKeyPayload() Payload {
	p := newPayload()
	p.ServerConfig[ConfigLinkSigningKeyCurrent] = EncPrefix + "abc"
	return p
}

// A revoked link token whose JTI has not expired is blacklisted IN THE SAME MUTATION — whatever the
// order of the two writes inside it — or nothing is written; and a file that breaks the rule is refused at load.
func TestSpecV2_RevokedLinkTokenMustBeBlacklistedInTheSameMutation(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, func(o *Options) { o.RequireEncryptedSecrets = true })
	exp := time.Now().Add(24 * time.Hour)
	mustMutate(t, e, func(tx *Tx) error {
		if err := tx.SetConfig(ConfigLinkSigningKeyCurrent, EncPrefix+"abc"); err != nil {
			return err
		}
		for _, id := range []string{"a", "b", "c"} {
			if err := tx.PutLinkToken(specLinkToken(id, exp)); err != nil {
				return err
			}
		}
		return nil
	})
	now := time.Now().UTC()
	revoked := func(id string) LinkToken { tk := specLinkToken(id, exp); tk.RevokedAt = &now; return tk }
	bl := func(id string) BlacklistEntry {
		return BlacklistEntry{JTI: "jti-" + id, RevokedAt: now, Reason: "link_revoked", ExpiresAt: exp.UTC()}
	}

	// 1. revocation alone: refused, and not even the flag is visible afterwards
	if err := e.Mutate(func(tx *Tx) error { return tx.PutLinkToken(revoked("a")) }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoking without blacklisting must be refused: %v", err)
	}
	if tk, _ := e.Snapshot().LinkToken("a"); tk.RevokedAt != nil || e.Snapshot().Blacklisted("jti-a") {
		t.Fatal("the refused revocation left a trace")
	}
	// 2. blacklist alone is not a revocation of the token: fine, but the token stays active
	mustMutate(t, e, func(tx *Tx) error { return tx.PutBlacklist(bl("b")) })
	if tk, _ := e.Snapshot().LinkToken("b"); tk.RevokedAt != nil {
		t.Fatal("blacklisting a jti does not by itself mark the registry entry")
	}
	// 3. both, in either order, in ONE mutation
	mustMutate(t, e, func(tx *Tx) error { // blacklist first
		if err := tx.PutBlacklist(bl("a")); err != nil {
			return err
		}
		return tx.PutLinkToken(revoked("a"))
	})
	mustMutate(t, e, func(tx *Tx) error { // token first
		if err := tx.PutLinkToken(revoked("c")); err != nil {
			return err
		}
		return tx.PutBlacklist(bl("c"))
	})
	for _, id := range []string{"a", "c"} {
		if tk, _ := e.Snapshot().LinkToken(id); tk.RevokedAt == nil || !e.Snapshot().Blacklisted("jti-"+id) {
			t.Errorf("%s: flag and blacklist entry must land together", id)
		}
	}
	// 4. an EXPIRED revoked token needs no blacklist entry (it may have been purged)
	mustMutate(t, e, func(tx *Tx) error {
		tk := specLinkToken("old", now.Add(-time.Hour))
		tk.RevokedAt = &now
		return tx.PutLinkToken(tk)
	})
	// 5. at load: a file with a revoked, unexpired, non blacklisted link token does not load
	p := specSigningKeyPayload()
	tk := revoked("x")
	p.LinkTokens["x"] = tk
	if err := openCrafted(t, &p); err == nil {
		t.Error("a revoked link token whose jti is not blacklisted must not load")
	}
	p.Blacklist["jti-x"] = bl("x")
	if err := openCrafted(t, &p); err != nil {
		t.Errorf("the same file with the blacklist entry must load: %v", err)
	}
	// 6. link tokens need the key that signed them
	p2 := newPayload()
	p2.LinkTokens["y"] = specLinkToken("y", exp)
	if err := openCrafted(t, &p2); err == nil {
		t.Error("link tokens without a link signing key must not load")
	}
}

func specPub(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// An incoherent trust anchor is refused by the write AND at load; the zero value is "no anchor".
func TestSpecV2_LinkTrustCoherence(t *testing.T) {
	bad := map[string]LinkTrust{
		"public key without kid":        {RootID: "root", CurrentPub: specPub(1)},
		"kid without public key":        {RootID: "root", CurrentKID: "k"},
		"public key without root id":    {CurrentPub: specPub(1), CurrentKID: "k"},
		"not base64":                    {RootID: "root", CurrentPub: "%%%", CurrentKID: "k"},
		"not 32 bytes":                  {RootID: "root", CurrentPub: base64.RawURLEncoding.EncodeToString([]byte("short")), CurrentKID: "k"},
		"previous without current":      {RootID: "root", PreviousPub: specPub(2), PreviousKID: "k2"},
		"sequence without current":      {Seq: 4},
		"root id alone":                 {RootID: "root"},
		"same kid for current+previous": {RootID: "root", CurrentPub: specPub(1), CurrentKID: "k", PreviousPub: specPub(2), PreviousKID: "k"},
	}
	good := LinkTrust{RootID: "root", CurrentPub: specPub(1), CurrentKID: "k1", PreviousPub: specPub(2), PreviousKID: "k0", Seq: 9}

	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	for name, lt := range bad {
		if err := e.Mutate(func(tx *Tx) error { return tx.SetLinkTrust(lt) }); !errors.Is(err, ErrInvalid) {
			t.Errorf("write, %s: %v", name, err)
		}
		p := newPayload()
		p.LinkTrust = lt
		if err := openCrafted(t, &p); err == nil {
			t.Errorf("load, %s: an incoherent link_trust must not load", name)
		}
	}
	if !e.Snapshot().LinkTrust().IsZero() {
		t.Fatal("refused anchors left a trace")
	}
	// the zero value and a coherent anchor are valid, and survive a restart
	p := newPayload()
	if err := openCrafted(t, &p); err != nil {
		t.Errorf("no anchor must load: %v", err)
	}
	mustMutate(t, e, func(tx *Tx) error { return tx.SetLinkTrust(good) })
	if got := openEngine(t, dir, nil).Snapshot().LinkTrust(); got != good {
		t.Errorf("round trip: %+v", got)
	}
	p.LinkTrust = good
	if err := openCrafted(t, &p); err != nil {
		t.Errorf("a coherent anchor must load: %v", err)
	}
	mustMutate(t, e, func(tx *Tx) error { return tx.SetLinkTrust(LinkTrust{}) })
	if !e.Snapshot().LinkTrust().IsZero() {
		t.Error("clearing the anchor")
	}
}
