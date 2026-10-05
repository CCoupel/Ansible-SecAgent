package state

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRelay(id, mode string) RelayNode {
	n := RelayNode{ID: "uuid-" + id, RelayID: id, Mode: mode, CreatedAt: time.Now(), JTI: "jti-" + id, TokenExp: time.Now().Add(time.Hour).Unix()}
	if mode == ModePush {
		n.TokenSecret = EncPrefix + "c2VhbGVk"
	} else {
		n.TokenHash = "hash-" + id
	}
	return n
}

func mustMutate(t *testing.T, e *Engine, fn func(*Tx) error) {
	t.Helper()
	if err := e.Mutate(fn); err != nil {
		t.Fatal(err)
	}
}

func TestUniqueKeysAreEnforced(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, func(tx *Tx) error {
		for _, f := range []error{
			tx.PutEnrollmentToken(EnrollmentToken{ID: "e1", TokenHash: "H", HostnamePattern: "*", CreatedAt: time.Now()}),
			tx.PutPluginToken(PluginToken{ID: "p1", TokenHash: "H", Role: "plugin", CreatedAt: time.Now()}), // same hash, other table: fine
			tx.PutRelayParentToken(RelayParentToken{ID: "r1", JTI: "J", ParentID: "up", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}),
			tx.PutRelayNode(newRelay("dmz1", ModePull)),
		} {
			if f != nil {
				return f
			}
		}
		return nil
	})
	cases := map[string]func(*Tx) error{
		"enrollment token_hash": func(tx *Tx) error {
			return tx.PutEnrollmentToken(EnrollmentToken{ID: "e2", TokenHash: "H", HostnamePattern: "*"})
		},
		"plugin token_hash": func(tx *Tx) error {
			if err := tx.PutPluginToken(PluginToken{ID: "p2", TokenHash: "P", Role: "plugin"}); err != nil {
				return err
			}
			return tx.PutPluginToken(PluginToken{ID: "p3", TokenHash: "P", Role: "plugin"})
		},
		"relay-parent jti": func(tx *Tx) error {
			return tx.PutRelayParentToken(RelayParentToken{ID: "r2", JTI: "J", ParentID: "up"})
		},
		"relay node uuid": func(tx *Tx) error {
			n := newRelay("dmz2", ModePull)
			n.ID = "uuid-dmz1"
			return tx.PutRelayNode(n)
		},
		"relay token_hash": func(tx *Tx) error {
			n := newRelay("dmz3", ModePull)
			n.TokenHash = "hash-dmz1"
			return tx.PutRelayNode(n)
		},
	}
	for name, fn := range cases {
		if err := e.Mutate(fn); !errors.Is(err, ErrDuplicate) {
			t.Errorf("%s: error %v, want ErrDuplicate", name, err)
		}
	}
	// a rejected mutation leaves nothing (p2 was added before the duplicate p3)
	if _, ok := e.Snapshot().PluginToken("p2"); ok {
		t.Error("p2 survived its mutation's failure")
	}
	// replacing the SAME entity (same id, new hash) frees the old hash
	mustMutate(t, e, func(tx *Tx) error {
		return tx.PutEnrollmentToken(EnrollmentToken{ID: "e1", TokenHash: "H2", HostnamePattern: "*", CreatedAt: time.Now()})
	})
	if _, ok := e.Snapshot().EnrollmentTokenByHash("H"); ok {
		t.Error("the old hash must be released")
	}
	if tok, ok := e.Snapshot().EnrollmentTokenByHash("H2"); !ok || tok.ID != "e1" {
		t.Error("lookup by the new hash")
	}
}

func TestRelayNodeTokenInvariants(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	push := newRelay("pushy", ModePush)
	push.TokenSecret = "plaintext-token" // NOT enc:
	if err := e.Mutate(func(tx *Tx) error { return tx.PutRelayNode(push) }); !errors.Is(err, ErrSecurityInvariant) {
		t.Errorf("a clear push token_secret must be refused at write: %v", err)
	}
	pushNoSecret := newRelay("pushy2", ModePush)
	pushNoSecret.TokenSecret = ""
	if err := e.Mutate(func(tx *Tx) error { return tx.PutRelayNode(pushNoSecret) }); !errors.Is(err, ErrInvalid) {
		t.Errorf("push without token_secret: %v", err)
	}
	pushWithHash := newRelay("pushy3", ModePush)
	pushWithHash.TokenHash = "h"
	if err := e.Mutate(func(tx *Tx) error { return tx.PutRelayNode(pushWithHash) }); !errors.Is(err, ErrInvalid) {
		t.Errorf("push with a token_hash: %v", err)
	}
	pullWithSecret := newRelay("pully", ModePull)
	pullWithSecret.TokenSecret = EncPrefix + "x"
	if err := e.Mutate(func(tx *Tx) error { return tx.PutRelayNode(pullWithSecret) }); !errors.Is(err, ErrInvalid) {
		t.Errorf("pull with a token_secret: %v", err)
	}
	bad := newRelay("weird", "sideways")
	if err := e.Mutate(func(tx *Tx) error { return tx.PutRelayNode(bad) }); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown mode: %v", err)
	}
	mustMutate(t, e, func(tx *Tx) error { return tx.PutRelayNode(newRelay("good", ModePush)) })
}

func TestClearTokenSecretOnLoadRefusesWithoutFallingBackOnPrev(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, addAgent("a")) // so a valid .prev exists after the next write
	// craft a state whose push relay carries a clear token_secret, with a VALID checksum
	p := newPayload()
	p.RelayNodes["leaky"] = RelayNode{ID: "u", RelayID: "leaky", Mode: ModePush, TokenSecret: "clear-text-secret", CreatedAt: time.Now()}
	data, err := encode(&p, 9, "evil", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(OSFS{}, dir, data, true); err != nil { // .prev = the valid generation
		t.Fatal(err)
	}
	_, err = Open(Options{Dir: dir})
	if !errors.Is(err, ErrSecurityInvariant) {
		t.Fatalf("must refuse to start with ErrSecurityInvariant, got %v", err)
	}
	if strings.Contains(err.Error(), "clear-text-secret") {
		t.Error("the secret must not appear in the error")
	}
}

func TestRevokedRelayMustBeBlacklistedAtomically(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	mustMutate(t, e, func(tx *Tx) error { return tx.PutRelayNode(newRelay("r", ModePull)) })

	revokeOnly := func(tx *Tx) error {
		n, _ := tx.RelayNode("r")
		n.Revoked = true
		return tx.PutRelayNode(n)
	}
	if err := e.Mutate(revokeOnly); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoking without blacklisting must be refused: %v", err)
	}
	if n, _ := e.Snapshot().RelayNode("r"); n.Revoked {
		t.Fatal("the refused revocation is visible")
	}
	both := func(tx *Tx) error {
		n, _ := tx.RelayNode("r")
		n.Revoked = true
		if err := tx.PutBlacklist(BlacklistEntry{JTI: n.JTI, Hostname: "r", RevokedAt: time.Now(), Reason: "test", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			return err
		}
		return tx.PutRelayNode(n)
	}
	mustMutate(t, e, both)
	if n, _ := e.Snapshot().RelayNode("r"); !n.Revoked || !e.Snapshot().Blacklisted(n.JTI) {
		t.Fatal("flag and blacklist entry must land together")
	}
	// a file where a revoked relay is not blacklisted is refused at load
	p := newPayload()
	n := newRelay("x", ModePull)
	n.Revoked = true
	p.RelayNodes["x"] = n
	data, _ := encode(&p, 5, "t", time.Now())
	d2 := t.TempDir()
	if err := atomicWrite(OSFS{}, d2, data, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: d2}); err == nil {
		t.Error("a revoked relay without blacklist entry must not load")
	}
}

func TestBlacklistPurgeBoundsTheFile(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	now := time.Now()
	mustMutate(t, e, func(tx *Tx) error {
		for i, exp := range []time.Duration{-time.Hour, -time.Minute, time.Hour} {
			if err := tx.PutBlacklist(BlacklistEntry{JTI: string(rune('a' + i)), RevokedAt: now, ExpiresAt: now.Add(exp)}); err != nil {
				return err
			}
		}
		return nil
	})
	var purged int
	mustMutate(t, e, func(tx *Tx) error { purged = tx.PurgeExpiredBlacklist(now); return nil })
	if purged != 2 || len(e.Snapshot().BlacklistEntries()) != 1 || !e.Snapshot().Blacklisted("c") {
		t.Errorf("purged %d, left %v", purged, e.Snapshot().BlacklistEntries())
	}
}

// ── secrets ──────────────────────────────────────────────────────────────────

func TestSecretConfigIsRefusedInClearWhenAMasterKeyIsConfigured(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, func(o *Options) { o.RequireEncryptedSecrets = true })
	for _, k := range []string{"rsa_key_current", "rsa_key_previous", "jwt_secret_current", "jwt_secret_previous"} {
		if err := e.Mutate(func(tx *Tx) error { return tx.SetConfig(k, "clear") }); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s in clear accepted: %v", k, err)
		}
		mustMutate(t, e, func(tx *Tx) error { return tx.SetConfig(k, EncPrefix+"abc") })
	}
	mustMutate(t, e, func(tx *Tx) error { return tx.SetConfig("key_rotation_deadline", "2026-10-06T00:00:00Z") }) // not a secret
	// without a master key (test mode) clear values are accepted
	d2 := t.TempDir()
	seedState(t, d2)
	e2 := openEngine(t, d2, nil)
	mustMutate(t, e2, func(tx *Tx) error { return tx.SetConfig("jwt_secret_current", "clear") })
}

func TestNoSecretInClearInTheFile(t *testing.T) {
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: "unit-test-master-key", RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e := openEngine(t, dir, func(o *Options) { o.RequireEncryptedSecrets = true })
	mustMutate(t, e, func(tx *Tx) error {
		if err := tx.PutRelayNode(newRelay("p", ModePush)); err != nil {
			return err
		}
		if err := tx.PutEnrollmentToken(EnrollmentToken{ID: "e", TokenHash: "sha256-of-token", HostnamePattern: "*", CreatedAt: time.Now()}); err != nil {
			return err
		}
		return tx.PutPluginToken(PluginToken{ID: "pl", TokenHash: "sha256-of-plugin-token", Role: "plugin", CreatedAt: time.Now()})
	})
	raw := string(mustFile(t, filepath.Join(dir, StateFile)))
	for _, forbidden := range []string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "unit-test-master-key"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("the file contains %q", forbidden)
		}
	}
	// walk the JSON: every secret-bearing field is enc:-prefixed
	var env struct {
		Payload Payload `json:"payload"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	for k := range secretConfigKeys {
		if v, ok := env.Payload.ServerConfig[k]; ok && v != "" && !strings.HasPrefix(v, EncPrefix) {
			t.Errorf("server_config[%s] is not encrypted", k)
		}
	}
	for id, n := range env.Payload.RelayNodes {
		if n.TokenSecret != "" && !strings.HasPrefix(n.TokenSecret, EncPrefix) {
			t.Errorf("relay %s token_secret is not encrypted", id)
		}
	}
	if env.Payload.ServerConfig["rsa_key_current"] == "" || env.Payload.ServerConfig["jwt_secret_current"] == "" {
		t.Error("init must have created the RSA key and the JWT secret")
	}
}
