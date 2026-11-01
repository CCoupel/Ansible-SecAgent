package state

// #214 (v3.0.5, D2) — spec tests of the RSA_MASTER_KEY minimum length at `state init`.
//
// Decision D2: a master key shorter than MinNewMasterKeyBytes (32) bytes is REFUSED (not a warning);
// the error carries the remedy (how to generate a key, `state rekey` for an existing deployment) and
// never the key itself; the derivation is NOT changed (AES key = SHA-256(master key), HMAC key =
// HKDF) so a state written by v3.0.4 with a key >= 32 bytes is read as before.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func keyOfLen(n int) string { return strings.Repeat("k", n) }

// (critical) a key shorter than 32 bytes is refused and NOTHING is written.
func TestSpec214_InitRefusesAMasterKeyShorterThan32Bytes(t *testing.T) {
	for _, n := range []int{1, 8, 16, 31} {
		key := keyOfLen(n)
		dir := t.TempDir()
		err := Init(InitOptions{Dir: dir, MasterKey: key, RSABits: 2048})
		if err == nil {
			t.Errorf("a %d-byte master key must be refused by state init", n)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "RSA_MASTER_KEY") || !strings.Contains(msg, "32") {
			t.Errorf("%d bytes: the refusal must name RSA_MASTER_KEY and the 32-byte minimum: %q", n, msg)
		}
		if !strings.Contains(msg, "openssl rand -base64 48") {
			t.Errorf("%d bytes: the refusal must give the generation command: %q", n, msg)
		}
		if n >= 8 && strings.Contains(msg, key) { // a 1-byte key may legitimately appear in a word
			t.Errorf("%d bytes: the error leaks the key: %q", n, msg)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Errorf("%d bytes: a refused init must write nothing, found %v", n, entries)
		}
	}
}

// The remedy for a deployment that already has a short key is `state rekey`: the message of an init
// refusal points to it (the operator reaching this message from the server start sees the same text).
func TestSpec214_RefusalNamesStateRekeyAsTheRemedyForAnExistingState(t *testing.T) {
	err := Init(InitOptions{Dir: t.TempDir(), MasterKey: keyOfLen(20), RSABits: 2048})
	if err == nil || !strings.Contains(err.Error(), "state rekey") {
		t.Fatalf("the refusal must mention 'state rekey': %v", err)
	}
}

// 32 bytes is the first accepted length; longer keys too.
func TestSpec214_InitAcceptsMasterKeysOf32BytesAndMore(t *testing.T) {
	for _, n := range []int{32, 33, 48, 64, 200} {
		dir := t.TempDir()
		if err := Init(InitOptions{Dir: dir, MasterKey: keyOfLen(n), RSABits: 2048}); err != nil {
			t.Errorf("a %d-byte master key must be accepted: %v", n, err)
			continue
		}
		if _, err := Open(Options{Dir: dir, MasterKey: keyOfLen(n)}); err != nil {
			t.Errorf("%d bytes: the initialized state must open with the same key: %v", n, err)
		}
	}
}

// The length is counted in BYTES, not characters: 16 two-byte runes make 32 bytes, 15 + 1 ASCII make 31.
func TestSpec214_LengthIsCountedInBytesNotRunes(t *testing.T) {
	ok := strings.Repeat("é", 16) // 32 bytes, 16 runes
	if len(ok) != 32 {
		t.Fatalf("fixture: %d bytes", len(ok))
	}
	if err := Init(InitOptions{Dir: t.TempDir(), MasterKey: ok, RSABits: 2048}); err != nil {
		t.Errorf("32 bytes (16 runes) must be accepted: %v", err)
	}
	short := strings.Repeat("é", 15) + "a" // 31 bytes, 16 runes
	if len(short) != 31 {
		t.Fatalf("fixture: %d bytes", len(short))
	}
	if err := Init(InitOptions{Dir: t.TempDir(), MasterKey: short, RSABits: 2048}); err == nil {
		t.Error("31 bytes (16 runes) must be refused")
	}
}

// The explicit clear-text test mode has no master key: it is not affected by the length rule.
func TestSpec214_InsecureTestModeWithoutKeyIsUnaffected(t *testing.T) {
	if err := Init(InitOptions{Dir: t.TempDir(), AllowPlaintext: true, RSABits: 2048}); err != nil {
		t.Fatalf("test mode without a key must still work: %v", err)
	}
}

// One constant for init and rekey: the minimum of the new key of a rekey and of `state init` agree.
func TestSpec214_InitAndRekeyShareTheSameMinimum(t *testing.T) {
	if MinNewMasterKeyBytes != 32 {
		t.Fatalf("MinNewMasterKeyBytes = %d, want 32", MinNewMasterKeyBytes)
	}
	if err := ValidateNewMasterKey("old", keyOfLen(31)); err == nil {
		t.Error("rekey must refuse 31 bytes")
	}
	if err := ValidateNewMasterKey("old", keyOfLen(32)); err != nil {
		t.Errorf("rekey must accept 32 bytes: %v", err)
	}
	if err := Init(InitOptions{Dir: t.TempDir(), MasterKey: keyOfLen(31), RSABits: 2048}); err == nil {
		t.Error("init must refuse 31 bytes")
	}
}

// Derivation unchanged (D2: no KDF migration, no schema bump): a secret of a state created with a
// >= 32-byte key opens with AES-256-GCM keyed by SHA-256(master key), the v3.0.4 construction, which
// this test re-implements independently of the product code. A switch to HKDF would fail here.
func TestSpec214_KeyDerivationIsUnchangedSHA256ForAES(t *testing.T) {
	key := strings.Repeat("0123456789abcdef", 3) // 48 bytes
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: key, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	e, err := Open(Options{Dir: dir, MasterKey: key})
	if err != nil {
		t.Fatalf("a state initialized with a long key must open: %v", err)
	}
	snap := e.Snapshot()
	sealed, _ := snap.Config("jwt_secret_current")
	if !strings.HasPrefix(sealed, EncPrefix) {
		t.Fatalf("the JWT secret must be encrypted: %.12q", sealed)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, EncPrefix))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], ConfigAAD("jwt_secret_current"))
	if err != nil {
		t.Fatalf("the value must open with AES-256-GCM keyed by SHA-256(master key) (derivation changed?): %v", err)
	}
	if len(plain) != 43 { // 32 random bytes, base64 raw URL
		t.Errorf("unexpected JWT secret length %d", len(plain))
	}
}

// An existing state (written with a >= 32-byte key, as v3.0.4 did) is read again by the new code,
// and the key never shows in the engine's error when it does not match.
func TestSpec214_AnExistingLongKeyStateIsReadAgainAndAWrongKeyLeaksNothing(t *testing.T) {
	key := keyOfLen(40)
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: key, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: key}); err != nil {
		t.Fatalf("reopen with the right key: %v", err)
	}
	wrong := strings.Repeat("w", 40)
	_, err := Open(Options{Dir: dir, MasterKey: wrong})
	if err == nil {
		t.Fatal("a wrong key must not open the state")
	}
	if strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), key) {
		t.Errorf("the error leaks a master key: %v", err)
	}
}
