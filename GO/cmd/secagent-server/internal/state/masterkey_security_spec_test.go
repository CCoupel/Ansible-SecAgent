package state

// #214 (D2) — requirements of the security review (_work/reports/security-reviewer-lot1-amont-v305.md):
//
//	D2-1 one shared validation: init, server start and rekey agree on the same constant
//	D2-2 no key (nor prefix, hash, or exact length) in errors and logs
//	D2-3 no format change: schema_version and "enc:" unchanged, a v3.0.4 state is read as before
//	D2-4 the threshold is NOT applied to a state already encrypted when it is only opened by the tools
//	     (restore of an old backup, verify, peek) and a short historical key can be rekeyed to a good one
//
// The two golden states in testdata/ were produced by the v3.0.4 `state init` (main @ 22dc4a2):
//   v304_short_key  — master key "historical-short-key" (20 bytes), accepted then
//   v304_long_key   — master key "v304-master-key-of-at-least-32-bytes!!" (38 bytes)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	goldenShortKey = "historical-short-key"
	goldenLongKey  = "v304-master-key-of-at-least-32-bytes!!"
)

func copyGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StateFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// D2-1: the three entry points use the one threshold.
func TestSecD2_1_OneThresholdForInitStartAndRekey(t *testing.T) {
	if MinNewMasterKeyBytes != 32 {
		t.Fatalf("threshold = %d, want 32", MinNewMasterKeyBytes)
	}
	for _, n := range []int{31, 32} {
		key := strings.Repeat("q", n)
		wantRefused := n < 32
		if got := ValidateMasterKeyLength(key) != nil; got != wantRefused {
			t.Errorf("start validation, %d bytes: refused=%v, want %v", n, got, wantRefused)
		}
		if got := Init(InitOptions{Dir: t.TempDir(), MasterKey: key, RSABits: 2048}) != nil; got != wantRefused {
			t.Errorf("state init, %d bytes: refused=%v, want %v", n, got, wantRefused)
		}
		if got := ValidateNewMasterKey("another-old-key", key) != nil; got != wantRefused {
			t.Errorf("state rekey (new key), %d bytes: refused=%v, want %v", n, got, wantRefused)
		}
	}
	if ValidateMasterKeyLength("") != nil {
		t.Error("an empty key is not judged by the length rule (each caller decides)")
	}
}

// D2-2: nothing derived from the key in the error: not the key, not a prefix, not its SHA-256, not its
// exact length (reviewer M5: no more than "< 32 bytes").
func TestSecD2_2_TheRefusalCarriesNothingDerivedFromTheKey(t *testing.T) {
	key := "Zx9-secret-19bytes!" // 19 bytes
	if len(key) != 19 {
		t.Fatalf("fixture length %d", len(key))
	}
	sum := sha256.Sum256([]byte(key))
	for name, err := range map[string]error{
		"start validation": ValidateMasterKeyLength(key),
		"state init":       Init(InitOptions{Dir: t.TempDir(), MasterKey: key, RSABits: 2048}),
	} {
		if err == nil {
			t.Fatalf("%s: a 19-byte key must be refused", name)
		}
		msg := err.Error()
		for what, needle := range map[string]string{
			"the key": key, "a prefix of the key": key[:6], "a suffix of the key": key[len(key)-6:],
			"its SHA-256": hex.EncodeToString(sum[:]), "its short hash": hex.EncodeToString(sum[:])[:12],
			"its exact length": "19 bytes",
		} {
			if strings.Contains(msg, needle) {
				t.Errorf("%s: the error contains %s: %q", name, what, msg)
			}
		}
		if !errors.Is(err, ErrMasterKeyTooShort) {
			t.Errorf("%s: the error must wrap ErrMasterKeyTooShort (callers classify it): %v", name, err)
		}
	}
}

// D2-3: nothing about the file format moves: schema_version 2, "enc:" values, and the v3.0.4 state with a
// long key opens and verifies exactly as before; the writer of a NEW state produces the same schema.
func TestSecD2_3_FormatUnchangedAndAV304StateIsReadAsBefore(t *testing.T) {
	dir := copyGolden(t, "v304_long_key")
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: goldenLongKey})
	if err != nil {
		t.Fatalf("a v3.0.4 state with a >= 32-byte key must verify unchanged: %v", err)
	}
	if rep.NeedsMigration {
		t.Error("a v3.0.4 state must not need a migration (no schema bump)")
	}
	e, err := Open(Options{Dir: dir, MasterKey: goldenLongKey})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, k := range []string{"rsa_key_current", "jwt_secret_current"} {
		v, _ := e.Snapshot().Config(k)
		plain, err := OpenSecret(v, goldenLongKey, ConfigAAD(k))
		if err != nil || plain == "" {
			t.Errorf("%s must open with the v3.0.4 derivation: %v", k, err)
		}
	}
	// a state written TODAY has the same schema_version as the golden one
	fresh := t.TempDir()
	if err := Init(InitOptions{Dir: fresh, MasterKey: goldenLongKey, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	versionOf := func(d string) float64 {
		raw, _ := os.ReadFile(filepath.Join(d, StateFile))
		var env map[string]any
		_ = json.Unmarshal(raw, &env)
		v, _ := env["schema_version"].(float64)
		return v
	}
	if versionOf(fresh) != versionOf(dir) || versionOf(dir) != 2 {
		t.Errorf("schema_version moved: golden %v, fresh %v (both must stay 2)", versionOf(dir), versionOf(fresh))
	}
}

// D2-4: a state sealed with a historical SHORT key stays openable by the read-only tools and can be
// rekeyed to a good key — the remedy the refusal message gives must actually work.
func TestSecD2_4_AHistoricalShortKeyStaysOpenableByTheToolsAndIsRekeyable(t *testing.T) {
	dir := copyGolden(t, "v304_short_key")
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: goldenShortKey}); err != nil {
		t.Fatalf("verify with the historical short key must work (tools do not apply the threshold): %v", err)
	}
	if _, err := PeekLinkTrust(dir, goldenShortKey, nil); err != nil && errors.Is(err, ErrMasterKeyTooShort) {
		t.Fatalf("the read-only tools must not refuse a historical short key: %v", err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: goldenShortKey}); err != nil {
		t.Fatalf("the engine opens a state sealed with a short key (only the SERVER START refuses it): %v", err)
	}
	// the remedy: state rekey from the short key to a long one
	newKey := "rekeyed-master-key-0123456789abcdefghij"
	res, err := Rekey(RekeyOptions{Dir: dir, OldKey: goldenShortKey, NewKey: newKey, Operator: "test"})
	if err != nil {
		t.Fatalf("rekey from a historical short key to a >= 32-byte key must work: %v", err)
	}
	if res.Restored {
		t.Fatal("the rekey was rolled back")
	}
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: newKey}); err != nil {
		t.Fatalf("the rekeyed state must verify with the new key: %v", err)
	}
	if _, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: goldenShortKey}); err == nil {
		t.Error("the old short key must no longer open the rekeyed state")
	}
}

// M4 (security review): a length check alone accepts a predictable key. Minimum cheap entropy check:
// at least 12 distinct characters and no repeated pattern; `openssl rand -base64 48` always passes.
func TestSecD2_M4_APredictableKeyOf32BytesIsRefused(t *testing.T) {
	for name, key := range map[string]string{
		"one character repeated":   strings.Repeat("a", 32),
		"short pattern repeated":   strings.Repeat("abcd", 8),
		"two characters repeated":  strings.Repeat("ab", 24),
		"fewer than 12 distinct":   "abcdefghijk" + strings.Repeat("a", 30),
		"digits sequence repeated": strings.Repeat("0123456789", 4),
	} {
		if len(key) < 32 {
			t.Fatalf("%s: fixture is too short (%d)", name, len(key))
		}
		if ValidateMasterKeyLength(key) == nil {
			t.Errorf("%s: a predictable %d-byte key must be refused at start", name, len(key))
		}
		if Init(InitOptions{Dir: t.TempDir(), MasterKey: key, RSABits: 2048}) == nil {
			t.Errorf("%s: a predictable %d-byte key must be refused by state init", name, len(key))
		}
	}
	for _, key := range []string{
		"Tq9vXr2LmZk8WcYb4HnJ7sUd1EoGfAp5iBx3NtVw6QyKzRaMlSjCh0e+/=", // random base64, 48 bytes decoded
		"v304-master-key-of-at-least-32-bytes!!",
	} {
		if err := ValidateMasterKeyLength(key); err != nil {
			t.Errorf("a random-looking key must pass: %v", err)
		}
	}
}
