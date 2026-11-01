package state

import (
	"errors"
	"strings"
	"testing"
)

// #214: the 32-byte minimum is enforced on new keys only. A state written under a shorter key
// (a v3.0.4 deployment) still opens with it, and `state rekey` — the documented remedy — moves it to
// a compliant key.
func TestMasterKeyLength_AHistoricalShortKeyStillOpensAndRekeys(t *testing.T) {
	short := "historical-key-19b"
	dir := t.TempDir()
	if err := Init(InitOptions{Dir: dir, MasterKey: short, RSABits: 2048, allowShortKey: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: short}); err != nil {
		t.Fatalf("a state under a short historical key must still open: %v", err)
	}
	o := rekeyOpts(dir)
	o.OldKey = short
	o.NewKey = varKey(MinNewMasterKeyBytes)
	if _, err := Rekey(o); err != nil {
		t.Fatalf("the rekey from a short key to a compliant one must work: %v", err)
	}
	if _, err := Open(Options{Dir: dir, MasterKey: o.NewKey}); err != nil {
		t.Fatalf("the rekeyed state must open with the new key: %v", err)
	}
}

func TestValidateMasterKeyLength(t *testing.T) {
	if err := ValidateMasterKeyLength(""); err != nil {
		t.Errorf("an empty key is not judged here: %v", err)
	}
	err := ValidateMasterKeyLength(strings.Repeat("x", 31))
	if !errors.Is(err, ErrMasterKeyTooShort) {
		t.Fatalf("31 bytes: %v", err)
	}
	if err := ValidateMasterKeyLength(varKey(32)); err != nil {
		t.Errorf("32 bytes: %v", err)
	}
}

// varKey returns a non-predictable test master key of n bytes (the key rules refuse repeated characters and patterns).
func varKey(n int) string {
	const src = "Tq9vXr2LmZk8WcYb4HnJ7sUd1EoGfAp5iBx3NtVw6QyKzRaMlSjCh0e+/=PdFgIuOl"
	out := make([]byte, n)
	for i := range out {
		out[i] = src[(i*7+i/len(src))%len(src)]
	}
	return string(out)
}
