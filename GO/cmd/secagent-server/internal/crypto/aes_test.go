package crypto

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	masterKey := "test-master-key-for-unit-tests"
	plaintext := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkq...\n-----END PRIVATE KEY-----"

	encrypted, err := EncryptAESGCM(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	if encrypted == "" {
		t.Fatal("expected non-empty ciphertext")
	}
	if encrypted == plaintext {
		t.Fatal("ciphertext must differ from plaintext")
	}

	decrypted, err := DecryptAESGCM(encrypted, masterKey)
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("roundtrip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesUniqueNonces(t *testing.T) {
	masterKey := "test-key"
	plaintext := "same plaintext"

	enc1, _ := EncryptAESGCM(plaintext, masterKey)
	enc2, _ := EncryptAESGCM(plaintext, masterKey)

	// AES-GCM with random nonce: two encryptions of the same plaintext differ
	if enc1 == enc2 {
		t.Error("expected different ciphertexts due to random nonce")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	encrypted, _ := EncryptAESGCM("secret", "correct-key")

	_, err := DecryptAESGCM(encrypted, "wrong-key")
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	_, err := DecryptAESGCM("not-valid-base64!!!", "key")
	if err == nil {
		t.Error("expected error for invalid base64 input")
	}
}

func TestDecryptTooShort(t *testing.T) {
	// Valid base64 but too short to contain nonce
	tooShort := "dGVzdA==" // "test" — 4 bytes, nonce is 12 bytes
	_, err := DecryptAESGCM(tooShort, "key")
	if err == nil {
		t.Error("expected error for ciphertext shorter than nonce size")
	}
}

func TestEncryptLargePayload(t *testing.T) {
	masterKey := "test-key"
	// RSA-4096 PKCS8 PEM is ~3500 bytes
	plaintext := strings.Repeat("A", 3500)

	encrypted, err := EncryptAESGCM(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptAESGCM large payload: %v", err)
	}

	decrypted, err := DecryptAESGCM(encrypted, masterKey)
	if err != nil {
		t.Fatalf("DecryptAESGCM large payload: %v", err)
	}
	if decrypted != plaintext {
		t.Error("large payload roundtrip mismatch")
	}
}

func TestDeriveKeyLength(t *testing.T) {
	key := deriveKey("any-master-key")
	if len(key) != 32 {
		t.Errorf("expected 32-byte key (AES-256), got %d", len(key))
	}
}

func TestWithAAD_RoundTripAndBinding(t *testing.T) {
	enc, err := EncryptWithAAD("secret", "mk", []byte("jwt_secret_current"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptWithAAD(enc, "mk", []byte("jwt_secret_current")); err != nil || got != "secret" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for _, aad := range [][]byte{[]byte("jwt_secret_previous"), nil, {}, []byte("jwt_secret_currentX")} {
		if _, err := DecryptWithAAD(enc, "mk", aad); err == nil {
			t.Errorf("a ciphertext moved to AAD %q must be rejected", aad)
		}
	}
	if _, err := DecryptWithAAD(enc, "other-key", []byte("jwt_secret_current")); err == nil {
		t.Error("wrong key must be rejected")
	}
	if _, err := DecryptWithAAD("!!!", "mk", nil); err == nil {
		t.Error("bad base64 must be rejected")
	}
	if _, err := DecryptWithAAD("AAAA", "mk", nil); err == nil {
		t.Error("short ciphertext must be rejected")
	}
}

// The legacy functions keep their behaviour (AAD nil): the SQLite store still uses them.
func TestAAD_DoesNotChangeLegacyFunctions(t *testing.T) {
	legacy, _ := EncryptAESGCM("v", "mk")
	if got, err := DecryptWithAAD(legacy, "mk", nil); err != nil || got != "v" {
		t.Fatalf("legacy ciphertext must open with nil AAD: %q %v", got, err)
	}
	withAAD, _ := EncryptWithAAD("v", "mk", []byte("f"))
	if _, err := DecryptAESGCM(withAAD, "mk"); err == nil {
		t.Fatal("legacy decrypt must not open an AAD-bound ciphertext")
	}
}

func TestDeriveStateHMACKey(t *testing.T) {
	a, err := DeriveStateHMACKey("mk")
	if err != nil || len(a) != 32 {
		t.Fatalf("%v %d", err, len(a))
	}
	b, _ := DeriveStateHMACKey("mk")
	c, _ := DeriveStateHMACKey("other")
	if string(a) != string(b) || string(a) == string(c) {
		t.Error("derivation must be deterministic and key dependent")
	}
	if string(a) == string(deriveKey("mk")) {
		t.Error("HMAC key must be a distinct derivation domain from the AES key")
	}
}
