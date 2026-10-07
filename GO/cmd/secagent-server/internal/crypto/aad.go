package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// stateHMACLabel is the HKDF info label of the state-file HMAC key. It is a derivation domain
// DISTINCT from the AES key (SHA-256 of the master key): the same master key never keys two
// different primitives with the same material.
const stateHMACLabel = "state-hmac-v1"

// EncryptWithAAD is EncryptAESGCM with additional authenticated data: the ciphertext is bound to
// aad (typically the name of the field it is stored in), so it cannot be moved to another field
// and still decrypt. Same key derivation and output format as EncryptAESGCM,
// base64(nonce || ciphertext), but only DecryptWithAAD with the same aad opens it.
func EncryptWithAAD(plaintext, masterKey string, aad []byte) (string, error) {
	gcm, err := newGCM(masterKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), aad)), nil
}

// DecryptWithAAD decrypts a value produced by EncryptWithAAD. It fails when aad differs from the
// one used to encrypt (a ciphertext moved to another field is rejected).
func DecryptWithAAD(encoded, masterKey string, aad []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	gcm, err := newGCM(masterKey)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], aad)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err)
	}
	return string(plaintext), nil
}

func newGCM(masterKey string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKey(masterKey))
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// DeriveStateHMACKey derives the 32-byte HMAC-SHA-256 key that authenticates the state file
// (HKDF-SHA-256 of the master key, label "state-hmac-v1"; domain distinct from the AES key).
func DeriveStateHMACKey(masterKey string) ([]byte, error) {
	k, err := hkdf.Key(sha256.New, []byte(masterKey), nil, stateHMACLabel, 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return k, nil
}
