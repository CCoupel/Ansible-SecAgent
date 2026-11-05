// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crypto provides AES-256-GCM encryption helpers for protecting
// sensitive values stored in the database (e.g. RSA private keys).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptAESGCM encrypts plaintext with AES-256-GCM using the provided master key.
// The master key is SHA-256 hashed to produce a 32-byte AES key.
// Returns base64(nonce || ciphertext).
func EncryptAESGCM(plaintext, masterKey string) (string, error) {
	key := deriveKey(masterKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAESGCM decrypts a value produced by EncryptAESGCM.
// Expects base64(nonce || ciphertext).
func DecryptAESGCM(encoded, masterKey string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	key := deriveKey(masterKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err)
	}

	return string(plaintext), nil
}

// deriveKey returns a 32-byte AES key derived from masterKey via SHA-256.
//
// A bare SHA-256 is not a password KDF (no salt, no work factor): it is sound only because
// RSA_MASTER_KEY is a random secret of at least 32 bytes, which `state init`, the server start and
// `state rekey` enforce (state.MinNewMasterKeyBytes, #214). The AES key and the HMAC key of the state
// are separated by domain (crypto/aad.go), and the derivation is deliberately unchanged so a state
// written by v3.0.4 with such a key is read as before (no HKDF, no schema_version bump).
func deriveKey(masterKey string) []byte {
	hash := sha256.Sum256([]byte(masterKey))
	return hash[:]
}
