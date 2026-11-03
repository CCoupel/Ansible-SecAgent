// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"errors"
	"fmt"
)

// MinNewMasterKeyBytes is the minimum length, in bytes, of RSA_MASTER_KEY (#214). The AES-256 key of
// the sealed secrets is SHA-256 of the master key (crypto/aes.go): that is sound for a random key of
// at least 32 bytes and weak for a short, guessable one, so a shorter key is REFUSED rather than
// stretched (no KDF change: the format of the state stays the one of v3.0.4).
//
// It applies to `state init`, to the start of the server and to the NEW key of `state rekey`. It is
// not applied to the CURRENT key of `state rekey` and of the read-only state tools: a historical key
// may be shorter and must stay openable, otherwise `state rekey` could not repair a deployment.
const MinNewMasterKeyBytes = 32

// ErrMasterKeyTooShort is returned for a RSA_MASTER_KEY shorter than MinNewMasterKeyBytes. The message
// carries the remedy and never the key.
var ErrMasterKeyTooShort = errors.New("RSA_MASTER_KEY is too short")

// MinDistinctMasterKeyChars is the fewest distinct characters a master key may have (#214, M4).
const MinDistinctMasterKeyChars = 12

// ErrMasterKeyPredictable is returned for a long enough RSA_MASTER_KEY that is trivially guessable: one
// repeated character, a repeated pattern, or fewer than MinDistinctMasterKeyChars distinct characters.
var ErrMasterKeyPredictable = errors.New("RSA_MASTER_KEY is predictable")

// isPredictableKey is a cheap sanity check, not an entropy estimate: `openssl rand -base64 48` always passes.
func isPredictableKey(key string) bool {
	seen := map[rune]struct{}{}
	for _, r := range key {
		seen[r] = struct{}{}
	}
	if len(seen) < MinDistinctMasterKeyChars {
		return true
	}
	n := len(key)
	for p := 1; p <= n/2; p++ { // the whole key is a block of p bytes repeated
		periodic := true
		for i := 0; i+p < n; i++ {
			if key[i] != key[i+p] {
				periodic = false
				break
			}
		}
		if periodic {
			return true
		}
	}
	return false
}

// ValidateMasterKeyLength refuses a non-empty master key that is shorter than MinNewMasterKeyBytes bytes
// or predictable (see isPredictableKey). An empty key is not judged here (it means "no master key":
// each caller decides). Nothing derived from the key is echoed.
func ValidateMasterKeyLength(key string) error {
	if key == "" {
		return nil
	}
	if len(key) >= MinNewMasterKeyBytes {
		if isPredictableKey(key) {
			return fmt.Errorf("%w: a repeated character or pattern, or fewer than %d distinct characters, is refused; generate one with 'openssl rand -base64 48'",
				ErrMasterKeyPredictable, MinDistinctMasterKeyChars)
		}
		return nil
	}
	// Nothing derived from the key (not even its length) is echoed.
	return fmt.Errorf("%w: at least %d bytes are required (the secrets of the state are encrypted with a key derived from it); "+
		"generate one with 'openssl rand -base64 48'; for a deployment that already uses a shorter key, re-encrypt its state first with "+
		"'secagent-server state rekey' (stopped node, NEW_RSA_MASTER_KEY_FILE), then start every node with the new key",
		ErrMasterKeyTooShort, MinNewMasterKeyBytes)
}
