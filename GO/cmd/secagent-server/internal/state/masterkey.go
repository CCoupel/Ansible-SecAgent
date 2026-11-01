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

// ValidateMasterKeyLength refuses a non-empty master key shorter than MinNewMasterKeyBytes bytes. An
// empty key is not judged here (it means "no master key": each caller decides).
func ValidateMasterKeyLength(key string) error {
	if key == "" || len(key) >= MinNewMasterKeyBytes {
		return nil
	}
	// Nothing derived from the key (not even its length) is echoed.
	return fmt.Errorf("%w: at least %d bytes are required (the secrets of the state are encrypted with a key derived from it); "+
		"generate one with 'openssl rand -base64 48'; for a deployment that already uses a shorter key, re-encrypt its state first with "+
		"'secagent-server state rekey' (stopped node, NEW_RSA_MASTER_KEY_FILE), then start every node with the new key",
		ErrMasterKeyTooShort, MinNewMasterKeyBytes)
}
