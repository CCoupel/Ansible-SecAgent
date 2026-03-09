// Package enrollment — helpers pour la gestion des clefs RSA.
package enrollment

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateRSAKey génère une paire de clefs RSA-4096.
// Utilisé lors du premier démarrage si aucune clef n'existe.
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// PublicKeyPEM sérialise la clef publique RSA en PEM PKIX.
func PublicKeyPEM(key *rsa.PrivateKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// PrivateKeyPEM sérialise la clef privée RSA en PEM PKCS1.
func PrivateKeyPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

// StorePrivateKey persiste la clef privée RSA sur disque en mode 0600 atomique.
func StorePrivateKey(key *rsa.PrivateKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("store private key: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("store private key: create: %w", err)
	}
	pemData := PrivateKeyPEM(key)
	if _, err := f.WriteString(pemData); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("store private key: write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store private key: close: %w", err)
	}
	return os.Rename(tmp, path)
}
