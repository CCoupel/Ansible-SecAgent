// Package ws — pont vers le package enrollment.
// Implémentations par défaut des fonctions d'enrollment utilisées par le dispatcher.
// Séparé pour faciliter le mocking dans les tests.
package ws

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// defaultDecryptAndSaveToken déchiffre token_encrypted (base64 RSA-OAEP SHA-256)
// et persiste le JWT résultant sur disque (jwtPath, mode 0600).
func defaultDecryptAndSaveToken(tokenEncryptedB64 string, privKey *rsa.PrivateKey, jwtPath string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(tokenEncryptedB64)
	if err != nil {
		return "", fmt.Errorf("rekey: decode base64: %w", err)
	}

	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("rekey: RSA-OAEP decrypt: %w", err)
	}
	jwt := string(jwtBytes)

	if jwtPath != "" {
		if err := writeSecret(jwtPath, jwtBytes); err != nil {
			return "", fmt.Errorf("rekey: persist JWT: %w", err)
		}
	}

	return jwt, nil
}

// defaultReEnrollOnce effectue POST /api/register avec la clef publique de l'agent
// et retourne le JWT déchiffré.
// Retourne httpStatusError si le serveur rejette (401, 403...).
func defaultReEnrollOnce(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	body, err := json.Marshal(map[string]string{
		"hostname":       ec.Hostname,
		"public_key_pem": pubPEM,
	})
	if err != nil {
		return "", fmt.Errorf("reenroll: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ec.RegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("reenroll: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("reenroll: POST %s: %w", ec.RegisterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", &httpStatusError{code: http.StatusForbidden, msg: "enrollment refused"}
	}
	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("reenroll: server returned HTTP %d: %v", resp.StatusCode, errBody)
	}

	var result struct {
		TokenEncrypted string `json:"token_encrypted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("reenroll: decode response: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(result.TokenEncrypted)
	if err != nil {
		return "", fmt.Errorf("reenroll: decode base64 token: %w", err)
	}

	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ec.PrivateKey, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("reenroll: RSA-OAEP decrypt: %w", err)
	}
	jwt := string(jwtBytes)

	if ec.JWTPath != "" {
		if err := writeSecret(ec.JWTPath, jwtBytes); err != nil {
			return "", fmt.Errorf("reenroll: persist JWT: %w", err)
		}
	}

	return jwt, nil
}

// defaultPublicKeyPEMFromPrivate sérialise la clef publique RSA en PEM PKIX.
func defaultPublicKeyPEMFromPrivate(privKey *rsa.PrivateKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	return string(pem.EncodeToMemory(block)), nil
}

// writeSecret écrit content dans path avec mode 0600 de façon atomique.
func writeSecret(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(content)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
