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
	"errors"
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

// defaultReEnrollOnce effectue le challenge-response en 2 étapes via POST /api/register
// et retourne le JWT déchiffré.
// Retourne httpStatusError si le serveur rejette (401, 403...).
func defaultReEnrollOnce(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
	if ec.EnrollmentToken == "" {
		return "", fmt.Errorf("reenroll: RELAY_ENROLLMENT_TOKEN is required for re-enrollment")
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: ec.Insecure, //nolint:gosec // tests only, guarded by flag
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// --- Étape 1 : POST {hostname, pubkey_pem, enrollment_token} → {challenge, server_public_key_pem} ---
	challengeB64, serverPubKeyPEM, err := reenrollStep1(ctx, client, ec, pubPEM)
	if err != nil {
		return "", err
	}

	// Déchiffrer le challenge (nonce) avec la clef privée de l'agent
	nonce, err := decryptOAEP(challengeB64, ec.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("reenroll: decrypt challenge: %w", err)
	}

	// Parser la clef publique du serveur
	serverPubKey, err := parseServerPubKey(serverPubKeyPEM)
	if err != nil {
		return "", fmt.Errorf("reenroll: parse server public key: %w", err)
	}

	// --- Étape 2 : POST {hostname, response: OAEP(nonce+token, server_pubkey)} → {jwt_encrypted} ---
	jwtEncryptedB64, err := reenrollStep2(ctx, client, ec, nonce, serverPubKey)
	if err != nil {
		return "", err
	}

	// Déchiffrer le JWT avec la clef privée de l'agent
	jwtCiphertext, err := base64.StdEncoding.DecodeString(jwtEncryptedB64)
	if err != nil {
		return "", fmt.Errorf("reenroll: decode base64 jwt_encrypted: %w", err)
	}
	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ec.PrivateKey, jwtCiphertext, nil)
	if err != nil {
		return "", fmt.Errorf("reenroll: RSA-OAEP decrypt JWT: %w", err)
	}
	jwt := string(jwtBytes)

	if ec.JWTPath != "" {
		if err := writeSecret(ec.JWTPath, jwtBytes); err != nil {
			return "", fmt.Errorf("reenroll: persist JWT: %w", err)
		}
	}

	return jwt, nil
}

// reenrollStep1 exécute l'étape 1 : POST {hostname, pubkey_pem, enrollment_token}
func reenrollStep1(ctx context.Context, client *http.Client, ec EnrollConfig, pubPEM string) (challengeB64, serverPubKeyPEM string, err error) {
	body, err := json.Marshal(map[string]string{
		"hostname":         ec.Hostname,
		"pubkey_pem":       pubPEM,
		"enrollment_token": ec.EnrollmentToken,
	})
	if err != nil {
		return "", "", fmt.Errorf("reenroll step1: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ec.RegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("reenroll step1: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("reenroll step1: POST %s: %w", ec.RegisterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", "", &httpStatusError{code: http.StatusForbidden, msg: "enrollment token invalid/expired/used"}
	}
	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", "", fmt.Errorf("reenroll step1: HTTP %d: %v", resp.StatusCode, errBody)
	}

	var result struct {
		Challenge       string `json:"challenge"`
		ServerPublicKey string `json:"server_public_key_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("reenroll step1: decode response: %w", err)
	}
	if result.Challenge == "" {
		return "", "", errors.New("reenroll step1: server returned empty challenge")
	}
	if result.ServerPublicKey == "" {
		return "", "", errors.New("reenroll step1: server returned empty server_public_key_pem")
	}

	return result.Challenge, result.ServerPublicKey, nil
}

// reenrollStep2 exécute l'étape 2 : POST {hostname, response: OAEP(nonce+token, server_pubkey)}
func reenrollStep2(ctx context.Context, client *http.Client, ec EnrollConfig, nonce []byte, serverPubKey *rsa.PublicKey) (string, error) {
	// Construire la réponse : nonce || enrollment_token
	plaintext := append(nonce, []byte(ec.EnrollmentToken)...)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("reenroll step2: encrypt response: %w", err)
	}
	responseB64 := base64.StdEncoding.EncodeToString(ciphertext)

	body, err := json.Marshal(map[string]string{
		"hostname": ec.Hostname,
		"response": responseB64,
	})
	if err != nil {
		return "", fmt.Errorf("reenroll step2: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ec.RegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("reenroll step2: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("reenroll step2: POST %s: %w", ec.RegisterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", &httpStatusError{code: http.StatusForbidden, msg: "challenge response rejected"}
	}
	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("reenroll step2: HTTP %d: %v", resp.StatusCode, errBody)
	}

	var result struct {
		JWTEncrypted string `json:"jwt_encrypted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("reenroll step2: decode response: %w", err)
	}
	if result.JWTEncrypted == "" {
		return "", errors.New("reenroll step2: server returned empty jwt_encrypted")
	}

	return result.JWTEncrypted, nil
}

// decryptOAEP déchiffre un ciphertext RSA-OAEP SHA-256 base64 avec privKey.
func decryptOAEP(ciphertextB64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decrypt: %w", err)
	}
	return plain, nil
}

// parseServerPubKey parse une clef publique RSA au format PEM PKIX.
func parseServerPubKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found in server public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("server public key is not RSA")
	}
	return rsaPub, nil
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
