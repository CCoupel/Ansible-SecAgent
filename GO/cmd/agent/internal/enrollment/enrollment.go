// Package enrollment gère l'enregistrement de l'agent auprès du relay server.
//
// Flow Phase 10 (challenge-response) :
//  1. POST /api/register { hostname, pubkey_pem, enrollment_token }
//     → Server répond { challenge: OAEP(nonce, agent_pubkey), server_public_key_pem }
//  2. Agent déchiffre nonce avec sa clef privée
//     → POST /api/register { hostname, response: OAEP(nonce+token, server_pubkey) }
//     → Server répond { jwt_encrypted: OAEP(jwt, agent_pubkey) }
//  3. Agent déchiffre JWT avec sa clef privée → stocke à RELAY_JWT_PATH (mode 0600)
//
// Sécurité :
//   - TLS vérifié obligatoire (InsecureSkipVerify=false)
//   - Échec déchiffrement RSA → erreur fatale, pas de fallback
//   - JWT et clef privée créés avec os.OpenFile(O_CREATE, 0600) atomique
//   - Token d'enrollment JAMAIS loggé en clair (CRITIQUE sécurité)
package enrollment

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

// Config contient les paramètres nécessaires à l'enrollment.
type Config struct {
	// RegisterURL est le endpoint d'enregistrement (https://relay.example.com/api/register).
	RegisterURL string
	// Hostname identifie l'agent auprès du serveur.
	Hostname string
	// PublicKeyPEM est la clef publique RSA PEM de l'agent.
	PublicKeyPEM string
	// PrivateKey est la clef privée RSA pour déchiffrer le JWT retourné.
	PrivateKey *rsa.PrivateKey
	// EnrollmentToken est le token d'enrollment single-use (env RELAY_ENROLLMENT_TOKEN).
	// Requis pour le challenge-response Phase 10.
	// JAMAIS loggé en clair.
	EnrollmentToken string
	// CABundle est le chemin vers un CA bundle PEM custom (vide = store système).
	CABundle string
	// JWTPath est le chemin de stockage du JWT (ex: /etc/relay-agent/token.jwt).
	JWTPath string
	// Timeout de la requête HTTP (défaut : 30s).
	Timeout time.Duration
	// Insecure désactive la vérification TLS (tests uniquement).
	Insecure bool
}

// step1Request est le corps de POST /api/register (étape 1).
type step1Request struct {
	Hostname        string `json:"hostname"`
	PublicKeyPEM    string `json:"public_key_pem"`
	EnrollmentToken string `json:"enrollment_token"`
}

// step1Response est la réponse de POST /api/register (étape 1).
type step1Response struct {
	Challenge        string `json:"challenge"`          // base64(OAEP(nonce, agent_pubkey))
	ServerPublicKey  string `json:"server_public_key_pem"` // clef publique du serveur pour l'étape 2
}

// step2Request est le corps de POST /api/register (étape 2).
type step2Request struct {
	Hostname          string `json:"hostname"`
	PublicKeyPEM      string `json:"public_key_pem"`
	EnrollmentToken   string `json:"enrollment_token"`
	ChallengeResponse string `json:"challenge_response"` // base64(OAEP(nonce+token, server_pubkey))
}

// step2Response est la réponse de POST /api/register (étape 2).
type step2Response struct {
	JWTEncrypted string `json:"jwt_encrypted"` // base64(OAEP(jwt, agent_pubkey))
}

// Enroll enregistre l'agent via le protocole challenge-response en 2 étapes.
//
// L'agent effectue :
//   - Étape 1 : POST /api/register {hostname, pubkey_pem, enrollment_token}
//     → server retourne {challenge: OAEP(nonce, agent_pubkey), server_public_key_pem}
//   - Étape 2 : POST /api/register {hostname, response: OAEP(nonce+token, server_pubkey)}
//     → server retourne {jwt_encrypted: OAEP(jwt, agent_pubkey)}
//
// Le JWT est déchiffré avec la clef privée de l'agent et stocké sur disque (0600).
//
// Retourne une erreur si :
//   - La requête HTTP échoue ou retourne != 200
//   - Le déchiffrement RSA échoue (jamais de fallback token brut)
//   - L'écriture du fichier JWT échoue
func Enroll(ctx context.Context, cfg Config) (string, error) {
	if cfg.PrivateKey == nil {
		return "", errors.New("enrollment: private key is required")
	}
	if cfg.EnrollmentToken == "" {
		return "", errors.New("enrollment: RELAY_ENROLLMENT_TOKEN is required (set via env var)")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	client, err := buildHTTPClient(cfg.CABundle, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return "", fmt.Errorf("enrollment: build HTTP client: %w", err)
	}

	// --- Étape 1 : Initiation ---
	challengeB64, serverPubKeyPEM, err := enrollStep1(ctx, client, cfg)
	if err != nil {
		return "", err
	}

	// Déchiffrer le challenge (nonce) avec la clef privée de l'agent
	nonce, err := decryptChallenge(challengeB64, cfg.PrivateKey)
	if err != nil {
		return "", err
	}

	// Parser la clef publique du serveur
	serverPubKey, err := parsePublicKeyPEM(serverPubKeyPEM)
	if err != nil {
		return "", fmt.Errorf("enrollment: parse server public key: %w", err)
	}

	// --- Étape 2 : Vérification ---
	jwtEncryptedB64, err := enrollStep2(ctx, client, cfg, nonce, serverPubKey)
	if err != nil {
		return "", err
	}

	// Déchiffrer le JWT avec la clef privée de l'agent
	jwtBytes, err := decryptJWT(jwtEncryptedB64, cfg.PrivateKey)
	if err != nil {
		return "", err
	}
	jwt := string(jwtBytes)

	// Persister le JWT avec mode 0600 atomique
	if cfg.JWTPath != "" {
		if err := writeSecret(cfg.JWTPath, jwtBytes); err != nil {
			return "", fmt.Errorf("enrollment: persist JWT: %w", err)
		}
	}

	return jwt, nil
}

// enrollStep1 exécute l'étape 1 du challenge-response :
// POST /api/register {hostname, pubkey_pem, enrollment_token}
// → {challenge, server_public_key_pem}
func enrollStep1(ctx context.Context, client *http.Client, cfg Config) (challengeB64, serverPubKeyPEM string, err error) {
	body, err := json.Marshal(step1Request{
		Hostname:        cfg.Hostname,
		PublicKeyPEM:    cfg.PublicKeyPEM,
		EnrollmentToken: cfg.EnrollmentToken,
	})
	if err != nil {
		return "", "", fmt.Errorf("enrollment step1: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("enrollment step1: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("enrollment step1: POST %s: %w", cfg.RegisterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", "", fmt.Errorf("enrollment step1: server rejected (HTTP %d): %v", resp.StatusCode, errBody)
	}

	var result step1Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("enrollment step1: decode response: %w", err)
	}
	if result.Challenge == "" {
		return "", "", errors.New("enrollment step1: server returned empty challenge")
	}
	if result.ServerPublicKey == "" {
		return "", "", errors.New("enrollment step1: server returned empty server_public_key_pem")
	}

	return result.Challenge, result.ServerPublicKey, nil
}

// decryptChallenge déchiffre le challenge OAEP reçu du serveur avec la clef privée de l'agent.
// Retourne le nonce en clair.
func decryptChallenge(challengeB64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("enrollment: decode base64 challenge: %w", err)
	}

	nonce, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("enrollment: RSA-OAEP decrypt challenge (key mismatch?): %w", err)
	}

	return nonce, nil
}

// enrollStep2 exécute l'étape 2 du challenge-response :
// POST /api/register {hostname, response: OAEP(nonce+token, server_pubkey)}
// → {jwt_encrypted}
func enrollStep2(ctx context.Context, client *http.Client, cfg Config, nonce []byte, serverPubKey *rsa.PublicKey) (string, error) {
	// Construire la réponse : nonce || enrollment_token (concatenation binaire)
	plaintext := append(nonce, []byte(cfg.EnrollmentToken)...)

	// Chiffrer avec la clef publique du serveur
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, plaintext, nil)
	if err != nil {
		return "", fmt.Errorf("enrollment step2: encrypt response OAEP: %w", err)
	}
	responseB64 := base64.StdEncoding.EncodeToString(ciphertext)

	body, err := json.Marshal(step2Request{
		Hostname:          cfg.Hostname,
		PublicKeyPEM:      cfg.PublicKeyPEM,
		EnrollmentToken:   cfg.EnrollmentToken,
		ChallengeResponse: responseB64,
	})
	if err != nil {
		return "", fmt.Errorf("enrollment step2: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("enrollment step2: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("enrollment step2: POST %s: %w", cfg.RegisterURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return "", fmt.Errorf("enrollment step2: server rejected (HTTP %d): %v", resp.StatusCode, errBody)
	}

	var result step2Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("enrollment step2: decode response: %w", err)
	}
	if result.JWTEncrypted == "" {
		return "", errors.New("enrollment step2: server returned empty jwt_encrypted")
	}

	return result.JWTEncrypted, nil
}

// decryptJWT déchiffre le jwt_encrypted OAEP reçu du serveur.
// Retourne le JWT en clair.
func decryptJWT(jwtEncryptedB64 string, privKey *rsa.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(jwtEncryptedB64)
	if err != nil {
		return nil, fmt.Errorf("enrollment: decode base64 jwt_encrypted: %w", err)
	}

	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("enrollment: RSA-OAEP decrypt JWT (key mismatch?): %w", err)
	}

	return jwtBytes, nil
}

// parsePublicKeyPEM parse une clef publique RSA au format PEM PKIX.
func parsePublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("parse server pubkey: no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse server pubkey: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parse server pubkey: not an RSA public key")
	}
	return rsaPub, nil
}

// buildHTTPClient construit un client HTTP avec TLS vérifié.
func buildHTTPClient(caBundle string, insecure bool, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // tests only, guarded by flag
	}
	if !insecure && caBundle != "" {
		pool, err := loadCABundle(caBundle)
		if err != nil {
			return nil, fmt.Errorf("load CA bundle: %w", err)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// writeSecret écrit content dans path avec mode 0600 de façon atomique.
// Le fichier est créé directement avec O_CREATE et perm 0600 — pas de fenêtre
// TOCTOU entre création et chmod (§HAUT-4).
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

// loadCABundle charge un fichier PEM et retourne un pool de CAs.
func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates in %s", path)
	}
	return pool, nil
}

// LoadPrivateKeyFromFile charge une clef privée RSA PEM depuis le disque.
func LoadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key: PKCS1: %v, PKCS8: %v", err, err2)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		return rsaKey, nil
	}
	return key, nil
}
