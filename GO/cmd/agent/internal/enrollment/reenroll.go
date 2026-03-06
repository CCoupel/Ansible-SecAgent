// Package enrollment — ré-enrôlement après expiration/révocation JWT.
//
// ReEnroll est utilisé par le dispatcher WS dans deux cas (§22 ARCHITECTURE.md) :
//   - Handler rekey : le serveur envoie un nouveau token_encrypted via WS
//   - Reconnexion sur 401 : le JWT existant est rejeté, ré-enrôlement complet requis
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// DecryptAndSaveToken déchiffre un token_encrypted (base64 RSA-OAEP) et persiste
// le JWT résultant sur disque (JWTPath, mode 0600).
//
// Utilisé par le handler WS "rekey" pour mettre à jour le JWT local
// sans interrompre la connexion WebSocket.
//
// Retourne le JWT en clair.
func DecryptAndSaveToken(tokenEncryptedB64 string, privKey *rsa.PrivateKey, jwtPath string) (string, error) {
	if privKey == nil {
		return "", fmt.Errorf("enrollment: private key required for token decryption")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(tokenEncryptedB64)
	if err != nil {
		return "", fmt.Errorf("enrollment: decode base64 token_encrypted: %w", err)
	}

	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("enrollment: RSA-OAEP decrypt token_encrypted: %w", err)
	}
	jwt := string(jwtBytes)

	if jwtPath != "" {
		if err := writeSecret(jwtPath, jwtBytes); err != nil {
			return "", fmt.Errorf("enrollment: persist rotated JWT: %w", err)
		}
	}

	return jwt, nil
}

// ReEnroll effectue un enrollment complet (POST /api/register) en réutilisant
// la clef privée RSA existante, puis persiste le nouveau JWT.
//
// Utilisé lors d'un 401 sur la connexion WS : le JWT est invalide mais la clef
// publique de l'agent est toujours autorisée côté serveur.
//
// Retourne le nouveau JWT ou une erreur si le serveur rejette (403 → clef non autorisée).
func ReEnroll(ctx context.Context, cfg Config) (string, error) {
	pubPEM, err := PublicKeyPEM(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("reenroll: compute public key PEM: %w", err)
	}
	cfg.PublicKeyPEM = pubPEM
	return Enroll(ctx, cfg)
}
