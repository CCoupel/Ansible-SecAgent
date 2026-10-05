// Package ws — pont vers le package enrollment.
// Implémentations par défaut des fonctions d'enrollment utilisées par le dispatcher.
// Séparé pour faciliter le mocking dans les tests.
package ws

import (
	"context"
	"crypto/rsa"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
)

// defaultDecryptAndSaveToken déchiffre token_encrypted (base64 RSA-OAEP SHA-256) et persiste le
// JWT sur disque (jwtPath, mode 0600). Délègue à enrollment.DecryptAndSaveToken : un seul
// client d'enrôlement, un seul contrat JSON (noms de champs du serveur).
func defaultDecryptAndSaveToken(tokenEncryptedB64 string, privKey *rsa.PrivateKey, jwtPath string) (string, error) {
	return enrollment.DecryptAndSaveToken(tokenEncryptedB64, privKey, jwtPath)
}

// defaultReEnrollOnce effectue UN enrôlement complet (challenge-response en 2 étapes sur
// POST /api/register) avec la clef privée existante et retourne le JWT déchiffré, persisté dans
// ec.JWTPath. Délègue à enrollment.ReEnroll : il n'existe plus de seconde implémentation du
// protocole (l'ancienne copie envoyait pubkey_pem / response au lieu de public_key_pem /
// challenge_response et était rejetée en 400 missing_fields).
// L'erreur est *enrollment.HTTPError quand le serveur rejette (403 = permanent).
func defaultReEnrollOnce(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
	return enrollment.ReEnroll(ctx, enrollment.Config{
		RegisterURL:     ec.RegisterURL,
		Hostname:        ec.Hostname,
		PublicKeyPEM:    pubPEM,
		PrivateKey:      ec.PrivateKey,
		EnrollmentToken: ec.EnrollmentToken,
		CABundle:        ec.CABundle,
		JWTPath:         ec.JWTPath,
		Insecure:        ec.Insecure,
	})
}

// defaultPublicKeyPEMFromPrivate sérialise la clef publique RSA en PEM PKIX.
func defaultPublicKeyPEMFromPrivate(privKey *rsa.PrivateKey) (string, error) {
	return enrollment.PublicKeyPEM(privKey)
}
