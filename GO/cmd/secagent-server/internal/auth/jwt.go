// Package auth provides JWT signing and verification for the relay server.
// It implements dual-key validation (ARCHITECTURE.md §22): tokens signed with
// the previous secret remain valid until the rotation deadline expires.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SecretsProvider supplies the current and previous JWT secrets plus the
// rotation deadline. Implemented by handlers.ServerState via GetJWTSecrets().
type SecretsProvider func() (current, previous string, deadline time.Time)

// JWTService signs and verifies agent JWTs using dual-key logic.
type JWTService struct {
	secrets SecretsProvider
	ttl     time.Duration
}

// New creates a JWTService backed by the given secrets provider.
// ttl is the lifetime of tokens produced by Sign (default 1h if zero).
func New(secrets SecretsProvider, ttl time.Duration) *JWTService {
	if ttl == 0 {
		ttl = time.Hour
	}
	return &JWTService{secrets: secrets, ttl: ttl}
}

// Sign creates a signed HS256 JWT for hostname with role "agent".
// Returns (rawJWT, jti, error).
func (s *JWTService) Sign(hostname string) (rawJWT, jti string, err error) {
	return s.signWithRole(hostname, "agent", s.ttl)
}

// SignRelay creates a signed HS256 JWT for a relay node with role "relay".
// The relay_id is stored in the "sub" claim.
// Uses a 30-day TTL so relay tokens remain valid across short outages.
// Returns (rawJWT, jti, error).
func (s *JWTService) SignRelay(relayID string) (rawJWT, jti string, err error) {
	return s.signWithRole(relayID, "relay", 720*time.Hour) // 30 days
}

// SignRelayParent creates a signed HS256 JWT with role "relay-parent": the token a child relay
// issues (signed with ITS secret) so that its parent can open a push-mode link to it (#140).
// The parent's relay_id is stored in "sub". Returns (rawJWT, jti, error).
func (s *JWTService) SignRelayParent(parentID string) (rawJWT, jti string, err error) {
	return s.SignRelayParentTTL(parentID, 720*time.Hour) // 30 days
}

// SignRelayParentTTL is SignRelayParent with an explicit lifetime. A relay-parent token ALWAYS
// expires: a non-positive ttl is refused.
func (s *JWTService) SignRelayParentTTL(parentID string, ttl time.Duration) (rawJWT, jti string, err error) {
	if ttl <= 0 {
		return "", "", fmt.Errorf("relay_parent_token_requires_expiry")
	}
	return s.signWithRole(parentID, "relay-parent", ttl)
}

// signWithRole is the shared implementation for Sign and SignRelay.
// Returns (rawJWT, jti, error).
func (s *JWTService) signWithRole(sub, role string, ttl time.Duration) (rawJWT, jti string, err error) {
	current, _, _ := s.secrets()
	if current == "" {
		return "", "", fmt.Errorf("jwt_secret_not_configured")
	}

	jti = uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"jti":  jti,
		"iat":  now.Unix(),
		"exp":  now.Add(ttl).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err = token.SignedString([]byte(current))
	if err != nil {
		return "", "", fmt.Errorf("SignedString: %w", err)
	}
	return rawJWT, jti, nil
}

// Verify validates tokenStr using dual-key logic:
//  1. Try current secret → accept if valid.
//  2. If invalid AND now < deadline → try previous secret → accept with usedPrevious=true.
//  3. Otherwise reject.
//
// Returns (claims, usedPrevious, error).
func (s *JWTService) Verify(tokenStr string) (claims jwt.MapClaims, usedPrevious bool, err error) {
	current, previous, deadline := s.secrets()
	if current == "" {
		return nil, false, fmt.Errorf("jwt_secret_not_configured")
	}

	// Attempt 1: current secret
	c, err := parseJWT(tokenStr, current)
	if err == nil {
		return c, false, nil
	}

	// Attempt 2: previous secret during grace period
	if previous != "" && !deadline.IsZero() && time.Now().Before(deadline) {
		c2, err2 := parseJWT(tokenStr, previous)
		if err2 == nil {
			return c2, true, nil
		}
	}

	return nil, false, fmt.Errorf("invalid_token: %w", err)
}

// ExtractSub returns the "sub" claim (hostname) from a raw JWT string,
// using dual-key validation. Convenience wrapper around Verify.
func (s *JWTService) ExtractSub(tokenStr string) (hostname string, usedPrevious bool, err error) {
	claims, prev, err := s.Verify(tokenStr)
	if err != nil {
		return "", false, err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", false, fmt.Errorf("jwt_missing_sub")
	}
	return sub, prev, nil
}

// parseJWT parses and validates a raw JWT string against secret using HS256.
func parseJWT(tokenStr, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}

	c, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}
	return c, nil
}
