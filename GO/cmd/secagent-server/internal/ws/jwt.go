package ws

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSecretsFunc is a function that returns (currentSecret, previousSecret, rotationDeadline).
// Set at startup by main.go via SetJWTSecretsFunc.
// previousSecret is empty string if no rotation is in progress.
// deadline is zero value if no rotation is in progress.
var JWTSecretsFunc func() (current, previous string, deadline time.Time)

// SetJWTSecretsFunc injects the function used to retrieve JWT secrets for validation.
// Must be called once at startup before serving WebSocket connections.
func SetJWTSecretsFunc(fn func() (current, previous string, deadline time.Time)) {
	JWTSecretsFunc = fn
}

// jwtValidationResult is the outcome of dual-key JWT validation.
type jwtValidationResult struct {
	Claims      jwt.MapClaims
	UsedPrevious bool // true if validated with the previous secret
}

// validateJWTDualKey implements the dual-key validation algorithm (ARCHITECTURE.md §22):
//
//  1. Try jwt_secret_current → if valid: accept
//  2. If invalid AND now < key_rotation_deadline:
//     a. Try jwt_secret_previous → if valid: accept (flag UsedPrevious=true)
//  3. Otherwise: reject
//
// Returns (result, nil) on success or ("", error) on rejection.
func validateJWTDualKey(tokenStr string) (*jwtValidationResult, error) {
	if JWTSecretsFunc == nil {
		return nil, fmt.Errorf("jwt_secrets_not_configured")
	}

	current, previous, deadline := JWTSecretsFunc()
	if current == "" {
		return nil, fmt.Errorf("jwt_secret_not_configured")
	}

	// Attempt 1: validate with current secret
	claims, err := parseJWT(tokenStr, current)
	if err == nil {
		return &jwtValidationResult{Claims: claims, UsedPrevious: false}, nil
	}

	// Attempt 2: fall back to previous secret during grace period
	if previous != "" && !deadline.IsZero() && time.Now().Before(deadline) {
		claims, err2 := parseJWT(tokenStr, previous)
		if err2 == nil {
			log.Printf("JWT validated with previous secret (rotation in progress, deadline=%s)", deadline.Format(time.RFC3339))
			return &jwtValidationResult{Claims: claims, UsedPrevious: true}, nil
		}
	}

	return nil, fmt.Errorf("invalid_token: %w", err)
}

// parseJWT parses and validates a JWT string against a given HMAC secret.
// Returns claims on success, error on failure.
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

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

// ExtractJWTClaims extracts claims from a Bearer token in the Authorization header
// using dual-key validation. Returns (claims, usedPrevious, error).
func ExtractJWTClaims(authHeader string) (jwt.MapClaims, bool, error) {
	if !hasPrefix(authHeader, "Bearer ") || len(authHeader) <= 7 {
		return nil, false, fmt.Errorf("missing_bearer_token")
	}
	tokenStr := authHeader[7:]

	result, err := validateJWTDualKey(tokenStr)
	if err != nil {
		return nil, false, err
	}
	return result.Claims, result.UsedPrevious, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
