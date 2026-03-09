package ws

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// makeTestJWT creates a signed JWT token for testing.
func makeTestJWT(secret, sub string, exp time.Time) string {
	claims := jwt.MapClaims{
		"sub":  sub,
		"role": "agent",
		"jti":  "test-jti",
		"exp":  exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString([]byte(secret))
	return signed
}

// ========================================================================
// parseJWT
// ========================================================================

func TestParseJWT_Valid(t *testing.T) {
	secret := "my-test-secret"
	tokenStr := makeTestJWT(secret, "host-a", time.Now().Add(time.Hour))

	claims, err := parseJWT(tokenStr, secret)
	if err != nil {
		t.Fatalf("parseJWT: unexpected error: %v", err)
	}
	if claims["sub"] != "host-a" {
		t.Errorf("expected sub=host-a, got %v", claims["sub"])
	}
}

func TestParseJWT_WrongSecret(t *testing.T) {
	tokenStr := makeTestJWT("correct-secret", "host-a", time.Now().Add(time.Hour))

	_, err := parseJWT(tokenStr, "wrong-secret")
	if err == nil {
		t.Error("expected error for wrong secret, got nil")
	}
}

func TestParseJWT_Expired(t *testing.T) {
	secret := "my-test-secret"
	tokenStr := makeTestJWT(secret, "host-a", time.Now().Add(-time.Hour)) // expired

	_, err := parseJWT(tokenStr, secret)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

// ========================================================================
// validateJWTDualKey
// ========================================================================

func setTestSecretsFunc(current, previous string, deadline time.Time) {
	JWTSecretsFunc = func() (string, string, time.Time) {
		return current, previous, deadline
	}
}

func TestValidateDualKey_CurrentSecretOK(t *testing.T) {
	setTestSecretsFunc("current-secret", "", time.Time{})
	defer func() { JWTSecretsFunc = nil }()

	tokenStr := makeTestJWT("current-secret", "host-a", time.Now().Add(time.Hour))

	result, err := validateJWTDualKey(tokenStr)
	if err != nil {
		t.Fatalf("expected valid, got error: %v", err)
	}
	if result.UsedPrevious {
		t.Error("expected UsedPrevious=false for current secret")
	}
	if result.Claims["sub"] != "host-a" {
		t.Errorf("expected sub=host-a, got %v", result.Claims["sub"])
	}
}

func TestValidateDualKey_FallbackToPreviousWithinDeadline(t *testing.T) {
	deadline := time.Now().Add(24 * time.Hour) // deadline in the future
	setTestSecretsFunc("current-secret", "previous-secret", deadline)
	defer func() { JWTSecretsFunc = nil }()

	// Token signed with PREVIOUS secret
	tokenStr := makeTestJWT("previous-secret", "host-b", time.Now().Add(time.Hour))

	result, err := validateJWTDualKey(tokenStr)
	if err != nil {
		t.Fatalf("expected valid with previous secret, got error: %v", err)
	}
	if !result.UsedPrevious {
		t.Error("expected UsedPrevious=true when validated with previous secret")
	}
	if result.Claims["sub"] != "host-b" {
		t.Errorf("expected sub=host-b, got %v", result.Claims["sub"])
	}
}

func TestValidateDualKey_PreviousSecretRejectedAfterDeadline(t *testing.T) {
	deadline := time.Now().Add(-time.Hour) // deadline already passed
	setTestSecretsFunc("current-secret", "previous-secret", deadline)
	defer func() { JWTSecretsFunc = nil }()

	// Token signed with PREVIOUS secret, but deadline has passed
	tokenStr := makeTestJWT("previous-secret", "host-c", time.Now().Add(time.Hour))

	_, err := validateJWTDualKey(tokenStr)
	if err == nil {
		t.Error("expected rejection after deadline, but got nil error")
	}
}

func TestValidateDualKey_NoPreviousSecret(t *testing.T) {
	// No previous secret, single-key mode
	setTestSecretsFunc("current-secret", "", time.Time{})
	defer func() { JWTSecretsFunc = nil }()

	// Token signed with wrong secret
	tokenStr := makeTestJWT("wrong-secret", "host-d", time.Now().Add(time.Hour))

	_, err := validateJWTDualKey(tokenStr)
	if err == nil {
		t.Error("expected rejection for wrong token in single-key mode, but got nil error")
	}
}

func TestValidateDualKey_NoSecretsFunc(t *testing.T) {
	JWTSecretsFunc = nil

	tokenStr := makeTestJWT("any-secret", "host-e", time.Now().Add(time.Hour))
	_, err := validateJWTDualKey(tokenStr)
	if err == nil {
		t.Error("expected error when JWTSecretsFunc is nil, got nil")
	}
}

func TestValidateDualKey_BothSecretsWrong(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	setTestSecretsFunc("current-secret", "previous-secret", deadline)
	defer func() { JWTSecretsFunc = nil }()

	tokenStr := makeTestJWT("completely-wrong", "host-f", time.Now().Add(time.Hour))

	_, err := validateJWTDualKey(tokenStr)
	if err == nil {
		t.Error("expected error when both secrets are wrong, got nil")
	}
}

// ========================================================================
// ExtractJWTClaims
// ========================================================================

func TestExtractJWTClaims_ValidBearer(t *testing.T) {
	setTestSecretsFunc("secret", "", time.Time{})
	defer func() { JWTSecretsFunc = nil }()

	tokenStr := makeTestJWT("secret", "host-a", time.Now().Add(time.Hour))
	authHeader := "Bearer " + tokenStr

	claims, prev, err := ExtractJWTClaims(authHeader)
	if err != nil {
		t.Fatalf("ExtractJWTClaims: %v", err)
	}
	if claims["sub"] != "host-a" {
		t.Errorf("expected sub=host-a, got %v", claims["sub"])
	}
	if prev {
		t.Error("expected usedPrevious=false")
	}
}

func TestExtractJWTClaims_MissingBearer(t *testing.T) {
	setTestSecretsFunc("secret", "", time.Time{})
	defer func() { JWTSecretsFunc = nil }()

	_, _, err := ExtractJWTClaims("not-a-bearer-token")
	if err == nil {
		t.Error("expected error for missing Bearer prefix")
	}
}

func TestExtractJWTClaims_InvalidToken(t *testing.T) {
	setTestSecretsFunc("secret", "", time.Time{})
	defer func() { JWTSecretsFunc = nil }()

	_, _, err := ExtractJWTClaims("Bearer invalid.token.here")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}
