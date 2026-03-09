package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func singleKeyProvider(secret string) SecretsProvider {
	return func() (string, string, time.Time) {
		return secret, "", time.Time{}
	}
}

func dualKeyProvider(current, previous string, deadline time.Time) SecretsProvider {
	return func() (string, string, time.Time) {
		return current, previous, deadline
	}
}

func newSvc(provider SecretsProvider) *JWTService {
	return New(provider, time.Hour)
}

// signWithSecret signs a JWT directly without going through JWTService (for crafting
// tokens signed with a specific secret in tests).
func signWithSecret(hostname, secret string, ttl time.Duration) string {
	claims := jwt.MapClaims{
		"sub":  hostname,
		"role": "agent",
		"jti":  "test-jti",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, _ := token.SignedString([]byte(secret))
	return raw
}

// ── Sign ─────────────────────────────────────────────────────────────────────

func TestSign_ProducesValidJWT(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	raw, jti, err := svc.Sign("host-1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if raw == "" {
		t.Error("expected non-empty JWT")
	}
	if jti == "" {
		t.Error("expected non-empty JTI")
	}
	// JWT has 3 parts
	if parts := strings.Split(raw, "."); len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}
}

func TestSign_JTIsAreUnique(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	_, jti1, _ := svc.Sign("host-1")
	_, jti2, _ := svc.Sign("host-1")
	if jti1 == jti2 {
		t.Error("consecutive Sign calls should produce unique JTIs")
	}
}

func TestSign_EmptySecret_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider(""))
	_, _, err := svc.Sign("host-1")
	if err == nil {
		t.Error("expected error when secret is empty")
	}
}

func TestSign_SubClaimMatchesHostname(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	raw, _, err := svc.Sign("my-host")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, usedPrev, err := svc.Verify(raw)
	if err != nil {
		t.Fatalf("Verify after Sign: %v", err)
	}
	if usedPrev {
		t.Error("expected usedPrevious=false for token signed with current secret")
	}
	sub, _ := claims["sub"].(string)
	if sub != "my-host" {
		t.Errorf("expected sub=my-host, got %q", sub)
	}
}

// ── Verify — single key ───────────────────────────────────────────────────────

func TestVerify_ValidToken_CurrentKey(t *testing.T) {
	svc := newSvc(singleKeyProvider("my-secret"))
	raw := signWithSecret("host-1", "my-secret", time.Hour)

	claims, usedPrev, err := svc.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if usedPrev {
		t.Error("expected usedPrevious=false")
	}
	sub, _ := claims["sub"].(string)
	if sub != "host-1" {
		t.Errorf("expected sub=host-1, got %q", sub)
	}
}

func TestVerify_InvalidToken_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	_, _, err := svc.Verify("not.a.jwt")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestVerify_WrongSecret_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider("correct-secret"))
	raw := signWithSecret("host-1", "wrong-secret", time.Hour)

	_, _, err := svc.Verify(raw)
	if err == nil {
		t.Error("expected error for token signed with wrong secret")
	}
}

func TestVerify_ExpiredToken_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	// Sign a token that expired 1 second ago
	raw := signWithSecret("host-1", "secret", -1*time.Second)

	_, _, err := svc.Verify(raw)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerify_EmptySecret_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider(""))
	_, _, err := svc.Verify("any.token.value")
	if err == nil {
		t.Error("expected error when secret is empty")
	}
}

// ── Verify — dual key ────────────────────────────────────────────────────────

func TestVerify_PreviousKey_WithinGrace_Accepted(t *testing.T) {
	deadline := time.Now().Add(24 * time.Hour)
	svc := newSvc(dualKeyProvider("current-secret", "previous-secret", deadline))

	// Token signed with previous secret
	raw := signWithSecret("host-1", "previous-secret", time.Hour)

	claims, usedPrev, err := svc.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !usedPrev {
		t.Error("expected usedPrevious=true for token signed with previous secret")
	}
	sub, _ := claims["sub"].(string)
	if sub != "host-1" {
		t.Errorf("expected sub=host-1, got %q", sub)
	}
}

func TestVerify_PreviousKey_DeadlinePassed_Rejected(t *testing.T) {
	// Deadline in the past
	deadline := time.Now().Add(-1 * time.Second)
	svc := newSvc(dualKeyProvider("current-secret", "previous-secret", deadline))

	raw := signWithSecret("host-1", "previous-secret", time.Hour)

	_, _, err := svc.Verify(raw)
	if err == nil {
		t.Error("expected error: previous key accepted after deadline expired")
	}
}

func TestVerify_PreviousKey_NoPreviousConfigured_Rejected(t *testing.T) {
	// No previous secret set (zero deadline)
	svc := newSvc(singleKeyProvider("current-secret"))

	// Token signed with some other secret
	raw := signWithSecret("host-1", "other-secret", time.Hour)

	_, _, err := svc.Verify(raw)
	if err == nil {
		t.Error("expected error when no previous key configured")
	}
}

func TestVerify_CurrentKeyTakesPrecedence(t *testing.T) {
	// Token signed with CURRENT secret — should not return usedPrevious even if previous exists
	deadline := time.Now().Add(24 * time.Hour)
	svc := newSvc(dualKeyProvider("current-secret", "previous-secret", deadline))

	raw := signWithSecret("host-1", "current-secret", time.Hour)

	_, usedPrev, err := svc.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if usedPrev {
		t.Error("expected usedPrevious=false when token validates against current key")
	}
}

// ── ExtractSub ───────────────────────────────────────────────────────────────

func TestExtractSub_ValidToken(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	raw := signWithSecret("my-host", "secret", time.Hour)

	hostname, usedPrev, err := svc.ExtractSub(raw)
	if err != nil {
		t.Fatalf("ExtractSub: %v", err)
	}
	if hostname != "my-host" {
		t.Errorf("expected my-host, got %q", hostname)
	}
	if usedPrev {
		t.Error("expected usedPrevious=false")
	}
}

func TestExtractSub_InvalidToken_ReturnsError(t *testing.T) {
	svc := newSvc(singleKeyProvider("secret"))
	_, _, err := svc.ExtractSub("garbage")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestExtractSub_WithPreviousKey(t *testing.T) {
	deadline := time.Now().Add(12 * time.Hour)
	svc := newSvc(dualKeyProvider("new-secret", "old-secret", deadline))

	raw := signWithSecret("host-prev", "old-secret", time.Hour)
	hostname, usedPrev, err := svc.ExtractSub(raw)
	if err != nil {
		t.Fatalf("ExtractSub with previous key: %v", err)
	}
	if hostname != "host-prev" {
		t.Errorf("expected host-prev, got %q", hostname)
	}
	if !usedPrev {
		t.Error("expected usedPrevious=true")
	}
}

// ── New defaults ─────────────────────────────────────────────────────────────

func TestNew_ZeroTTL_DefaultsToOneHour(t *testing.T) {
	svc := New(singleKeyProvider("secret"), 0)
	if svc.ttl != time.Hour {
		t.Errorf("expected 1h default TTL, got %s", svc.ttl)
	}
}

func TestNew_CustomTTL(t *testing.T) {
	svc := New(singleKeyProvider("secret"), 2*time.Hour)
	if svc.ttl != 2*time.Hour {
		t.Errorf("expected 2h TTL, got %s", svc.ttl)
	}
}
