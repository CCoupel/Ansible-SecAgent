package handlers

import (
	"context"
	"testing"
	"time"

	"relay-server/cmd/server/internal/storage"
)

// initStore creates a fresh in-memory store for server_config tests.
func initStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatalf("initStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ========================================================================
// InitServerState — RSA keypair + JWT persistence
// ========================================================================

func TestInitServerState_GeneratesKeysOnFirstBoot(t *testing.T) {
	s := initStore(t)
	ctx := context.Background()

	// Verify DB has no RSA key yet
	val, _ := s.ConfigGet(ctx, "rsa_key_current")
	if val != "" {
		t.Fatal("expected rsa_key_current absent before init")
	}

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	// RSA key should be persisted
	rsaKey, err := s.ConfigGet(ctx, "rsa_key_current")
	if err != nil || rsaKey == "" {
		t.Errorf("expected rsa_key_current in DB after init, got %q err=%v", rsaKey, err)
	}

	// JWT secret should be persisted
	jwtKey, err := s.ConfigGet(ctx, "jwt_secret_current")
	if err != nil || jwtKey == "" {
		t.Errorf("expected jwt_secret_current in DB after init, got %q err=%v", jwtKey, err)
	}

	// server.PrivateKey must be set
	if server.PrivateKey == nil {
		t.Error("expected server.PrivateKey to be non-nil after InitServerState")
	}
	if server.PublicPEM == "" {
		t.Error("expected server.PublicPEM to be non-empty after InitServerState")
	}
}

func TestInitServerState_LoadsExistingKeysOnReboot(t *testing.T) {
	s := initStore(t)
	ctx := context.Background()

	// First boot: generates and persists
	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("first InitServerState: %v", err)
	}

	pubPEM1 := server.PublicPEM
	rsaStored, _ := s.ConfigGet(ctx, "rsa_key_current")

	// Simulate reboot: clear in-memory state
	server.mu.Lock()
	server.PrivateKey = nil
	server.PublicPEM = ""
	server.mu.Unlock()

	// Second boot: should load from DB, not regenerate
	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("second InitServerState: %v", err)
	}

	if server.PublicPEM != pubPEM1 {
		t.Error("public PEM changed on reboot — RSA key was regenerated instead of loaded")
	}

	// DB entry should be unchanged
	rsaStored2, _ := s.ConfigGet(ctx, "rsa_key_current")
	if rsaStored != rsaStored2 {
		t.Error("rsa_key_current changed in DB on second boot")
	}
}

func TestInitServerState_LoadsPreviousJWTSecret(t *testing.T) {
	s := initStore(t)
	ctx := context.Background()

	// Pre-seed a previous JWT secret and deadline
	_ = s.ConfigSet(ctx, "jwt_secret_current", "secret-current")
	_ = s.ConfigSet(ctx, "jwt_secret_previous", "secret-previous")
	deadline := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	_ = s.ConfigSet(ctx, "key_rotation_deadline", deadline)

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	cur, prev, dl := server.GetJWTSecrets()
	if cur != "secret-current" {
		t.Errorf("expected JWTSecret=secret-current, got %q", cur)
	}
	if prev != "secret-previous" {
		t.Errorf("expected JWTPreviousSecret=secret-previous, got %q", prev)
	}
	if dl.IsZero() {
		t.Error("expected KeyRotationDeadline to be set")
	}
}

// ========================================================================
// storage.ConfigGet / ConfigSet / ConfigDelete
// ========================================================================

func TestConfigGetSet(t *testing.T) {
	s := initStore(t)
	ctx := context.Background()

	// Get absent key → empty string
	val, err := s.ConfigGet(ctx, "absent_key")
	if err != nil || val != "" {
		t.Errorf("expected empty for absent key, got %q err=%v", val, err)
	}

	// Set and get
	if err := s.ConfigSet(ctx, "test_key", "hello"); err != nil {
		t.Fatalf("ConfigSet: %v", err)
	}
	val, err = s.ConfigGet(ctx, "test_key")
	if err != nil || val != "hello" {
		t.Errorf("expected hello, got %q err=%v", val, err)
	}

	// Update (upsert)
	if err := s.ConfigSet(ctx, "test_key", "world"); err != nil {
		t.Fatalf("ConfigSet update: %v", err)
	}
	val, _ = s.ConfigGet(ctx, "test_key")
	if val != "world" {
		t.Errorf("expected world after update, got %q", val)
	}
}

func TestConfigDelete(t *testing.T) {
	s := initStore(t)
	ctx := context.Background()

	_ = s.ConfigSet(ctx, "to_delete", "value")
	if err := s.ConfigDelete(ctx, "to_delete"); err != nil {
		t.Fatalf("ConfigDelete: %v", err)
	}

	val, _ := s.ConfigGet(ctx, "to_delete")
	if val != "" {
		t.Errorf("expected empty after delete, got %q", val)
	}

	// Delete absent key should not error
	if err := s.ConfigDelete(ctx, "nonexistent"); err != nil {
		t.Errorf("ConfigDelete of absent key should not error, got %v", err)
	}
}

// ========================================================================
// Dual-key JWT validation (ws/jwt.go)
// ========================================================================

func TestGetServerJWTSecrets_SingleKey(t *testing.T) {
	server.mu.Lock()
	server.JWTSecret = "only-current"
	server.JWTPreviousSecret = ""
	server.KeyRotationDeadline = time.Time{}
	server.mu.Unlock()

	cur, prev, dl := GetServerJWTSecrets()
	if cur != "only-current" {
		t.Errorf("expected only-current, got %q", cur)
	}
	if prev != "" {
		t.Errorf("expected empty previous, got %q", prev)
	}
	if !dl.IsZero() {
		t.Error("expected zero deadline")
	}
}

func TestGetServerJWTSecrets_DualKey(t *testing.T) {
	deadline := time.Now().Add(12 * time.Hour)
	server.mu.Lock()
	server.JWTSecret = "current-secret"
	server.JWTPreviousSecret = "previous-secret"
	server.KeyRotationDeadline = deadline
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.JWTPreviousSecret = ""
		server.KeyRotationDeadline = time.Time{}
		server.mu.Unlock()
	}()

	cur, prev, dl := GetServerJWTSecrets()
	if cur != "current-secret" {
		t.Errorf("expected current-secret, got %q", cur)
	}
	if prev != "previous-secret" {
		t.Errorf("expected previous-secret, got %q", prev)
	}
	if dl.IsZero() {
		t.Error("expected non-zero deadline")
	}
}
