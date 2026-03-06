package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"testing"
	"time"

	"relay-server/cmd/server/internal/storage"
)

// TestMain sets required env vars and bootstraps server state for all handler tests.
// Usage: JWT_SECRET_KEY=test ADMIN_TOKEN=test go test ./...
func TestMain(m *testing.M) {
	if os.Getenv("JWT_SECRET_KEY") == "" {
		os.Setenv("JWT_SECRET_KEY", "test-secret-key-for-unit-tests")
	}
	if os.Getenv("ADMIN_TOKEN") == "" {
		os.Setenv("ADMIN_TOKEN", "test-admin-token")
	}

	// init() already ran and set JWTSecret + AdminToken.
	// Generate an in-memory RSA keypair for tests that call RegisterAgent / TokenRefresh
	// (normally done by InitServerState+DB at server startup).
	if server != nil && server.PrivateKey == nil {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048-bit sufficient for tests
		if err != nil {
			log.Fatalf("TestMain: generate RSA test key: %v", err)
		}
		_, pubPEM, err := encodeRSAKeyPair(privKey)
		if err != nil {
			log.Fatalf("TestMain: encode RSA test key: %v", err)
		}

		server.mu.Lock()
		server.PrivateKey = privKey
		server.PublicPEM = pubPEM
		server.JWTttl = time.Hour
		server.mu.Unlock()

		log.Println("[TEST] RSA-2048 keypair generated for unit tests")
	}

	// Initialize an in-memory SQLite store for register/token handler tests.
	testStore, err := storage.NewStore(":memory:")
	if err != nil {
		log.Fatalf("TestMain: create test store: %v", err)
	}
	SetAdminStore(testStore)
	SetRegisterStore(testStore)

	// Pre-authorize test agents so register tests can succeed.
	ctx := context.Background()
	testAuthorizedAgents := []struct{ hostname, pubkey string }{
		{"test-agent-01", ""}, // placeholder — pubkey is set per test
		{"test-agent-02", ""}, // used by TestAdminAuthorizeSuccess
		{"test-agent-05", ""}, // used by TestTokenRefreshSuccess
	}
	_ = testAuthorizedAgents
	// Individual tests call AddAuthorizedKey directly (pubkey varies).

	_ = ctx

	os.Exit(m.Run())
}
