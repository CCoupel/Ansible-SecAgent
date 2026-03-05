package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RegisterRequest represents agent enrollment request
type RegisterRequest struct {
	Hostname     string `json:"hostname"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// RegisterResponse returns encrypted JWT and server public key
type RegisterResponse struct {
	TokenEncrypted     string `json:"token_encrypted"`
	ServerPublicKeyPEM string `json:"server_public_key_pem"`
}

// AdminAuthorizeRequest pre-authorizes a public key
type AdminAuthorizeRequest struct {
	Hostname     string `json:"hostname"`
	PublicKeyPEM string `json:"public_key_pem"`
	ApprovedBy   string `json:"approved_by"`
}

// TokenRefreshRequest refreshes an agent JWT
type TokenRefreshRequest struct {
	Hostname           string `json:"hostname"`
	ChallengeEncrypted string `json:"challenge_encrypted"`
}

// ServerState holds global server state
type ServerState struct {
	PrivateKey *rsa.PrivateKey
	PublicPEM  string
	JWTSecret  string
	AdminToken string
	JWTttl     time.Duration
}

var server *ServerState

func init() {
	secret := os.Getenv("JWT_SECRET_KEY")
	adminToken := os.Getenv("ADMIN_TOKEN")

	if secret == "" {
		log.Fatal("JWT_SECRET_KEY environment variable not set")
	}
	if adminToken == "" {
		log.Fatal("ADMIN_TOKEN environment variable not set")
	}

	// Generate 4096-bit RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Export public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	publicPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	server = &ServerState{
		PrivateKey: privateKey,
		PublicPEM:  publicPEM,
		JWTSecret:  secret,
		AdminToken: adminToken,
		JWTttl:     time.Hour,
	}

	log.Println("[OK] Server RSA key pair generated")
}

// RegisterAgent enrolls a relay-agent
// POST /api/register
func RegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	// Validate input
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)

	if req.Hostname == "" || req.PublicKeyPEM == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"missing_fields"}`)
		return
	}

	// Step 1: Check if hostname is in authorized_keys
	// TODO: Query database for authorized key record
	authorizedPEM := req.PublicKeyPEM // Placeholder: accept all for now

	// Step 2: Verify submitted key matches authorized key
	if req.PublicKeyPEM != authorizedPEM {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"public_key_mismatch"}`)
		return
	}

	// Step 3: Check for existing agent with different key (409 Conflict)
	// TODO: Query database for existing agent record
	// For now, always allow

	// Step 4: Issue JWT
	jti := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  req.Hostname,
		"role": "agent",
		"jti":  jti,
		"iat":  now.Unix(),
		"exp":  now.Add(server.JWTttl).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err := token.SignedString([]byte(server.JWTSecret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"jwt_generation_failed"}`)
		return
	}

	// Step 5: Encrypt JWT with agent's public key (RSA-OAEP)
	tokenEncrypted, err := encryptWithPublicKey(rawJWT, req.PublicKeyPEM)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_public_key"}`)
		return
	}

	// Step 6: Store agent record
	// TODO: Upsert agent in database with hostname, public_key_pem, token_jti

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(RegisterResponse{
		TokenEncrypted:     tokenEncrypted,
		ServerPublicKeyPEM: server.PublicPEM,
	})
}

// AdminAuthorize pre-authorizes a public key (CI/CD pipeline)
// POST /api/admin/authorize
func AdminAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check admin authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"missing_authorization"}`)
		return
	}

	token := authHeader[7:]
	if token != server.AdminToken {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_admin_token"}`)
		return
	}

	var req AdminAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	// Validate input
	if strings.TrimSpace(req.Hostname) == "" || strings.TrimSpace(req.PublicKeyPEM) == "" || strings.TrimSpace(req.ApprovedBy) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"missing_fields"}`)
		return
	}

	// TODO: Store authorized key in database
	// INSERT OR REPLACE INTO authorized_keys (hostname, public_key_pem, approved_by, created_at)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"hostname": req.Hostname,
		"status":   "authorized",
	})
}

// TokenRefresh refreshes an agent JWT
// POST /api/token/refresh
func TokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	// Step 1: Look up agent in database
	// TODO: Query database for agent by hostname
	// agentRecord, err := db.GetAgent(req.Hostname)

	// Step 2: Decrypt challenge with server private key
	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.ChallengeEncrypted)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"challenge_decryption_failed"}`)
		return
	}

	_, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, server.PrivateKey, ciphertextBytes, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"challenge_decryption_failed"}`)
		return
	}

	// Step 3: Issue new JWT
	newJTI := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  req.Hostname,
		"role": "agent",
		"jti":  newJTI,
		"iat":  now.Unix(),
		"exp":  now.Add(server.JWTttl).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err := token.SignedString([]byte(server.JWTSecret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"jwt_generation_failed"}`)
		return
	}

	// TODO: Get agent public key from database
	// agentPublicKey := agentRecord.PublicKeyPEM

	// For now, use placeholder
	agentPublicKey := ""

	// Encrypt with agent public key
	tokenEncrypted, err := encryptWithPublicKey(rawJWT, agentPublicKey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"encryption_failed"}`)
		return
	}

	// TODO: Blacklist old JTI
	// TODO: Update agent token_jti in database

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token_encrypted":      tokenEncrypted,
		"server_public_key_pem": server.PublicPEM,
	})
}

// Helper functions

func encryptWithPublicKey(plaintext string, publicKeyPEM string) (string, error) {
	// Parse PEM-encoded public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("not an RSA public key")
	}

	// Encrypt with RSA-OAEP
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		[]byte(plaintext),
		nil,
	)
	if err != nil {
		return "", err
	}

	// Return base64-encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
