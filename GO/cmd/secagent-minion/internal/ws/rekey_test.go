package ws

// Tests pour le handler WS "rekey" et le ré-enrôlement sur 401 (§22 ARCHITECTURE.md).
//
// Stratégie de test :
//   - Handler rekey : mock WS server envoyant {"type":"rekey","token_encrypted":"..."} →
//     vérifier JWT mis à jour, connexion maintenue
//   - 401 sur connect : mock WS server retournant 401 au handshake →
//     vérifier ré-enrôlement déclenché, nouveau JWT utilisé
//   - 403 sur /api/register après 401 → erreur permanente, pas de boucle infinie

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
)

// generateTestKey2048 génère une clef RSA 2048-bit pour les tests (plus rapide que 4096).
func generateTestKey2048(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// encryptJWT chiffre un JWT avec la clef publique RSA (RSA-OAEP SHA-256).
func encryptJWT(t *testing.T, pubKey *rsa.PublicKey, jwt string) string {
	t.Helper()
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(jwt), nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// ============================================================================
// DecryptAndSaveToken (defaultDecryptAndSaveToken)
// ============================================================================

func TestDecryptAndSaveTokenSuccess(t *testing.T) {
	key := generateTestKey2048(t)
	expectedJWT := "eyJhbGciOiJSUzI1NiJ9.test.rekey"

	tokenEncB64 := encryptJWT(t, &key.PublicKey, expectedJWT)

	jwt, err := defaultDecryptAndSaveToken(tokenEncB64, key, "")
	if err != nil {
		t.Fatalf("decryptAndSaveToken: %v", err)
	}
	if jwt != expectedJWT {
		t.Errorf("JWT: got %q, want %q", jwt, expectedJWT)
	}
}

func TestDecryptAndSaveTokenPersists(t *testing.T) {
	key := generateTestKey2048(t)
	dir := t.TempDir()
	jwtPath := dir + "/token.jwt"
	expectedJWT := "my-rotated-jwt"

	tokenEncB64 := encryptJWT(t, &key.PublicKey, expectedJWT)

	_, err := defaultDecryptAndSaveToken(tokenEncB64, key, jwtPath)
	if err != nil {
		t.Fatalf("decryptAndSaveToken: %v", err)
	}

	data, err := os.ReadFile(jwtPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != expectedJWT {
		t.Errorf("persisted JWT: got %q, want %q", data, expectedJWT)
	}
}

func TestDecryptAndSaveTokenBadBase64(t *testing.T) {
	key := generateTestKey2048(t)
	_, err := defaultDecryptAndSaveToken("!!! not base64 !!!", key, "")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "decode base64") {
		t.Errorf("error should mention 'decode base64', got: %v", err)
	}
}

func TestDecryptAndSaveTokenWrongKey(t *testing.T) {
	key1 := generateTestKey2048(t)
	key2 := generateTestKey2048(t)
	// Encrypt with key1's public key, try to decrypt with key2
	tokenEncB64 := encryptJWT(t, &key1.PublicKey, "test-jwt")
	_, err := defaultDecryptAndSaveToken(tokenEncB64, key2, "")
	if err == nil {
		t.Error("expected error for wrong private key")
	}
	if !strings.Contains(err.Error(), "RSA-OAEP decrypt") {
		t.Errorf("error should mention 'RSA-OAEP decrypt', got: %v", err)
	}
}

// ============================================================================
// httpStatusError
// ============================================================================

func TestHTTPStatusErrorString(t *testing.T) {
	err := &httpStatusError{code: 401, msg: "unauthorized"}
	if err.Error() != "http 401: unauthorized" {
		t.Errorf("Error(): got %q", err.Error())
	}
}

func TestIsHTTP401True(t *testing.T) {
	err := &httpStatusError{code: 401, msg: "unauthorized"}
	if !isHTTP401(err) {
		t.Error("isHTTP401 should return true for 401")
	}
}

func TestIsHTTP401FalseFor403(t *testing.T) {
	err := &httpStatusError{code: 403, msg: "forbidden"}
	if isHTTP401(err) {
		t.Error("isHTTP401 should return false for 403")
	}
}

func TestIsHTTP401FalseForNil(t *testing.T) {
	if isHTTP401(nil) {
		t.Error("isHTTP401 should return false for nil")
	}
}

func TestIsForbiddenErrTrue(t *testing.T) {
	err := &httpStatusError{code: 403, msg: "forbidden"}
	if !isForbiddenErr(err) {
		t.Error("isForbiddenErr should return true for 403")
	}
}

func TestIsForbiddenErrFalseFor401(t *testing.T) {
	err := &httpStatusError{code: 401, msg: "unauthorized"}
	if isForbiddenErr(err) {
		t.Error("isForbiddenErr should return false for 401")
	}
}

// ============================================================================
// Dispatcher — RekeyMsg JSON
// ============================================================================

func TestRekeyMsgJSON(t *testing.T) {
	msg := RekeyMsg{
		Type:           "rekey",
		TokenEncrypted: "base64encodedciphertext==",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded RekeyMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != "rekey" {
		t.Errorf("Type: got %q, want rekey", decoded.Type)
	}
	if decoded.TokenEncrypted != "base64encodedciphertext==" {
		t.Errorf("TokenEncrypted: got %q", decoded.TokenEncrypted)
	}
}

// ============================================================================
// Dispatcher — WithEnrollConfig
// ============================================================================

func TestWithEnrollConfigChaining(t *testing.T) {
	key := generateTestKey2048(t)
	d := NewDispatcher(ConnConfig{JWT: "initial"}, nil).
		WithEnrollConfig(EnrollConfig{
			RegisterURL: "https://relay.example.com/api/register",
			Hostname:    "test-host",
			PrivateKey:  key,
			JWTPath:     "/tmp/token.jwt",
		})
	if d.enrollCfg.Hostname != "test-host" {
		t.Errorf("Hostname: got %q", d.enrollCfg.Hostname)
	}
	if d.enrollCfg.PrivateKey != key {
		t.Error("PrivateKey not set")
	}
}

// ============================================================================
// Dispatcher — JWT management (currentJWT / updateJWT)
// ============================================================================

func TestCurrentJWTInitialValue(t *testing.T) {
	d := NewDispatcher(ConnConfig{JWT: "initial-jwt"}, nil)
	if d.currentJWT() != "initial-jwt" {
		t.Errorf("currentJWT: got %q, want initial-jwt", d.currentJWT())
	}
}

func TestUpdateJWT(t *testing.T) {
	d := NewDispatcher(ConnConfig{JWT: "old-jwt"}, nil)
	d.updateJWT("new-jwt")
	if d.currentJWT() != "new-jwt" {
		t.Errorf("currentJWT after update: got %q, want new-jwt", d.currentJWT())
	}
}

// ============================================================================
// Handler rekey — intégration avec mock WS server
// ============================================================================

// TestDispatcherRekeyUpdatesJWT teste le scénario complet :
// 1. Le serveur envoie un message rekey avec token_encrypted
// 2. Le dispatcher déchiffre le token et met à jour le JWT courant
// 3. La connexion WS reste ouverte (pas de reconnexion)
func TestDispatcherRekeyUpdatesJWT(t *testing.T) {
	key := generateTestKey2048(t)
	newJWT := "rotated-jwt-after-rekey"
	tokenEncB64 := encryptJWT(t, &key.PublicKey, newJWT)

	// Mock WS server : envoie un rekey puis ferme proprement
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Envoie le message rekey
		msg := map[string]string{
			"type":            "rekey",
			"token_encrypted": tokenEncB64,
		}
		if err := conn.WriteJSON(msg); err != nil {
			return
		}

		// Laisse le dispatcher traiter le message, puis ferme proprement
		time.Sleep(100 * time.Millisecond)
		if err := conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done")); err != nil {
			t.Logf("mock server: WriteMessage close: %v", err)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	d := NewDispatcher(ConnConfig{
		ServerURL: wsURL,
		JWT:       "old-jwt",
		Insecure:  true,
	}, nil).WithEnrollConfig(EnrollConfig{
		PrivateKey: key,
	})

	// Override decryptAndSaveToken pour capturer l'appel
	originalFn := decryptAndSaveToken
	defer func() { decryptAndSaveToken = originalFn }()

	var decryptCalled atomic.Bool
	decryptAndSaveToken = func(enc string, privKey *rsa.PrivateKey, jwtPath string) (string, error) {
		decryptCalled.Store(true)
		return defaultDecryptAndSaveToken(enc, privKey, jwtPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_ = d.Run(ctx)

	if !decryptCalled.Load() {
		t.Error("decryptAndSaveToken was not called on rekey")
	}
	if d.currentJWT() != newJWT {
		t.Errorf("JWT after rekey: got %q, want %q", d.currentJWT(), newJWT)
	}
}

// ============================================================================
// Handler 401 — ré-enrôlement sur reconnexion
// ============================================================================

// TestDispatcherReenrollOn401 teste le scénario :
// 1. Le handshake WS retourne 401
// 2. Le dispatcher appelle reEnrollOnce
// 3. Après succès, reconnecte avec le nouveau JWT
func TestDispatcherReenrollOn401(t *testing.T) {
	key := generateTestKey2048(t)
	newJWT := "fresh-jwt-after-reenroll"

	var connectCount atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := connectCount.Add(1)
		if n == 1 {
			// Premier connect : refuser avec 401
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Deuxième connect : accepter et fermer proprement
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		time.Sleep(50 * time.Millisecond)
		if err := conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "ok")); err != nil {
			t.Logf("mock server: WriteMessage close: %v", err)
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	d := NewDispatcher(ConnConfig{
		ServerURL: wsURL,
		JWT:       "expired-jwt",
		Insecure:  true,
	}, nil).WithEnrollConfig(EnrollConfig{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PrivateKey:      key,
		EnrollmentToken: "tok",
	})

	// Mock reEnrollOnce pour retourner un nouveau JWT sans appel HTTP réel
	originalFn := reEnrollOnce
	defer func() { reEnrollOnce = originalFn }()

	var reEnrollCalled atomic.Bool
	reEnrollOnce = func(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
		reEnrollCalled.Store(true)
		return newJWT, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_ = d.Run(ctx)

	if !reEnrollCalled.Load() {
		t.Error("reEnrollOnce was not called after 401")
	}
	if d.currentJWT() != newJWT {
		t.Errorf("JWT after reenroll: got %q, want %q", d.currentJWT(), newJWT)
	}
	if connectCount.Load() < 2 {
		t.Errorf("expected at least 2 connect attempts, got %d", connectCount.Load())
	}
}

// TestDispatcherReenroll403StopsLoop teste que le 403 sur /api/register
// provoque une erreur permanente et stoppe la boucle.
func TestDispatcherReenroll403StopsLoop(t *testing.T) {
	key := generateTestKey2048(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	d := NewDispatcher(ConnConfig{
		ServerURL: wsURL,
		JWT:       "expired-jwt",
		Insecure:  true,
	}, nil).WithEnrollConfig(EnrollConfig{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PrivateKey:      key,
		EnrollmentToken: "tok",
	})

	// Mock reEnrollOnce pour simuler un 403
	originalFn := reEnrollOnce
	defer func() { reEnrollOnce = originalFn }()

	reEnrollOnce = func(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
		return "", &httpStatusError{code: 403, msg: "key not authorized"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	err := d.Run(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error after 403 on re-enrollment")
	}
	if !strings.Contains(err.Error(), "enrollment refused") && !strings.Contains(err.Error(), "re-enrollment") {
		t.Errorf("error should mention enrollment refusal, got: %v", err)
	}
	// Doit s'arrêter rapidement (pas de boucle infinie)
	if elapsed > 2*time.Second {
		t.Errorf("took too long to stop after 403: %s (expected < 2s)", elapsed)
	}
}

// TestDispatcherNoEnrollConfigOn401 teste que sans EnrollConfig,
// un 401 provoque une erreur claire.
func TestDispatcherNoEnrollConfigOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	d := NewDispatcher(ConnConfig{
		ServerURL: wsURL,
		JWT:       "expired-jwt",
		Insecure:  true,
	}, nil) // pas de WithEnrollConfig

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := d.Run(ctx)
	if err == nil {
		t.Error("expected error when no EnrollConfig configured")
	}
	if !strings.Contains(err.Error(), "no enrollment config") {
		t.Errorf("error should mention 'no enrollment config', got: %v", err)
	}
}

// ============================================================================
// handleUnauthorized — unit tests
// ============================================================================

func TestHandleUnauthorizedNoConfig(t *testing.T) {
	d := NewDispatcher(ConnConfig{}, nil)
	_, err := d.handleUnauthorized(context.Background())
	if err == nil {
		t.Error("expected error for missing enrollment config")
	}
}

func TestHandleUnauthorizedSuccessOnFirstAttempt(t *testing.T) {
	key := generateTestKey2048(t)
	d := NewDispatcher(ConnConfig{}, nil).WithEnrollConfig(EnrollConfig{
		RegisterURL:     "https://relay.example.com/api/register",
		Hostname:        "test",
		PrivateKey:      key,
		EnrollmentToken: "tok",
	})

	originalFn := reEnrollOnce
	defer func() { reEnrollOnce = originalFn }()

	reEnrollOnce = func(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
		return "new-jwt", nil
	}

	jwt, err := d.handleUnauthorized(context.Background())
	if err != nil {
		t.Fatalf("handleUnauthorized: %v", err)
	}
	if jwt != "new-jwt" {
		t.Errorf("JWT: got %q, want new-jwt", jwt)
	}
}

// handleUnauthorized fait UNE tentative : une erreur corrigible est rendue telle quelle (pas
// permanente) et c'est Run qui réessaie avec backoff.
func TestHandleUnauthorizedTransientErrorIsNotPermanent(t *testing.T) {
	key := generateTestKey2048(t)
	d := NewDispatcher(ConnConfig{}, nil).WithEnrollConfig(EnrollConfig{
		RegisterURL: "https://relay.example.com/api/register", Hostname: "test", PrivateKey: key, EnrollmentToken: "tok",
	})
	originalFn := reEnrollOnce
	defer func() { reEnrollOnce = originalFn }()
	var attempts atomic.Int32
	reEnrollOnce = func(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
		attempts.Add(1)
		return "", &httpStatusError{code: 503, msg: "unavailable"}
	}
	_, err := d.handleUnauthorized(context.Background())
	var perm *permanentError
	if err == nil || errors.As(err, &perm) {
		t.Fatalf("a 503 must be a retryable error, got %v", err)
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts: got %d, want 1", attempts.Load())
	}
}

func TestHandleUnauthorizedStopsOn403(t *testing.T) {
	key := generateTestKey2048(t)
	d := NewDispatcher(ConnConfig{}, nil).WithEnrollConfig(EnrollConfig{
		RegisterURL:     "https://relay.example.com/api/register",
		Hostname:        "test",
		PrivateKey:      key,
		EnrollmentToken: "tok",
	})

	originalFn := reEnrollOnce
	defer func() { reEnrollOnce = originalFn }()

	var attempts atomic.Int32
	reEnrollOnce = func(ctx context.Context, ec EnrollConfig, pubPEM string) (string, error) {
		attempts.Add(1)
		return "", &httpStatusError{code: 403, msg: "key not authorized"}
	}

	_, err := d.handleUnauthorized(context.Background())
	if err == nil {
		t.Error("expected error for 403")
	}
	var perm *permanentError
	if !errors.As(err, &perm) {
		t.Errorf("403 must be a permanent error, got %v", err)
	}
	// stoppe dès le premier 403
	if attempts.Load() != 1 {
		t.Errorf("attempts: got %d, want 1 (should stop immediately on 403)", attempts.Load())
	}
}

// ============================================================================
// EnrollConfig
// ============================================================================

func TestEnrollConfigFields(t *testing.T) {
	key := generateTestKey2048(t)
	ec := EnrollConfig{
		RegisterURL: "https://relay.example.com/api/register",
		Hostname:    "my-agent",
		PrivateKey:  key,
		JWTPath:     "/etc/secagent-minion/token.jwt",
	}
	if ec.Hostname != "my-agent" {
		t.Error("Hostname not preserved")
	}
	if ec.PrivateKey == nil {
		t.Error("PrivateKey is nil")
	}
}

// ============================================================================
// ReEnroller interface
// ============================================================================

func TestReEnrollerInterface(t *testing.T) {
	// Vérification que l'interface est correctement définie (compilation suffit)
	var _ ReEnroller = (*mockReEnroller)(nil)
}

type mockReEnroller struct {
	jwt string
	err error
}

func (m *mockReEnroller) ReEnroll(ctx context.Context) (string, error) {
	return m.jwt, m.err
}

// ============================================================================
// handleRekey — robustesse (#217)
// ============================================================================

func newRekeyDispatcher(t *testing.T, jwtPath string) (*Dispatcher, *rsa.PrivateKey) {
	t.Helper()
	key := generateTestKey2048(t)
	d := NewDispatcher(ConnConfig{JWT: "old-jwt", Insecure: true}, nil).
		WithEnrollConfig(EnrollConfig{PrivateKey: key, JWTPath: jwtPath})
	return d, key
}

func rekeyFrame(t *testing.T, key *rsa.PrivateKey, jwt string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": "rekey", "token_encrypted": encryptJWT(t, &key.PublicKey, jwt)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Le JWT est déjà sur disque (0600) au moment où updateJWT est appelé.
func TestHandleRekeyPersistsBeforeUse(t *testing.T) {
	path := t.TempDir() + "/token.jwt"
	d, key := newRekeyDispatcher(t, path)

	var onDiskAtUse string
	orig := decryptAndSaveToken
	defer func() { decryptAndSaveToken = orig }()
	decryptAndSaveToken = func(enc string, k *rsa.PrivateKey, p string) (string, error) {
		jwt, err := defaultDecryptAndSaveToken(enc, k, p)
		// Au retour, le dispatcher n'a pas encore adopté le JWT : il est déjà persisté.
		if b, rerr := os.ReadFile(p); rerr == nil {
			onDiskAtUse = string(b)
		}
		if d.currentJWT() != "old-jwt" {
			t.Errorf("JWT adopted before persistence returned")
		}
		return jwt, err
	}

	d.handleRekey(context.Background(), rekeyFrame(t, key, "renewed-1"))

	if onDiskAtUse != "renewed-1" {
		t.Errorf("on-disk JWT before use: got %q", onDiskAtUse)
	}
	if d.currentJWT() != "renewed-1" {
		t.Errorf("current JWT: got %q", d.currentJWT())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("token.jwt mode: %v %v", fi, err)
	}
}

// Trames malformées : aucune panique, JWT inchangé, compteur inchangé.
func TestHandleRekeyMalformedKeepsJWT(t *testing.T) {
	path := t.TempDir() + "/token.jwt"
	d, key := newRekeyDispatcher(t, path)
	otherKey := generateTestKey2048(t)

	cases := map[string][]byte{
		"not json":        []byte("{not json"),
		"token is number": []byte(`{"type":"rekey","token_encrypted":42}`),
		"missing token":   []byte(`{"type":"rekey"}`),
		"empty token":     []byte(`{"type":"rekey","token_encrypted":""}`),
		"bad base64":      []byte(`{"type":"rekey","token_encrypted":"!!!"}`),
		"wrong key":       rekeyFrame(t, otherKey, "x"),
		"empty plaintext": rekeyFrame(t, key, ""),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d.handleRekey(context.Background(), raw)
			if d.currentJWT() != "old-jwt" {
				t.Errorf("JWT changed: %q", d.currentJWT())
			}
			if n := d.rekeyCount.Load(); n != 0 {
				t.Errorf("rekeyCount: %d", n)
			}
			if _, err := os.Stat(path); err == nil {
				t.Errorf("token.jwt written on invalid frame")
			}
		})
	}
}

// Deux rekey successifs : le dernier gagne, le compteur vaut 2, le disque suit.
func TestHandleRekeyTwoSuccessive(t *testing.T) {
	path := t.TempDir() + "/token.jwt"
	d, key := newRekeyDispatcher(t, path)

	d.handleRekey(context.Background(), rekeyFrame(t, key, "renewed-1"))
	d.handleRekey(context.Background(), []byte("{garbage")) // entre deux : sans effet
	d.handleRekey(context.Background(), rekeyFrame(t, key, "renewed-2"))

	if d.currentJWT() != "renewed-2" {
		t.Errorf("current JWT: %q", d.currentJWT())
	}
	if b, _ := os.ReadFile(path); string(b) != "renewed-2" {
		t.Errorf("on-disk JWT: %q", b)
	}
	if n := d.rekeyCount.Load(); n != 2 {
		t.Errorf("rekeyCount: %d", n)
	}
}

// Échec d'écriture : le JWT est adopté en mémoire (l'ancien JTI est remplacé côté serveur).
func TestHandleRekeyPersistFailureKeptInMemory(t *testing.T) {
	dir := t.TempDir()
	blocker := dir + "/file"
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d, key := newRekeyDispatcher(t, blocker+"/sub/token.jwt") // parent = fichier : MkdirAll échoue

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.handleRekey(ctx, rekeyFrame(t, key, "renewed-mem"))

	if d.currentJWT() != "renewed-mem" {
		t.Errorf("current JWT: %q", d.currentJWT())
	}
}

// Le journal ne contient jamais le JWT.
func TestHandleRekeyNeverLogsToken(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	d, key := newRekeyDispatcher(t, t.TempDir()+"/token.jwt")

	d.handleRekey(context.Background(), rekeyFrame(t, key, "SECRET-JWT-VALUE"))
	d.handleRekey(context.Background(), []byte(`{"type":"rekey","token_encrypted":"SECRET-JWT-VALUE"}`))

	if strings.Contains(buf.String(), "SECRET-JWT-VALUE") {
		t.Errorf("JWT leaked in logs: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "renewal #1") {
		t.Errorf("renewal counter missing from logs: %s", buf.String())
	}
}

// M4 : échec d'écriture puis succès à la relance ; le JWT COURANT est écrit ; la relance s'arrête.
func TestHandleRekeyPersistRetryFailThenSuccess(t *testing.T) {
	path := t.TempDir() + "/token.jwt"
	d, key := newRekeyDispatcher(t, path)
	d.persistRetryInterval = 10 * time.Millisecond

	origDec, origPersist := decryptAndSaveToken, persistToken
	defer func() { decryptAndSaveToken, persistToken = origDec, origPersist }()
	decryptAndSaveToken = func(enc string, k *rsa.PrivateKey, p string) (string, error) {
		return "renewed-retry", &enrollment.PersistError{Err: errors.New("disk full")}
	}
	var calls atomic.Int32
	var last atomic.Value
	persistToken = func(p, jwt string) error {
		last.Store(jwt)
		if calls.Add(1) < 3 {
			return errors.New("still failing")
		}
		return origPersist(p, jwt)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.handleRekey(ctx, rekeyFrame(t, key, "ignored"))

	if d.currentJWT() != "renewed-retry" {
		t.Fatalf("current JWT %q", d.currentJWT())
	}
	waitFor(t, "condition", func() bool { b, _ := os.ReadFile(path); return string(b) == "renewed-retry" })
	if last.Load() != "renewed-retry" {
		t.Errorf("retry wrote %v", last.Load())
	}
	time.Sleep(60 * time.Millisecond) // plus de relance après le succès
	if n := calls.Load(); n != 3 {
		t.Errorf("persist calls: %d, want 3", n)
	}
}

// M4 : l'annulation du contexte (fermeture de connexion / arrêt) stoppe la relance.
func TestHandleRekeyPersistRetryStopsOnCancel(t *testing.T) {
	d, key := newRekeyDispatcher(t, t.TempDir()+"/token.jwt")
	d.persistRetryInterval = 10 * time.Millisecond

	origDec, origPersist := decryptAndSaveToken, persistToken
	defer func() { decryptAndSaveToken, persistToken = origDec, origPersist }()
	decryptAndSaveToken = func(string, *rsa.PrivateKey, string) (string, error) {
		return "j", &enrollment.PersistError{Err: errors.New("ro")}
	}
	var calls atomic.Int32
	persistToken = func(string, string) error { calls.Add(1); return errors.New("ro") }

	ctx, cancel := context.WithCancel(context.Background())
	d.handleRekey(ctx, rekeyFrame(t, key, "x"))
	waitFor(t, "condition", func() bool { return calls.Load() >= 2 })
	cancel()
	time.Sleep(30 * time.Millisecond)
	n := calls.Load()
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != n {
		t.Errorf("retry continued after cancel: %d -> %d", n, calls.Load())
	}
}

// M4 : un rekey persisté avec succès remplace la relance en attente.
func TestHandleRekeyNewRekeyStopsPendingRetry(t *testing.T) {
	path := t.TempDir() + "/token.jwt"
	d, key := newRekeyDispatcher(t, path)
	d.persistRetryInterval = 10 * time.Millisecond

	origDec, origPersist := decryptAndSaveToken, persistToken
	defer func() { decryptAndSaveToken, persistToken = origDec, origPersist }()
	fail := true
	decryptAndSaveToken = func(enc string, k *rsa.PrivateKey, p string) (string, error) {
		if fail {
			return "first", &enrollment.PersistError{Err: errors.New("ro")}
		}
		return defaultDecryptAndSaveToken(enc, k, p)
	}
	var calls atomic.Int32
	persistToken = func(string, string) error { calls.Add(1); return errors.New("ro") }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.handleRekey(ctx, rekeyFrame(t, key, "x"))
	waitFor(t, "condition", func() bool { return calls.Load() >= 1 })
	fail = false
	d.handleRekey(ctx, rekeyFrame(t, key, "second"))
	time.Sleep(30 * time.Millisecond)
	n := calls.Load()
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != n {
		t.Errorf("stale retry still running")
	}
	if b, _ := os.ReadFile(path); string(b) != "second" {
		t.Errorf("file %q", b)
	}
}
