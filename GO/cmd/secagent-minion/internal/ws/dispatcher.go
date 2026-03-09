// Package ws gère la connexion WebSocket persistante de l'agent et le dispatch
// des messages entrants vers les handlers appropriés.
//
// Protocole (§4 ARCHITECTURE.md) :
//   - Une seule WSS persistante par agent, multiplexée par task_id
//   - Messages Serveur→Agent : exec, put_file, fetch_file, cancel, rekey
//   - Messages Agent→Serveur : ack, stdout, result
//   - Reconnexion avec backoff exponentiel (1s..60s), sauf code 4001 (révocation)
//
// Architecture interne :
//   - Dispatcher reçoit les messages JSON bruts et les route vers les handlers
//   - Chaque exec lance une goroutine indépendante (pas de blocking du read loop)
//   - taskRegistry : map[task_id]*exec.Cmd pour les cancellations SIGTERM
//   - rekey : traité en-ligne dans la read loop (pas de goroutine), connexion maintenue
//   - 401 sur connect WS : ré-enrôlement automatique puis reconnexion (§22)
package ws

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// CloseCodeRevoked indique une révocation définitive — pas de reconnexion.
	CloseCodeRevoked = 4001
	// MaxConcurrentTasks est le nombre maximum de tâches exec simultanées.
	MaxConcurrentTasks = 10
	// StdoutBufferMax est la taille maximale de stdout avant troncature (5 MB).
	StdoutBufferMax = 5 * 1024 * 1024
)

// MessageHandler est la signature d'un handler de message WebSocket.
// Il reçoit le message décodé et le contexte de la connexion.
type MessageHandler interface {
	// HandleExec exécute une commande shell et envoie ack + result.
	HandleExec(ctx context.Context, msg ExecMsg, send SendFunc) error
	// HandlePutFile écrit un fichier base64 sur disque.
	HandlePutFile(ctx context.Context, msg PutFileMsg, send SendFunc) error
	// HandleFetchFile lit un fichier et retourne son contenu en base64.
	HandleFetchFile(ctx context.Context, msg FetchFileMsg, send SendFunc) error
}

// SendFunc est la fonction d'envoi de messages JSON sur le WebSocket.
type SendFunc func(payload any) error

// --- Message types (Serveur → Agent) ---

// BaseMsg est l'enveloppe commune à tous les messages.
type BaseMsg struct {
	TaskID string `json:"task_id"`
	Type   string `json:"type"`
}

// ExecMsg est le message d'exécution de commande (§4 ARCHITECTURE.md).
type ExecMsg struct {
	BaseMsg
	Cmd        string `json:"cmd"`
	Stdin      string `json:"stdin,omitempty"` // base64 | ""
	Timeout    int    `json:"timeout"`
	Become     bool   `json:"become"`
	BecomeMethod string `json:"become_method,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
}

// PutFileMsg est le message de transfert de fichier vers l'agent (§4).
type PutFileMsg struct {
	BaseMsg
	Dest string `json:"dest"`
	Data string `json:"data"` // base64
	Mode string `json:"mode"` // ex: "0700"
}

// FetchFileMsg est le message de récupération de fichier (§4).
type FetchFileMsg struct {
	BaseMsg
	Src string `json:"src"`
}

// CancelMsg est le message d'annulation de tâche (§4).
type CancelMsg struct {
	BaseMsg
}

// RekeyMsg est le message de rotation de JWT envoyé par le serveur (§22).
// Il ne contient pas de task_id — traité en-ligne avant le lookup de tâche.
type RekeyMsg struct {
	Type           string `json:"type"`
	TokenEncrypted string `json:"token_encrypted"` // base64(RSA-OAEP(JWT))
}

// --- Reconnect manager ---

// ReconnectManager gère le backoff exponentiel pour les reconnexions WebSocket.
type ReconnectManager struct {
	baseDelay float64
	maxDelay  float64
	attempt   int
}

// NewReconnectManager crée un ReconnectManager avec baseDelay et maxDelay en secondes.
func NewReconnectManager(baseDelay, maxDelay float64) *ReconnectManager {
	return &ReconnectManager{baseDelay: baseDelay, maxDelay: maxDelay}
}

// NextDelay retourne le prochain délai de reconnexion et incrémente le compteur.
func (r *ReconnectManager) NextDelay() time.Duration {
	delay := r.baseDelay * math.Pow(2, float64(r.attempt))
	if delay > r.maxDelay {
		delay = r.maxDelay
	}
	r.attempt++
	return time.Duration(delay * float64(time.Second))
}

// Reset remet le compteur à zéro après une connexion réussie.
func (r *ReconnectManager) Reset() {
	r.attempt = 0
}

// ShouldReconnect retourne false si le code de fermeture indique une révocation.
func (r *ReconnectManager) ShouldReconnect(closeCode int) bool {
	return closeCode != CloseCodeRevoked
}

// --- Rekey / ReEnroll interface ---

// ReEnroller permet au dispatcher de déclencher un ré-enrôlement complet
// auprès du relay server quand le JWT est rejeté (HTTP 401).
// Implémenté par le package enrollment, injecté dans le Dispatcher.
type ReEnroller interface {
	// ReEnroll effectue POST /api/register et retourne le nouveau JWT.
	// Retourne une erreur encapsulant le code HTTP si le serveur rejette (ex. 403).
	ReEnroll(ctx context.Context) (string, error)
}

// --- Connection config ---

// ConnConfig regroupe les paramètres de connexion WebSocket.
type ConnConfig struct {
	// ServerURL est l'URL WSS du relay server (wss://relay.example.com/ws/agent).
	ServerURL string
	// JWT est le token d'authentification Bearer.
	JWT string
	// CABundle est le chemin vers un CA bundle PEM custom (vide = store système).
	CABundle string
	// Insecure désactive la vérification TLS (tests uniquement).
	Insecure bool
}

// EnrollConfig regroupe les paramètres nécessaires au ré-enrôlement sur 401.
// Stocké dans le Dispatcher pour être utilisé dans la boucle de reconnexion.
type EnrollConfig struct {
	// RegisterURL est le endpoint d'enregistrement (https://relay.example.com/api/register).
	RegisterURL string
	// Hostname identifie l'agent.
	Hostname string
	// PrivateKey est la clef RSA locale de l'agent.
	PrivateKey *rsa.PrivateKey
	// JWTPath est le chemin de stockage du JWT persisté.
	JWTPath string
	// EnrollmentToken est le token d'enrollment (RELAY_ENROLLMENT_TOKEN) — requis Phase 10.
	// JAMAIS loggé en clair.
	EnrollmentToken string
	// Insecure désactive la vérification TLS (tests uniquement).
	Insecure bool
	// MaxRetries est le nombre max de tentatives de ré-enrôlement avant abandon (défaut: 3).
	MaxRetries int
}

// --- Dispatcher ---

// Dispatcher maintient la connexion WebSocket et route les messages.
type Dispatcher struct {
	cfg            ConnConfig
	enrollCfg      EnrollConfig
	handler        MessageHandler
	mu             sync.Mutex
	tasks          map[string]context.CancelFunc // task_id → cancel goroutine
	maxConcurrent  int

	// jwtMu protège l'accès concurrent au JWT courant (rotation rekey).
	jwtMu sync.RWMutex
	jwt   string
}

// NewDispatcher crée un Dispatcher avec le handler fourni.
// maxConcurrent = 0 → utilise MaxConcurrentTasks (constante, défaut 10).
func NewDispatcher(cfg ConnConfig, handler MessageHandler, maxConcurrent ...int) *Dispatcher {
	max := MaxConcurrentTasks
	if len(maxConcurrent) > 0 && maxConcurrent[0] > 0 {
		max = maxConcurrent[0]
	}
	return &Dispatcher{
		cfg:           cfg,
		handler:       handler,
		tasks:         make(map[string]context.CancelFunc),
		maxConcurrent: max,
		jwt:           cfg.JWT,
	}
}

// WithEnrollConfig attache la configuration de ré-enrôlement au dispatcher.
// Doit être appelé avant Run() pour activer le ré-enrôlement sur 401.
func (d *Dispatcher) WithEnrollConfig(ec EnrollConfig) *Dispatcher {
	if ec.MaxRetries <= 0 {
		ec.MaxRetries = 3
	}
	d.enrollCfg = ec
	return d
}

// currentJWT retourne le JWT courant (thread-safe).
func (d *Dispatcher) currentJWT() string {
	d.jwtMu.RLock()
	defer d.jwtMu.RUnlock()
	return d.jwt
}

// updateJWT met à jour le JWT courant (thread-safe).
func (d *Dispatcher) updateJWT(token string) {
	d.jwtMu.Lock()
	defer d.jwtMu.Unlock()
	d.jwt = token
}

// Run ouvre la connexion WebSocket et entre dans la boucle de lecture.
// Tourne jusqu'à ce que ctx soit annulé ou que la connexion soit révoquée (4001).
//
// Gestion du 401 (§22 ARCHITECTURE.md — Phase 3) :
//   - HTTP 401 sur upgrade WS → ré-enrôlement complet (si EnrollConfig configurée)
//   - HTTP 403 sur re-enrôlement → log + abandon (pas de boucle infinie)
//   - Après ré-enrôlement réussi, le backoff est réinitialisé
func (d *Dispatcher) Run(ctx context.Context) error {
	reconnect := NewReconnectManager(1.0, 60.0)

	for {
		err := d.connect(ctx, reconnect)
		if err == nil {
			// Connexion fermée proprement via ctx
			return nil
		}

		// Vérification révocation (code WS 4001)
		var closeErr *websocket.CloseError
		if isClose(err, &closeErr) && !reconnect.ShouldReconnect(closeErr.Code) {
			return fmt.Errorf("ws: agent revoked by server (code %d)", closeErr.Code)
		}

		// Gestion du 401 : ré-enrôlement automatique
		if isHTTP401(err) {
			if newJWT, reenrollErr := d.handleUnauthorized(ctx); reenrollErr != nil {
				return fmt.Errorf("ws: re-enrollment failed: %w", reenrollErr)
			} else {
				d.updateJWT(newJWT)
				reconnect.Reset()
				log.Printf("[SECURITY] Re-enrollment after JWT rejection (401) — reconnecting")
				continue // reconnexion immédiate avec le nouveau JWT
			}
		}

		delay := reconnect.NextDelay()
		log.Printf("[WS] Connection lost: %v — reconnecting in %s", err, delay)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// handleUnauthorized gère le ré-enrôlement complet après un 401 WS.
// Supprime le JWT local, appelle POST /api/register, sauvegarde le nouveau JWT.
// Retourne une erreur permanente si le serveur répond 403 (clef non autorisée).
func (d *Dispatcher) handleUnauthorized(ctx context.Context) (string, error) {
	ec := d.enrollCfg
	if ec.RegisterURL == "" || ec.PrivateKey == nil {
		return "", fmt.Errorf("401 received but no enrollment config — cannot re-enroll")
	}

	maxRetries := ec.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	// Supprimer le JWT local invalide
	if ec.JWTPath != "" {
		if err := os.Remove(ec.JWTPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] Cannot remove stale JWT %s: %v", ec.JWTPath, err)
		}
	}

	pubPEM, err := publicKeyPEMFromPrivate(ec.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("re-enrollment: compute public key: %w", err)
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		enrollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		newJWT, enrollErr := reEnrollOnce(enrollCtx, ec, pubPEM)
		cancel()

		if enrollErr == nil {
			return newJWT, nil
		}

		// 403 : clef non autorisée — pas la peine de boucler
		if isForbiddenErr(enrollErr) {
			log.Printf("[SECURITY] enrollment refused (403) — agent key not authorized, stopping")
			return "", fmt.Errorf("enrollment refused by server (403): %w", enrollErr)
		}

		log.Printf("[WARN] Re-enrollment attempt %d/%d failed: %v", attempt, maxRetries, enrollErr)
		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 5 * time.Second):
			}
		}
	}

	return "", fmt.Errorf("re-enrollment failed after %d attempts", maxRetries)
}

// connect établit une connexion WSS et entre dans la boucle de lecture.
func (d *Dispatcher) connect(ctx context.Context, reconnect *ReconnectManager) error {
	tlsCfg, err := buildTLSConfig(d.cfg.CABundle, d.cfg.Insecure)
	if err != nil {
		return fmt.Errorf("ws: build TLS config: %w", err)
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 15 * time.Second,
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+d.currentJWT())

	conn, resp, err := dialer.DialContext(ctx, d.cfg.ServerURL, headers)
	if err != nil {
		// Détecter le 401 HTTP lors du handshake WS
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return &httpStatusError{code: http.StatusUnauthorized, msg: "ws handshake rejected (401 Unauthorized)"}
		}
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return &httpStatusError{code: http.StatusForbidden, msg: "ws handshake rejected (403 Forbidden)"}
		}
		return fmt.Errorf("ws: dial %s: %w", d.cfg.ServerURL, err)
	}
	defer conn.Close()

	reconnect.Reset()
	log.Printf("[WS] Connected to %s", d.cfg.ServerURL)

	// Heartbeat : répond automatiquement aux pings du serveur avec un pong.
	// gorilla/websocket envoie les pongs via le handler enregistré.
	sendMu := &sync.Mutex{}
	conn.SetPongHandler(func(appData string) error {
		log.Printf("[WS] Pong received")
		return nil
	})
	conn.SetPingHandler(func(appData string) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return conn.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	send := func(payload any) error {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		sendMu.Lock()
		defer sendMu.Unlock()
		return conn.WriteMessage(websocket.TextMessage, data)
	}

	sem := make(chan struct{}, d.maxConcurrent)

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var base BaseMsg
		if err := json.Unmarshal(raw, &base); err != nil {
			log.Printf("[WS] Non-JSON message: %q", string(raw)[:min(200, len(raw))])
			continue
		}

		switch base.Type {
		case "rekey":
			// Rotation JWT sans interruption de connexion (§22 ARCHITECTURE.md).
			// Traité en-ligne (pas de goroutine) : le JWT doit être mis à jour
			// immédiatement avant tout envoi ultérieur.
			var msg RekeyMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("[WS] Bad rekey message: %v", err)
				continue
			}
			if d.enrollCfg.PrivateKey == nil {
				log.Printf("[SECURITY] rekey received but no private key configured — ignoring")
				continue
			}
			newJWT, err := decryptAndSaveToken(msg.TokenEncrypted, d.enrollCfg.PrivateKey, d.enrollCfg.JWTPath)
			if err != nil {
				log.Printf("[SECURITY] rekey: failed to decrypt new token: %v", err)
				continue
			}
			d.updateJWT(newJWT)
			log.Printf("[SECURITY] JWT rotated — new token received")

		case "exec":
			var msg ExecMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("[WS] Bad exec message: %v", err)
				continue
			}
			select {
			case sem <- struct{}{}:
				taskCtx, cancel := context.WithCancel(ctx)
				d.registerTask(msg.TaskID, cancel)
				go func() {
					defer func() { <-sem }()
					defer d.unregisterTask(msg.TaskID)
					if err := d.handler.HandleExec(taskCtx, msg, send); err != nil {
						log.Printf("[WS] exec task %s error: %v", msg.TaskID, err)
					}
				}()
			default:
				_ = send(map[string]any{
					"task_id":   base.TaskID,
					"type":      "result",
					"rc":        -1,
					"stdout":    "",
					"stderr":    "agent_busy",
					"truncated": false,
				})
			}

		case "put_file":
			var msg PutFileMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("[WS] Bad put_file message: %v", err)
				continue
			}
			go func() {
				if err := d.handler.HandlePutFile(ctx, msg, send); err != nil {
					log.Printf("[WS] put_file task %s error: %v", msg.TaskID, err)
				}
			}()

		case "fetch_file":
			var msg FetchFileMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("[WS] Bad fetch_file message: %v", err)
				continue
			}
			go func() {
				if err := d.handler.HandleFetchFile(ctx, msg, send); err != nil {
					log.Printf("[WS] fetch_file task %s error: %v", msg.TaskID, err)
				}
			}()

		case "cancel":
			var msg CancelMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}
			d.cancelTask(msg.TaskID)

		default:
			log.Printf("[WS] Unknown message type: %s (task_id=%s)", base.Type, base.TaskID)
		}
	}
}

func (d *Dispatcher) registerTask(taskID string, cancel context.CancelFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tasks[taskID] = cancel
}

func (d *Dispatcher) unregisterTask(taskID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.tasks, taskID)
}

func (d *Dispatcher) cancelTask(taskID string) {
	d.mu.Lock()
	cancel, ok := d.tasks[taskID]
	d.mu.Unlock()
	if ok {
		cancel()
		log.Printf("[WS] Task %s cancelled", taskID)
	} else {
		log.Printf("[WS] Cancel received for unknown task: %s", taskID)
	}
}

// buildTLSConfig construit un TLS config strict (MinVersion TLS 1.2, cert vérifié).
// caBundle vide → store système. insecure=true désactive la vérification (tests uniquement).
func buildTLSConfig(caBundle string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // tests only, guarded by flag
	}
	if !insecure && caBundle != "" {
		pem, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs in CA bundle %s", caBundle)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func isClose(err error, target **websocket.CloseError) bool {
	ce, ok := err.(*websocket.CloseError)
	if ok && target != nil {
		*target = ce
	}
	return ok
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// HTTP 401 / 403 helpers
// ---------------------------------------------------------------------------

// httpStatusError représente une erreur HTTP avec code de statut,
// retournée lors du handshake WebSocket pour permettre la détection du 401.
type httpStatusError struct {
	code int
	msg  string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("http %d: %s", e.code, e.msg)
}

// isHTTP401 retourne true si l'erreur est un httpStatusError HTTP 401.
func isHTTP401(err error) bool {
	var e *httpStatusError
	if ok := asHTTPStatusError(err, &e); ok {
		return e.code == http.StatusUnauthorized
	}
	return false
}

// isForbiddenErr retourne true si l'erreur indique un HTTP 403.
func isForbiddenErr(err error) bool {
	var e *httpStatusError
	if ok := asHTTPStatusError(err, &e); ok {
		return e.code == http.StatusForbidden
	}
	return false
}

func asHTTPStatusError(err error, target **httpStatusError) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*httpStatusError)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// ---------------------------------------------------------------------------
// Enrollment helpers (évite import circulaire en copiant les signatures)
// ---------------------------------------------------------------------------

// decryptAndSaveToken déchiffre un token_encrypted RSA-OAEP et le persiste.
// Délègue à enrollment.DecryptAndSaveToken via une variable de fonction
// pour faciliter les tests (mock possible).
var decryptAndSaveToken = defaultDecryptAndSaveToken

// reEnrollOnce effectue un enrollment complet POST /api/register.
// Délégue à enrollment.Enroll via une variable de fonction pour les tests.
var reEnrollOnce = defaultReEnrollOnce

// publicKeyPEMFromPrivate sérialise la clef publique RSA en PEM PKIX.
// Délègue à enrollment.PublicKeyPEM via une variable de fonction pour les tests.
var publicKeyPEMFromPrivate = defaultPublicKeyPEMFromPrivate
