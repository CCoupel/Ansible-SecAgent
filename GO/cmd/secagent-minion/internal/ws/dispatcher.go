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
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
	"secagent-server/internal/endpoints"
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
	Cmd          string `json:"cmd"`
	Stdin        string `json:"stdin,omitempty"` // base64 | ""
	Timeout      int    `json:"timeout"`
	Become       bool   `json:"become"`
	BecomeMethod string `json:"become_method,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
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
	cycles    int // cycles ré-enrôlement → 401 consécutifs sans connexion réussie
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

// Cycle donne le délai à attendre avant de relancer un cycle « ré-enrôlement réussi → WS 401 » :
// 0 pour le premier cycle après une connexion qui fonctionnait (reconnexion immédiate avec le
// nouveau JWT), puis base, 2×base… plafonné à maxDelay si le serveur continue de répondre 401.
func (r *ReconnectManager) Cycle() time.Duration {
	n := r.cycles
	r.cycles++
	if n == 0 {
		return 0
	}
	delay := r.baseDelay * math.Pow(2, float64(n-1))
	if delay > r.maxDelay {
		delay = r.maxDelay
	}
	return time.Duration(delay * float64(time.Second))
}

// Reset remet les compteurs à zéro après une connexion réussie.
func (r *ReconnectManager) Reset() {
	r.attempt = 0
	r.cycles = 0
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
	// ServerURL est l'URL WSS du relay server (wss://relay.example.com/ws/agent). Valeur unique,
	// ignorée si Endpoints est défini.
	ServerURL string
	// Endpoints est la liste des adresses WSS (RELAY_WS_URL en liste), appariées par position avec
	// celles de EnrollConfig.Rotor : essayées par endpoints.DialFirst, dernière bonne en tête.
	Endpoints *endpoints.Rotor
	// JWT est le token d'authentification Bearer.
	JWT string
	// CABundle est le chemin vers un CA bundle PEM custom (vide = store système).
	CABundle string
	// Insecure désactive la vérification TLS (tests uniquement).
	Insecure bool
}

// wsAttemptTimeout borne la connexion + la poignée de main WebSocket sur UNE adresse.
const wsAttemptTimeout = 20 * time.Second

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
	// CABundle est le chemin vers un CA bundle PEM custom (vide = store système).
	CABundle string
	// Rotor, quand il est défini, remplace RegisterURL : adresses des serveurs (URL de base),
	// appariées par position avec ConnConfig.Endpoints (même instance). Le ré-enrôlement ne change
	// d'adresse que si la connexion échoue avant l'envoi.
	Rotor *endpoints.Rotor
	// Insecure désactive la vérification TLS (tests uniquement).
	Insecure bool
}

// --- Dispatcher ---

// Dispatcher maintient la connexion WebSocket et route les messages.
type Dispatcher struct {
	cfg           ConnConfig
	enrollCfg     EnrollConfig
	handler       MessageHandler
	mu            sync.Mutex
	tasks         map[string]context.CancelFunc // task_id → cancel goroutine
	maxConcurrent int

	// jwtMu protège l'accès concurrent au JWT courant (rotation rekey).
	jwtMu sync.RWMutex
	jwt   string

	// wait dort delay ou jusqu'à l'annulation de ctx (injectable : les tests n'attendent pas).
	wait func(ctx context.Context, delay time.Duration) error
	// reconnectBase / reconnectMax bornent le backoff en secondes (0 = 1 s → 60 s).
	reconnectBase, reconnectMax float64
	// connected est vrai quand la dernière connexion a abouti (handshake WS réussi).
	connected atomic.Bool

	// wsRotor ordonne les adresses WS ; enrollRotor (EnrollConfig.Rotor) celles d'enrôlement. Les
	// deux listes sont appariées par position : la dernière bonne instance est partagée.
	wsRotor *endpoints.Rotor
	// attemptTimeout borne connexion + poignée de main sur une adresse (0 = wsAttemptTimeout).
	attemptTimeout time.Duration
}

// permanentError marque une erreur de ré-enrôlement qui ne se corrige pas en réessayant (token
// d'enrôlement refusé : 403, ou aucune configuration d'enrôlement) : le minion s'arrête.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func sleepCtx(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ConsecutiveAuthFailuresAlert est le nombre de cycles consécutifs sans connexion réussie à
// partir duquel le minion journalise une erreur explicite (il continue d'essayer, avec backoff).
const ConsecutiveAuthFailuresAlert = 5

// NewDispatcher crée un Dispatcher avec le handler fourni.
// maxConcurrent = 0 → utilise MaxConcurrentTasks (constante, défaut 10).
func NewDispatcher(cfg ConnConfig, handler MessageHandler, maxConcurrent ...int) *Dispatcher {
	max := MaxConcurrentTasks
	if len(maxConcurrent) > 0 && maxConcurrent[0] > 0 {
		max = maxConcurrent[0]
	}
	d := &Dispatcher{
		cfg:           cfg,
		handler:       handler,
		tasks:         make(map[string]context.CancelFunc),
		maxConcurrent: max,
		jwt:           cfg.JWT,
		wsRotor:       cfg.Endpoints,
	}
	if d.wsRotor == nil && cfg.ServerURL != "" {
		// valeur unique (compatibilité) : liste d'une adresse
		if u, err := url.Parse(cfg.ServerURL); err == nil {
			d.wsRotor, _ = endpoints.NewRotor([]*url.URL{u}, endpoints.Backoff{})
		}
	}
	return d
}

// syncPair propage la dernière bonne instance d'une liste à l'autre (appariement par position).
func syncPair(from, to *endpoints.Rotor) {
	if from != nil && to != nil && from.Len() == to.Len() {
		to.Success(from.Head())
	}
}

// WithEnrollConfig attache la configuration de ré-enrôlement au dispatcher.
// Doit être appelé avant Run() pour activer le ré-enrôlement sur 401.
func (d *Dispatcher) WithEnrollConfig(ec EnrollConfig) *Dispatcher {
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
// Tourne jusqu'à ce que ctx soit annulé, que la connexion soit révoquée (4001) ou qu'une erreur
// permanente survienne.
//
// Gestion du 401 (§22 ARCHITECTURE.md) :
//   - HTTP 401 sur l'upgrade WS → ré-enrôlement complet (si EnrollConfig configurée) puis
//     reconnexion avec le nouveau JWT ;
//   - HTTP 403 au ré-enrôlement (token d'enrôlement invalide, expiré ou consommé) → arrêt
//     explicite, pas de boucle ;
//   - tout autre échec du ré-enrôlement (400 transitoire, réseau, 5xx) → nouvel essai avec
//     backoff exponentiel 1 s → 60 s, sans abandon ;
//   - backoff aussi entre deux cycles « ré-enrôlement réussi → WS encore en 401 » (le premier
//     cycle après une connexion qui fonctionnait est immédiat), remis à zéro à la première
//     connexion WS réussie ; [ERROR] explicite à partir de 5 cycles consécutifs ;
//   - fermeture 4001 (révocation) → arrêt, ni reconnexion ni ré-enrôlement.
func (d *Dispatcher) Run(ctx context.Context) error {
	base, max := d.reconnectBase, d.reconnectMax
	if base <= 0 {
		base = 1.0
	}
	if max <= 0 {
		max = 60.0
	}
	reconnect := NewReconnectManager(base, max)
	wait := d.wait
	if wait == nil {
		wait = sleepCtx
	}
	authFailures := 0 // cycles consécutifs sans connexion WS réussie, côté authentification

	for {
		d.connected.Store(false)
		err := d.connect(ctx, reconnect)
		if err == nil {
			// Connexion fermée proprement via ctx
			return nil
		}
		if d.connected.Load() {
			authFailures = 0 // le WS a fonctionné : on repart de zéro
		}

		// Vérification révocation (code WS 4001)
		var closeErr *websocket.CloseError
		if isClose(err, &closeErr) && !reconnect.ShouldReconnect(closeErr.Code) {
			return fmt.Errorf("ws: agent revoked by server (code %d)", closeErr.Code)
		}

		// Gestion du 401 : ré-enrôlement automatique
		if isHTTP401(err) {
			authFailures++
			if authFailures >= ConsecutiveAuthFailuresAlert {
				log.Printf("[ERROR] %d consecutive authentication cycles without a working WebSocket (JWT refused after re-enrollment) — still retrying with backoff; check the server and the minion enrollment", authFailures)
			}
			newJWT, reenrollErr := d.handleUnauthorized(ctx)
			var perm *permanentError
			switch {
			case errors.As(reenrollErr, &perm):
				return fmt.Errorf("ws: re-enrollment failed: %w", reenrollErr)
			case reenrollErr != nil:
				if ctx.Err() != nil {
					return ctx.Err()
				}
				delay := reconnect.NextDelay()
				log.Printf("[WARN] Re-enrollment failed: %v — retrying in %s", reenrollErr, delay)
				if werr := wait(ctx, delay); werr != nil {
					return werr
				}
				continue
			}
			d.updateJWT(newJWT)
			log.Printf("[SECURITY] Re-enrollment after JWT rejection (401) — reconnecting")
			// pas de reconnect.Reset() ici : seul un handshake WS réussi remet le backoff à zéro
			if delay := reconnect.Cycle(); delay > 0 {
				log.Printf("[WS] Re-enrolled but the server still rejects the JWT — waiting %s before the next cycle", delay)
				if werr := wait(ctx, delay); werr != nil {
					return werr
				}
			}
			continue
		}

		delay := reconnect.NextDelay()
		log.Printf("[WS] Connection lost: %v — reconnecting in %s", err, delay)

		if werr := wait(ctx, delay); werr != nil {
			return werr
		}
	}
}

// handleUnauthorized tente UN ré-enrôlement complet après un 401 WS : supprime le JWT local
// invalide, rejoue le challenge-response (clef privée existante, hostname configuré, token
// d'enrôlement) via enrollment, persiste le nouveau JWT et le retourne.
// Erreur *permanentError : pas de configuration d'enrôlement, ou 403 (token d'enrôlement
// invalide, expiré ou consommé). Toute autre erreur est corrigible : l'appelant réessaie.
// Rien de secret n'est journalisé (ni JWT, ni token, ni challenge).
func (d *Dispatcher) handleUnauthorized(ctx context.Context) (string, error) {
	ec := d.enrollCfg
	if (ec.RegisterURL == "" && ec.Rotor == nil) || ec.PrivateKey == nil {
		return "", &permanentError{fmt.Errorf("401 received but no enrollment config — cannot re-enroll")}
	}
	if ec.EnrollmentToken == "" {
		return "", &permanentError{fmt.Errorf("401 received but RELAY_ENROLLMENT_TOKEN is not set — cannot re-enroll")}
	}

	// Supprimer le JWT local invalide
	if ec.JWTPath != "" {
		if err := os.Remove(ec.JWTPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] Cannot remove stale JWT %s: %v", ec.JWTPath, err)
		}
	}

	pubPEM, err := publicKeyPEMFromPrivate(ec.PrivateKey)
	if err != nil {
		return "", &permanentError{fmt.Errorf("re-enrollment: compute public key: %w", err)}
	}

	enrollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	newJWT, enrollErr := reEnrollOnce(enrollCtx, ec, pubPEM)
	if enrollErr == nil {
		syncPair(ec.Rotor, d.wsRotor) // the instance that enrolled us is the first one the WS tries
		return newJWT, nil
	}
	// 403 : token d'enrôlement refusé — inutile de boucler
	if isForbiddenErr(enrollErr) {
		log.Printf("[SECURITY] enrollment refused (403) — enrollment token invalid, expired or already used, stopping")
		return "", &permanentError{fmt.Errorf("enrollment refused by server (403): %w", enrollErr)}
	}
	return "", enrollErr
}

// connect établit une connexion WSS et entre dans la boucle de lecture.
func (d *Dispatcher) connect(ctx context.Context, reconnect *ReconnectManager) error {
	tlsCfg, err := buildTLSConfig(d.cfg.CABundle, d.cfg.Insecure)
	if err != nil {
		return fmt.Errorf("ws: build TLS config: %w", err)
	}

	if d.wsRotor == nil {
		return errors.New("ws: no server address configured")
	}
	jwt := d.currentJWT()
	attempt := d.attemptTimeout
	if attempt <= 0 {
		attempt = wsAttemptTimeout
	}
	conn, u, err := endpoints.DialFirst(ctx, d.wsRotor, attempt,
		func(actx context.Context, u *url.URL) (*websocket.Conn, error) {
			return d.dialOne(actx, u, tlsCfg, jwt)
		})
	if err != nil {
		var hs *httpStatusError
		if errors.Is(err, endpoints.ErrAfterSend) && !errors.As(err, &hs) {
			// the handshake was sent and failed (cut, silence): no other address in this round
			// (the request is not replayed), but the next round must not start on the same
			// silent address. A 401/403 answer is a verdict, not a silent host: no rotation.
			if i, ok := endpoints.AfterSendIndex(err); ok {
				d.wsRotor.Rotate(i)
			}
		}
		return err
	}
	syncPair(d.wsRotor, d.enrollCfg.Rotor)
	return d.serve(ctx, conn, u.Host, reconnect)
}

// dialOne opens ONE WebSocket on u. The Upgrade request is written by gorilla itself, so the
// connection wrapper calls endpoints.MarkSent right before the first application byte: a timeout
// or cut after that point is an "after send" failure and DialFirst will not try another address.
// TLS (wss) is done here so that its own writes (ClientHello) do NOT count as "sent".
func (d *Dispatcher) dialOne(ctx context.Context, u *url.URL, tlsCfg *tls.Config, jwt string) (*websocket.Conn, error) {
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	nd := &net.Dialer{}
	switch u.Scheme {
	case "wss":
		dialer.NetDialTLSContext = func(c context.Context, network, addr string) (net.Conn, error) {
			raw, err := nd.DialContext(c, network, addr)
			if err != nil {
				return nil, err
			}
			cfg := tlsCfg.Clone()
			if cfg.ServerName == "" {
				cfg.ServerName = u.Hostname()
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(c); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return &markingConn{Conn: tc, ctx: c}, nil
		}
	default:
		dialer.NetDialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			raw, err := nd.DialContext(c, network, addr)
			if err != nil {
				return nil, err
			}
			return &markingConn{Conn: raw, ctx: c}, nil
		}
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+jwt)
	conn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		// Détecter le 401/403 HTTP lors du handshake WS
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, &httpStatusError{code: http.StatusUnauthorized, msg: "ws handshake rejected (401 Unauthorized)"}
		}
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return nil, &httpStatusError{code: http.StatusForbidden, msg: "ws handshake rejected (403 Forbidden)"}
		}
		return nil, fmt.Errorf("ws: dial %s: %w", u.Host, err)
	}
	return conn, nil
}

// markingConn marks the attempt as "request sent" at the first write on the established
// (and, for wss, TLS-secured) connection: that write is the HTTP Upgrade request.
type markingConn struct {
	net.Conn
	ctx  context.Context
	once sync.Once
}

func (m *markingConn) Write(p []byte) (int, error) {
	m.once.Do(func() { endpoints.MarkSent(m.ctx) })
	return m.Conn.Write(p)
}

// serve runs the read loop of an established connection.
func (d *Dispatcher) serve(ctx context.Context, conn *websocket.Conn, host string, reconnect *ReconnectManager) error {
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Debug("[WS] close connection", "err", err)
		}
	}()

	// Arrêt demandé (SIGTERM → ctx annulé) : fermer la socket débloque la lecture ci-dessous,
	// sinon un minion connecté ne s'arrêterait qu'à la perte de la connexion.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	reconnect.Reset()
	d.connected.Store(true)
	log.Printf("[WS] Connected to %s", host)

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
			if ctx.Err() != nil {
				return nil // arrêt demandé, pas une perte de connexion
			}
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
	return enrollment.IsForbidden(err)
}

func asHTTPStatusError(err error, target **httpStatusError) bool {
	if err == nil {
		return false
	}
	var e *httpStatusError
	ok := errors.As(err, &e) // DialFirst wraps handshake verdicts in an after-send error
	if ok && target != nil {
		*target = e
	}
	return ok
}

// ---------------------------------------------------------------------------
// Enrollment helpers (délégation à internal/enrollment, seule implémentation du protocole)
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
