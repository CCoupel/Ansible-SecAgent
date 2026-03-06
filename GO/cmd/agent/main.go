// relay-agent — Daemon client AnsibleRelay (Go).
//
// Flow de démarrage (§8, §18 ARCHITECTURE.md) :
//  1. Charge la configuration depuis les variables d'environnement
//  2. Génère la keypair RSA-4096 si la clef privée n'existe pas encore
//  3. Enrollment : POST /api/register avec clef publique RSA
//     → déchiffre le JWT retourné (RSA-OAEP SHA-256) → persiste en 0600
//     Si JWT déjà présent sur disque → réutilise sans re-enrollment
//  4. Collecte les facts système (hostname, OS, CPU, RAM, disk, network)
//  5. Ouvre la connexion WSS avec JWT Bearer
//  6. Boucle de dispatch des messages (exec / put_file / fetch_file / cancel)
//  7. Reconnexion backoff exponentiel (1s→2s→4s→…→max 60s)
//     Arrêt définitif si close code 4001 (révocation par le serveur)
//  8. Graceful shutdown sur SIGTERM/SIGINT
//
// Configuration (variables d'environnement) :
//
//	RELAY_SERVER_URL      URL HTTPS du relay server   (défaut: https://localhost:7770)
//	RELAY_WS_URL          URL WSS du relay server     (défaut: wss://localhost:7772/ws/agent)
//	RELAY_AGENT_HOSTNAME  Hostname de l'agent         (défaut: os.Hostname())
//	RELAY_PRIVATE_KEY     Chemin clef privée RSA      (défaut: /etc/relay-agent/id_rsa)
//	RELAY_JWT_PATH        Chemin JWT persisté         (défaut: /etc/relay-agent/token.jwt)
//	RELAY_CA_BUNDLE       CA bundle PEM custom        (défaut: store système)
//	RELAY_ASYNC_DIR       Répertoire registre async   (défaut: /var/lib/relay-agent/async)
//	RELAY_INSECURE_TLS    "true" pour désactiver TLS  (TESTS UNIQUEMENT)
//	MAX_CONCURRENT_TASKS  Tâches exec simultanées     (défaut: 10)
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"relay-server/cmd/agent/internal/enrollment"
	"relay-server/cmd/agent/internal/executor"
	"relay-server/cmd/agent/internal/facts"
	"relay-server/cmd/agent/internal/files"
	"relay-server/cmd/agent/internal/registry"
	"relay-server/cmd/agent/internal/ws"
)

func main() {
	log.Printf("[INIT] AnsibleRelay GO Agent v1.0")

	cfg := loadConfig()

	// --- Étape 1 : Clef privée RSA ---
	privKey, err := loadOrGenerateKey(cfg)
	if err != nil {
		log.Fatalf("[FATAL] RSA key error: %v", err)
	}

	// --- Étape 2 : Hostname ---
	hostname := cfg.hostname
	if hostname == "" {
		agentFacts := facts.Collect()
		hostname = agentFacts.Hostname
		log.Printf("[INIT] Hostname auto-detected: %s — OS: %s — CPUs: %d — RAM: %dMB",
			hostname, agentFacts.OSFamily, agentFacts.CPUCount, agentFacts.MemoryTotalMB)
	} else {
		log.Printf("[INIT] Hostname (env): %s", hostname)
	}

	// --- Étape 3 : JWT — reload ou enrollment ---
	jwt, err := loadOrEnroll(cfg, hostname, privKey)
	if err != nil {
		log.Fatalf("[FATAL] Enrollment failed: %v", err)
	}
	log.Printf("[OK] JWT obtained (len=%d)", len(jwt))

	// --- Étape 4 : Registre async ---
	reg, err := registry.New(cfg.asyncDir + "/jobs.json")
	if err != nil {
		log.Fatalf("[FATAL] Cannot init async registry: %v", err)
	}
	if err := reg.RestoreOnRestart(); err != nil {
		log.Printf("[WARN] Registry restore error: %v", err)
	}

	// --- Étape 5 : WebSocket dispatcher ---
	handler := &agentHandler{
		exec:     executor.New(),
		registry: reg,
	}

	dispatcher := ws.NewDispatcher(ws.ConnConfig{
		ServerURL: cfg.wsURL,
		JWT:       jwt,
		CABundle:  cfg.caBundle,
		Insecure:  cfg.insecure,
	}, handler, cfg.maxConcurrentTasks).WithEnrollConfig(ws.EnrollConfig{
		RegisterURL: cfg.serverURL + "/api/register",
		Hostname:    hostname,
		PrivateKey:  privKey,
		JWTPath:     cfg.jwtPath,
		MaxRetries:  3,
	})

	// --- Étape 6 : Signal handling + run loop ---
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	log.Printf("[INIT] Connecting to %s", cfg.wsURL)
	if err := dispatcher.Run(ctx); err != nil {
		log.Printf("[SHUTDOWN] Dispatcher stopped: %v", err)
	}

	log.Printf("[OK] Agent shutdown complete")
}

// ---------------------------------------------------------------------------
// RSA Keypair management
// ---------------------------------------------------------------------------

// loadOrGenerateKey charge la clef privée depuis le disque.
// Si le fichier n'existe pas, génère une nouvelle paire RSA-4096 et la persiste.
func loadOrGenerateKey(cfg agentConfig) (*rsa.PrivateKey, error) {
	key, err := enrollment.LoadPrivateKeyFromFile(cfg.privateKeyPath)
	if err == nil {
		log.Printf("[INIT] Private key loaded from %s", cfg.privateKeyPath)
		return key, nil
	}

	// Fichier absent → génère une nouvelle clef
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err // erreur de lecture autre que "not found" → fatale
	}

	log.Printf("[INIT] No private key at %s — generating RSA-4096 keypair...", cfg.privateKeyPath)
	key, err = enrollment.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	// Persiste la clef privée avec mode 0600 atomique
	if err := enrollment.StorePrivateKey(key, cfg.privateKeyPath); err != nil {
		return nil, err
	}
	log.Printf("[OK] RSA-4096 keypair generated and stored at %s", cfg.privateKeyPath)
	return key, nil
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

// loadOrEnroll retourne le JWT existant si présent, sinon effectue l'enrollment.
// L'enrollment appelle POST /api/register et déchiffre le JWT avec la clef privée.
func loadOrEnroll(cfg agentConfig, hostname string, privKey *rsa.PrivateKey) (string, error) {
	// Tente de recharger le JWT existant
	if data, err := os.ReadFile(cfg.jwtPath); err == nil && len(data) > 0 {
		token := string(data)
		log.Printf("[INIT] Existing JWT loaded from %s", cfg.jwtPath)
		return token, nil
	}

	log.Printf("[INIT] No JWT found — enrolling with %s", cfg.serverURL)

	pubPEM, err := enrollment.PublicKeyPEM(privKey)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return enrollment.Enroll(ctx, enrollment.Config{
		RegisterURL:  cfg.serverURL + "/api/register",
		Hostname:     hostname,
		PublicKeyPEM: pubPEM,
		PrivateKey:   privKey,
		CABundle:     cfg.caBundle,
		JWTPath:      cfg.jwtPath,
		Insecure:     cfg.insecure,
	})
}

// ---------------------------------------------------------------------------
// WebSocket message handler
// ---------------------------------------------------------------------------

// agentHandler implémente ws.MessageHandler en déléguant aux packages internes.
type agentHandler struct {
	exec     *executor.Executor
	registry *registry.Registry
}

func (h *agentHandler) HandleExec(ctx context.Context, msg ws.ExecMsg, send ws.SendFunc) error {
	// Ack immédiat avant de bloquer sur le subprocess
	_ = send(map[string]any{
		"task_id": msg.TaskID,
		"type":    "ack",
		"status":  "running",
	})

	result := h.exec.Run(ctx, executor.ExecRequest{
		TaskID:    msg.TaskID,
		Cmd:       msg.Cmd,
		StdinB64:  msg.Stdin,
		Timeout:   msg.Timeout,
		Become:    msg.Become,
		ExpiresAt: msg.ExpiresAt,
	})

	return send(map[string]any{
		"task_id":   result.TaskID,
		"type":      "result",
		"rc":        result.RC,
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
		"truncated": result.Truncated,
	})
}

func (h *agentHandler) HandlePutFile(ctx context.Context, msg ws.PutFileMsg, send ws.SendFunc) error {
	err := files.PutFile(files.PutFileRequest{
		TaskID:  msg.TaskID,
		Dest:    msg.Dest,
		DataB64: msg.Data,
		Mode:    msg.Mode,
	})
	if err != nil {
		return send(map[string]any{
			"task_id":   msg.TaskID,
			"type":      "result",
			"rc":        -1,
			"stdout":    "",
			"stderr":    err.Error(),
			"truncated": false,
		})
	}
	return send(map[string]any{
		"task_id":   msg.TaskID,
		"type":      "result",
		"rc":        0,
		"stdout":    "",
		"stderr":    "",
		"truncated": false,
	})
}

func (h *agentHandler) HandleFetchFile(ctx context.Context, msg ws.FetchFileMsg, send ws.SendFunc) error {
	data, err := files.FetchFile(files.FetchFileRequest{
		TaskID: msg.TaskID,
		Src:    msg.Src,
	})
	if err != nil {
		return send(map[string]any{
			"task_id":   msg.TaskID,
			"type":      "result",
			"rc":        -1,
			"data":      "",
			"stderr":    err.Error(),
			"truncated": false,
		})
	}
	return send(map[string]any{
		"task_id":   msg.TaskID,
		"type":      "result",
		"rc":        0,
		"data":      data,
		"truncated": false,
	})
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type agentConfig struct {
	serverURL        string
	wsURL            string
	hostname         string
	privateKeyPath   string
	jwtPath          string
	caBundle         string
	asyncDir         string
	insecure         bool // TESTS UNIQUEMENT — désactive TLS verification
	maxConcurrentTasks int
}

func loadConfig() agentConfig {
	maxTasks := 10
	if v := os.Getenv("MAX_CONCURRENT_TASKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxTasks = n
		}
	}
	cfg := agentConfig{
		serverURL:          getenv("RELAY_SERVER_URL", "https://localhost:7770"),
		wsURL:              getenv("RELAY_WS_URL", "wss://localhost:7772/ws/agent"),
		hostname:           getenv("RELAY_AGENT_HOSTNAME", ""),
		privateKeyPath:     getenv("RELAY_PRIVATE_KEY", "/etc/relay-agent/id_rsa"),
		jwtPath:            getenv("RELAY_JWT_PATH", "/etc/relay-agent/token.jwt"),
		caBundle:           getenv("RELAY_CA_BUNDLE", ""),
		asyncDir:           getenv("RELAY_ASYNC_DIR", "/var/lib/relay-agent/async"),
		insecure:           getenv("RELAY_INSECURE_TLS", "") == "true",
		maxConcurrentTasks: maxTasks,
	}
	if cfg.insecure {
		log.Printf("[WARN] RELAY_INSECURE_TLS=true — TLS verification disabled (tests only)")
	}
	log.Printf("[INIT] server=%s ws=%s key=%s jwt=%s maxTasks=%d",
		cfg.serverURL, cfg.wsURL, cfg.privateKeyPath, cfg.jwtPath, cfg.maxConcurrentTasks)
	return cfg
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
