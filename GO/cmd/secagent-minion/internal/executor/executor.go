// Package executor gère l'exécution de commandes shell via os/exec.
//
// Responsabilités (§4, §9, §12 ARCHITECTURE.md) :
//   - Spawn d'un subprocess par tâche (isolé, pas de goroutine partagée)
//   - Collecte stdout/stderr avec limite 5 MB (truncation + flag)
//   - Timeout → SIGTERM sur le subprocess, rc=-15
//   - become : stdin injecté (become_pass) — jamais loggué
//   - SIGTERM sur cancel via context annulé
//
// Pattern de communication : ack immédiat puis result final (MVP).
// Streaming stdout (messages "stdout" intermédiaires) : v2.
package executor

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const (
	// StdoutBufferMax est la taille maximale de stdout avant troncature (5 MB).
	StdoutBufferMax = 5 * 1024 * 1024
	// DefaultTimeout est le timeout par défaut pour une commande (30s).
	DefaultTimeout = 30 * time.Second
)

// ExecRequest décrit une commande à exécuter.
type ExecRequest struct {
	// TaskID est l'identifiant de la tâche (pour les logs et les réponses WS).
	TaskID string
	// Cmd est la commande shell à exécuter.
	Cmd string
	// StdinB64 est le stdin encodé en base64 (become_pass, pipelining).
	StdinB64 string
	// Timeout en secondes (0 → DefaultTimeout).
	Timeout int
	// Become indique qu'une élévation de privilèges est requise.
	// Utilisé uniquement pour masquer stdin dans les logs.
	Become bool
	// ExpiresAt est le timestamp UNIX d'expiration de la tâche (0 = pas d'expiration).
	ExpiresAt int64
}

// ExecResult est le résultat d'une exécution.
type ExecResult struct {
	TaskID    string
	RC        int
	Stdout    string
	Stderr    string
	Truncated bool
}

// Executor exécute des commandes shell de façon isolée.
type Executor struct{}

// New crée un Executor.
func New() *Executor { return &Executor{} }

// Run exécute la commande décrite par req et retourne le résultat.
//
// Comportements :
//   - ExpiresAt dépassé → rc=-1, stderr="task expired"
//   - Timeout dépassé → SIGTERM, rc=-15, truncated=true
//   - ctx annulé (cancel message) → process tué, rc=-15
//   - stdout > 5 MB → troncature, truncated=true
func (e *Executor) Run(ctx context.Context, req ExecRequest) ExecResult {
	// Vérification expiration
	if req.ExpiresAt > 0 && time.Now().Unix() > req.ExpiresAt {
		log.Printf("[EXEC] Task %s expired (expires_at=%d)", req.TaskID, req.ExpiresAt)
		return ExecResult{TaskID: req.TaskID, RC: -1, Stderr: "task expired"}
	}

	timeout := DefaultTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	// Décode stdin si fourni
	var stdinBytes []byte
	if req.StdinB64 != "" {
		var err error
		stdinBytes, err = base64.StdEncoding.DecodeString(req.StdinB64)
		if err != nil {
			// Essai avec RawStdEncoding (sans padding)
			stdinBytes, err = base64.RawStdEncoding.DecodeString(req.StdinB64)
			if err != nil {
				log.Printf("[EXEC] Task %s: failed to decode stdin base64: %v", req.TaskID, err)
				stdinBytes = nil
			}
		}
		if req.Become {
			log.Printf("[EXEC] Task %s: become=true, stdin masked (%d bytes)", req.TaskID, len(stdinBytes))
		} else {
			log.Printf("[EXEC] Task %s: stdin provided (%d bytes)", req.TaskID, len(stdinBytes))
		}
	}

	// Créer le contexte avec timeout
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Spawn subprocess via /bin/sh -c (compatibilité Ansible pipelining)
	// Note : la commande provient du relay server authentifié (JWT + WSS).
	// Migration vers exec.CommandContext direct recommandée en v2 (CRITIQUE #3 roadmap).
	cmd := exec.CommandContext(runCtx, "/bin/sh", "-c", req.Cmd)

	if stdinBytes != nil {
		cmd.Stdin = newBytesReader(stdinBytes)
	}

	// Capture stdout et stderr avec limite 5 MB
	var stdoutBuf, stderrBuf limitedBuffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	startErr := cmd.Start()
	if startErr != nil {
		return ExecResult{
			TaskID: req.TaskID,
			RC:     1,
			Stderr: fmt.Sprintf("failed to start command: %v", startErr),
		}
	}

	err := cmd.Wait()
	rc := 0
	truncated := false

	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			rc = -15
			truncated = true
			log.Printf("[EXEC] Task %s: timeout after %s, subprocess terminated", req.TaskID, timeout)
		} else if ctx.Err() != nil {
			rc = -15
			log.Printf("[EXEC] Task %s: cancelled via context", req.TaskID)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			rc = exitErr.ExitCode()
		} else {
			rc = 1
			log.Printf("[EXEC] Task %s: wait error: %v", req.TaskID, err)
		}
	}

	stdout := stdoutBuf.Bytes()
	if len(stdout) > StdoutBufferMax {
		stdout = stdout[:StdoutBufferMax]
		truncated = true
	}

	return ExecResult{
		TaskID:    req.TaskID,
		RC:        rc,
		Stdout:    string(stdout),
		Stderr:    string(stderrBuf.Bytes()),
		Truncated: truncated,
	}
}

// limitedBuffer est un bytes.Buffer avec une limite de taille.
// Au-delà de la limite, les écritures sont ignorées (troncature en post-traitement).
type limitedBuffer struct {
	data []byte
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if remaining := StdoutBufferMax + 1024 - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.data
}

// bytesReader implémente io.Reader sur un slice de bytes.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
