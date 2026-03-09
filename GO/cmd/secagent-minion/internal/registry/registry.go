// Package registry gère le registre persisté des tâches Ansible async.
//
// Contexte (§10 ARCHITECTURE.md) :
// Les tâches Ansible async sont déclenchées avec `async:` dans un playbook.
// L'agent démarre le subprocess en background, enregistre le job (jid, pid)
// dans un fichier JSON sur disque, et répond immédiatement.
// Ansible interroge ensuite le statut via async_status.
//
// Invariants :
//   - Persistance write-through JSON sur disque (survie aux restarts)
//   - Restauration au démarrage : PIDs morts → finished=true, rc=-1
//   - Sauvegarde atomique via renommage de fichier temporaire
//   - get_async_status retourne le format Ansible (ansible_job_id, finished 0/1, rc, stdout)
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Job représente un enregistrement de tâche async.
type Job struct {
	JID        string    `json:"jid"`
	PID        int       `json:"pid"`
	Cmd        string    `json:"cmd"`
	Timeout    int       `json:"timeout"`
	StdoutPath string    `json:"stdout_path"`
	StartedAt  time.Time `json:"started_at"`
	Finished   bool      `json:"finished"`
	RC         int       `json:"rc"`
}

// AsyncStatus est le format retourné par get_async_status (compatible Ansible).
type AsyncStatus struct {
	AnsibleJobID string `json:"ansible_job_id"`
	Finished     int    `json:"finished"` // 0 = en cours, 1 = terminé
	RC           int    `json:"rc,omitempty"`
	Stdout       string `json:"stdout,omitempty"`
	Failed       bool   `json:"failed,omitempty"`
	Msg          string `json:"msg,omitempty"`
}

// Registry est le registre persisté des jobs async.
type Registry struct {
	mu       sync.Mutex
	jobsFile string
	jobs     map[string]*Job
}

// New crée un Registry qui persiste les jobs dans jobsFile.
// Si le fichier existe, il est chargé au démarrage.
func New(jobsFile string) (*Registry, error) {
	r := &Registry{
		jobsFile: jobsFile,
		jobs:     make(map[string]*Job),
	}
	if _, err := os.Stat(jobsFile); err == nil {
		if err := r.load(); err != nil {
			return nil, fmt.Errorf("registry: load %s: %w", jobsFile, err)
		}
	}
	return r, nil
}

// RegisterJob enregistre une nouvelle tâche async et la persiste sur disque.
func (r *Registry) RegisterJob(jid string, pid int, cmd string, timeout int, stdoutPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.jobs[jid] = &Job{
		JID:        jid,
		PID:        pid,
		Cmd:        cmd,
		Timeout:    timeout,
		StdoutPath: stdoutPath,
		StartedAt:  time.Now(),
		Finished:   false,
		RC:         0,
	}
	return r.save()
}

// GetJob retourne le job identifié par jid, ou nil s'il n'existe pas.
func (r *Registry) GetJob(jid string) *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jid]
	if !ok {
		return nil
	}
	// Retourne une copie pour éviter les races
	cp := *j
	return &cp
}

// UpdateJob met à jour les champs d'un job existant et persiste.
func (r *Registry) UpdateJob(jid string, finished bool, rc int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jid]
	if !ok {
		return fmt.Errorf("registry: job %s not found", jid)
	}
	j.Finished = finished
	j.RC = rc
	return r.save()
}

// RemoveJob supprime un job du registre et persiste.
func (r *Registry) RemoveJob(jid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.jobs, jid)
	return r.save()
}

// CheckJobAlive retourne true si le processus pid est vivant.
// Sur Unix : kill(pid, 0). Sur Windows : OpenProcess + GetExitCodeProcess.
func (r *Registry) CheckJobAlive(pid int) bool {
	return checkPIDAlive(pid)
}

// RestoreOnRestart marque les jobs avec un PID mort comme finished=true, rc=-1.
// Appelé au démarrage pour nettoyer les jobs orphelins.
func (r *Registry) RestoreOnRestart() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	modified := false
	for _, j := range r.jobs {
		if j.Finished {
			continue
		}
		if !r.checkAliveUnlocked(j.PID) {
			j.Finished = true
			j.RC = -1
			modified = true
		}
	}

	if modified {
		return r.save()
	}
	return nil
}

// CheckAndKillExpired envoie SIGTERM aux jobs dont le timeout est dépassé.
func (r *Registry) CheckAndKillExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	modified := false
	for _, j := range r.jobs {
		if j.Finished {
			continue
		}
		deadline := j.StartedAt.Add(time.Duration(j.Timeout) * time.Second)
		if now.After(deadline) {
			proc, err := os.FindProcess(j.PID)
			if err == nil {
				_ = proc.Signal(syscall.SIGTERM)
			}
			j.Finished = true
			j.RC = -15
			modified = true
		}
	}

	if modified {
		return r.save()
	}
	return nil
}

// GetAsyncStatus retourne le statut d'un job au format Ansible async_status.
func (r *Registry) GetAsyncStatus(jid string) (*AsyncStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	j, ok := r.jobs[jid]
	if !ok {
		return &AsyncStatus{
			AnsibleJobID: jid,
			Finished:     1,
			Failed:       true,
			Msg:          fmt.Sprintf("job %s not found", jid),
		}, nil
	}

	status := &AsyncStatus{
		AnsibleJobID: j.JID,
		Finished:     boolToInt(j.Finished),
		RC:           j.RC,
	}

	if j.Finished && j.StdoutPath != "" {
		data, err := os.ReadFile(j.StdoutPath)
		if err == nil {
			status.Stdout = string(data)
		}
	}

	if j.Finished && j.RC != 0 {
		status.Failed = true
	}

	return status, nil
}

// save persiste les jobs dans le fichier JSON de façon atomique (tmp + rename).
// Appelé avec le mutex déjà acquis.
func (r *Registry) save() error {
	if err := os.MkdirAll(filepath.Dir(r.jobsFile), 0755); err != nil {
		return err
	}

	tmp := r.jobsFile + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r.jobs); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, r.jobsFile)
}

// load charge les jobs depuis le fichier JSON.
// Appelé sans le mutex (initialisation uniquement).
func (r *Registry) load() error {
	data, err := os.ReadFile(r.jobsFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &r.jobs)
}

// checkAliveUnlocked est la version sans lock de CheckJobAlive (pour usage interne).
func (r *Registry) checkAliveUnlocked(pid int) bool {
	return checkPIDAlive(pid)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
