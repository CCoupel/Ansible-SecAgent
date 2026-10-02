// Package executor — partie spécifique Unix/Linux.
//
// Ce fichier implémente le kill par groupe de processus pour garantir que les
// petits-fils (grandchildren) spawned par /bin/sh -c "..." sont bien tués lors
// d'un timeout ou d'une annulation de contexte, évitant ainsi que cmd.Wait()
// bloque indéfiniment à cause de pipes maintenus ouverts par des processus orphelins.

//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
	"time"
)

// setupCmdSysProcAttr place le subprocess dans son propre groupe de processus
// (pgid == pid). Cela permet d'envoyer SIGTERM/SIGKILL à l'arbre entier via
// syscall.Kill(-pid, sig) au lieu de tuer uniquement /bin/sh.
func setupCmdSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// setCmdCancel remplace le comportement par défaut de exec.CommandContext
// (Kill du seul processus /bin/sh) par un kill du groupe de processus entier :
//  1. SIGTERM → processus propres (sleep, ansible-playbook...) ont le temps de se terminer.
//  2. Goroutine de sécurité : SIGKILL au groupe après 2 s si SIGTERM ignoré.
//
// cmd.WaitDelay (configuré dans executor.go) joue le rôle de dernier filet de sécurité
// si pour une raison quelconque le groupe ne répond pas.
func setCmdCancel(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		pid := cmd.Process.Pid
		// SIGTERM au groupe de processus (pgid == pid car Setpgid=true)
		if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
			// Groupe déjà disparu ou accès refusé — pas d'erreur fatale.
			return nil
		}
		// Goroutine de sécurité : SIGKILL si SIGTERM ignoré après 2 s.
		go func() {
			time.Sleep(2 * time.Second)
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}()
		return nil
	}
}
