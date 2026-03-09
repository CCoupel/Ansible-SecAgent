//go:build !windows

package registry

import (
	"os"
	"syscall"
)

// checkPIDAlive retourne true si le processus pid est vivant (Unix: kill(pid,0)).
func checkPIDAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM = processus existe mais on n'a pas les droits → vivant
	return err == syscall.EPERM
}
