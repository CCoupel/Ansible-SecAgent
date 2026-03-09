//go:build windows

package registry

import (
	"os"
	"syscall"
)

const stillActive = 259 // STILL_ACTIVE Windows constant

// checkPIDAlive retourne true si le processus pid est vivant (Windows: OpenProcess + GetExitCodeProcess).
func checkPIDAlive(pid int) bool {
	// OpenProcess avec PROCESS_QUERY_LIMITED_INFORMATION
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		// Si le processus n'existe pas, OpenProcess échoue
		// Cas spécial : pid == current process → toujours vivant
		if os.Getpid() == pid {
			return true
		}
		return false
	}
	defer syscall.CloseHandle(handle)

	var exitCode uint32
	if err := syscall.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
