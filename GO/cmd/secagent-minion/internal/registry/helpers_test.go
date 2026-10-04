package registry

import (
	"os"
	"testing"
)

// mustWriteFile creates or overwrites a file with given content. Fatals the test on error.
func mustWriteFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", path, err)
	}
}

// mustRegisterJob registers a job and fatals the test if an error occurs.
func mustRegisterJob(t *testing.T, r *Registry, jid string, pid int, cmd string, timeout int, stdoutPath string) {
	t.Helper()
	if err := r.RegisterJob(jid, pid, cmd, timeout, stdoutPath); err != nil {
		t.Fatalf("RegisterJob(%q): %v", jid, err)
	}
}

// mustUpdateJob updates a job and fatals the test if an error occurs.
func mustUpdateJob(t *testing.T, r *Registry, jid string, finished bool, rc int) {
	t.Helper()
	if err := r.UpdateJob(jid, finished, rc); err != nil {
		t.Fatalf("UpdateJob(%q): %v", jid, err)
	}
}

// mustRemoveJob removes a job and fatals the test if an error occurs.
func mustRemoveJob(t *testing.T, r *Registry, jid string) {
	t.Helper()
	if err := r.RemoveJob(jid); err != nil {
		t.Fatalf("RemoveJob(%q): %v", jid, err)
	}
}

// mustCheckAndKillExpired checks and kills expired jobs, fataling the test on error.
func mustCheckAndKillExpired(t *testing.T, r *Registry) {
	t.Helper()
	if err := r.CheckAndKillExpired(); err != nil {
		t.Fatalf("CheckAndKillExpired: %v", err)
	}
}
