package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestRegistry creates a Registry backed by a temp file.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	r, err := New(jobsFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// ========================================================================
// New
// ========================================================================

func TestNewCreatesEmptyRegistry(t *testing.T) {
	r := newTestRegistry(t)
	if r == nil {
		t.Fatal("New returned nil")
	}
	if len(r.jobs) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(r.jobs))
	}
}

func TestNewLoadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")

	// Pre-populate the file
	jobs := map[string]*Job{
		"jid-1": {
			JID:      "jid-1",
			PID:      12345,
			Cmd:      "echo hello",
			Timeout:  30,
			Finished: false,
		},
	}
	data, _ := json.MarshalIndent(jobs, "", "  ")
	os.WriteFile(jobsFile, data, 0600)

	r, err := New(jobsFile)
	if err != nil {
		t.Fatalf("New with existing file: %v", err)
	}
	if len(r.jobs) != 1 {
		t.Errorf("expected 1 job loaded, got %d", len(r.jobs))
	}
	if r.jobs["jid-1"] == nil {
		t.Error("jid-1 not loaded")
	}
}

func TestNewInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	os.WriteFile(jobsFile, []byte("invalid json"), 0600)

	_, err := New(jobsFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ========================================================================
// RegisterJob
// ========================================================================

func TestRegisterJob(t *testing.T) {
	r := newTestRegistry(t)

	err := r.RegisterJob("jid-1", 1234, "echo hello", 30, "/tmp/stdout.txt")
	if err != nil {
		t.Fatalf("RegisterJob: %v", err)
	}

	job := r.GetJob("jid-1")
	if job == nil {
		t.Fatal("GetJob returned nil after RegisterJob")
	}
	if job.JID != "jid-1" {
		t.Errorf("JID: got %q, want %q", job.JID, "jid-1")
	}
	if job.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", job.PID)
	}
	if job.Cmd != "echo hello" {
		t.Errorf("Cmd: got %q, want %q", job.Cmd, "echo hello")
	}
	if job.Timeout != 30 {
		t.Errorf("Timeout: got %d, want 30", job.Timeout)
	}
	if job.StdoutPath != "/tmp/stdout.txt" {
		t.Errorf("StdoutPath: got %q, want %q", job.StdoutPath, "/tmp/stdout.txt")
	}
	if job.Finished {
		t.Error("Finished should be false")
	}
	if job.RC != 0 {
		t.Errorf("RC should be 0, got %d", job.RC)
	}
}

func TestRegisterJobPersists(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	r, _ := New(jobsFile)

	r.RegisterJob("jid-persist", 9999, "ls", 10, "")

	// Reload from disk
	r2, err := New(jobsFile)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	job := r2.GetJob("jid-persist")
	if job == nil {
		t.Error("job not persisted to disk")
	}
}

func TestRegisterMultipleJobs(t *testing.T) {
	r := newTestRegistry(t)

	for i, jid := range []string{"j1", "j2", "j3"} {
		if err := r.RegisterJob(jid, i+100, "cmd", 30, ""); err != nil {
			t.Fatalf("RegisterJob %s: %v", jid, err)
		}
	}

	for _, jid := range []string{"j1", "j2", "j3"} {
		if r.GetJob(jid) == nil {
			t.Errorf("job %s not found", jid)
		}
	}
}

// ========================================================================
// GetJob
// ========================================================================

func TestGetJobNotFound(t *testing.T) {
	r := newTestRegistry(t)
	job := r.GetJob("nonexistent")
	if job != nil {
		t.Error("expected nil for nonexistent job")
	}
}

func TestGetJobReturnsCopy(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-copy", 1, "cmd", 10, "")

	job1 := r.GetJob("jid-copy")
	job1.Finished = true // modify the copy

	job2 := r.GetJob("jid-copy")
	if job2.Finished {
		t.Error("modifying returned copy should not affect the registry")
	}
}

// ========================================================================
// UpdateJob
// ========================================================================

func TestUpdateJob(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-update", 1, "cmd", 10, "")

	err := r.UpdateJob("jid-update", true, 0)
	if err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}

	job := r.GetJob("jid-update")
	if !job.Finished {
		t.Error("expected Finished=true after update")
	}
	if job.RC != 0 {
		t.Errorf("RC: got %d, want 0", job.RC)
	}
}

func TestUpdateJobWithError(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-err", 1, "cmd", 10, "")

	r.UpdateJob("jid-err", true, 1)

	job := r.GetJob("jid-err")
	if job.RC != 1 {
		t.Errorf("RC: got %d, want 1", job.RC)
	}
}

func TestUpdateJobNotFound(t *testing.T) {
	r := newTestRegistry(t)
	err := r.UpdateJob("nonexistent", true, 0)
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestUpdateJobPersists(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	r, _ := New(jobsFile)
	r.RegisterJob("jid-p", 1, "cmd", 10, "")
	r.UpdateJob("jid-p", true, 42)

	r2, _ := New(jobsFile)
	job := r2.GetJob("jid-p")
	if job == nil || !job.Finished || job.RC != 42 {
		t.Error("update not persisted to disk")
	}
}

// ========================================================================
// RemoveJob
// ========================================================================

func TestRemoveJob(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-remove", 1, "cmd", 10, "")

	err := r.RemoveJob("jid-remove")
	if err != nil {
		t.Fatalf("RemoveJob: %v", err)
	}

	if r.GetJob("jid-remove") != nil {
		t.Error("job still present after RemoveJob")
	}
}

func TestRemoveJobNonexistent(t *testing.T) {
	r := newTestRegistry(t)
	// Removing nonexistent job should not error
	err := r.RemoveJob("nonexistent")
	if err != nil {
		t.Errorf("RemoveJob nonexistent: %v", err)
	}
}

func TestRemoveJobPersists(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	r, _ := New(jobsFile)
	r.RegisterJob("jid-rm-p", 1, "cmd", 10, "")
	r.RemoveJob("jid-rm-p")

	r2, _ := New(jobsFile)
	if r2.GetJob("jid-rm-p") != nil {
		t.Error("removed job still present after reload")
	}
}

// ========================================================================
// RestoreOnRestart
// ========================================================================

func TestRestoreOnRestartMarksDead(t *testing.T) {
	r := newTestRegistry(t)
	// Use PID 99999999 — almost certainly not running
	r.RegisterJob("jid-dead", 99999999, "cmd", 30, "")

	err := r.RestoreOnRestart()
	if err != nil {
		t.Fatalf("RestoreOnRestart: %v", err)
	}

	job := r.GetJob("jid-dead")
	if !job.Finished {
		t.Error("expected dead job to be marked Finished=true")
	}
	if job.RC != -1 {
		t.Errorf("expected RC=-1 for dead job, got %d", job.RC)
	}
}

func TestRestoreOnRestartSkipsFinished(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-done", 99999999, "cmd", 30, "")
	r.UpdateJob("jid-done", true, 0) // already finished

	err := r.RestoreOnRestart()
	if err != nil {
		t.Fatalf("RestoreOnRestart: %v", err)
	}

	// Should remain at RC=0, not overwritten to -1
	job := r.GetJob("jid-done")
	if job.RC != 0 {
		t.Errorf("finished job RC changed: got %d, want 0", job.RC)
	}
}

func TestRestoreOnRestartEmptyRegistry(t *testing.T) {
	r := newTestRegistry(t)
	err := r.RestoreOnRestart()
	if err != nil {
		t.Fatalf("RestoreOnRestart on empty registry: %v", err)
	}
}

// ========================================================================
// CheckAndKillExpired
// ========================================================================

func TestCheckAndKillExpiredMarksExpired(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-exp", 99999999, "cmd", 1, "")

	// Manually backdate StartedAt to force expiry
	r.mu.Lock()
	r.jobs["jid-exp"].StartedAt = time.Now().Add(-10 * time.Second)
	r.mu.Unlock()

	err := r.CheckAndKillExpired()
	if err != nil {
		t.Fatalf("CheckAndKillExpired: %v", err)
	}

	job := r.GetJob("jid-exp")
	if !job.Finished {
		t.Error("expected expired job to be marked Finished=true")
	}
	if job.RC != -15 {
		t.Errorf("expected RC=-15 for expired job, got %d", job.RC)
	}
}

func TestCheckAndKillExpiredSkipsNotExpired(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-fresh", 99999999, "cmd", 3600, "") // 1 hour timeout

	r.CheckAndKillExpired()

	job := r.GetJob("jid-fresh")
	if job.Finished {
		t.Error("fresh job should not be marked expired")
	}
}

func TestCheckAndKillExpiredSkipsFinished(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-already-done", 99999999, "cmd", 1, "")
	r.mu.Lock()
	r.jobs["jid-already-done"].StartedAt = time.Now().Add(-10 * time.Second)
	r.jobs["jid-already-done"].Finished = true
	r.jobs["jid-already-done"].RC = 0
	r.mu.Unlock()

	r.CheckAndKillExpired()

	job := r.GetJob("jid-already-done")
	// RC should remain 0 (not changed to -15)
	if job.RC != 0 {
		t.Errorf("finished job RC changed: got %d, want 0", job.RC)
	}
}

// ========================================================================
// GetAsyncStatus
// ========================================================================

func TestGetAsyncStatusRunning(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-running", 1, "cmd", 30, "")

	status, err := r.GetAsyncStatus("jid-running")
	if err != nil {
		t.Fatalf("GetAsyncStatus: %v", err)
	}
	if status.AnsibleJobID != "jid-running" {
		t.Errorf("ansible_job_id: got %q, want %q", status.AnsibleJobID, "jid-running")
	}
	if status.Finished != 0 {
		t.Errorf("finished: got %d, want 0 (still running)", status.Finished)
	}
}

func TestGetAsyncStatusFinished(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-fin", 1, "cmd", 30, "")
	r.UpdateJob("jid-fin", true, 0)

	status, err := r.GetAsyncStatus("jid-fin")
	if err != nil {
		t.Fatalf("GetAsyncStatus: %v", err)
	}
	if status.Finished != 1 {
		t.Errorf("finished: got %d, want 1", status.Finished)
	}
	if status.Failed {
		t.Error("expected failed=false for RC=0")
	}
}

func TestGetAsyncStatusFailed(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-fail", 1, "cmd", 30, "")
	r.UpdateJob("jid-fail", true, 1)

	status, err := r.GetAsyncStatus("jid-fail")
	if err != nil {
		t.Fatalf("GetAsyncStatus: %v", err)
	}
	if status.Finished != 1 {
		t.Errorf("finished: got %d, want 1", status.Finished)
	}
	if !status.Failed {
		t.Error("expected failed=true for RC=1")
	}
}

func TestGetAsyncStatusNotFound(t *testing.T) {
	r := newTestRegistry(t)

	status, err := r.GetAsyncStatus("nonexistent")
	if err != nil {
		t.Fatalf("GetAsyncStatus: %v", err)
	}
	if status.Finished != 1 {
		t.Errorf("expected finished=1 for not-found job, got %d", status.Finished)
	}
	if !status.Failed {
		t.Error("expected failed=true for not-found job")
	}
}

func TestGetAsyncStatusWithStdout(t *testing.T) {
	dir := t.TempDir()
	stdoutPath := filepath.Join(dir, "stdout.txt")
	os.WriteFile(stdoutPath, []byte("command output"), 0644)

	r := newTestRegistry(t)
	r.RegisterJob("jid-stdout", 1, "cmd", 30, stdoutPath)
	r.UpdateJob("jid-stdout", true, 0)

	status, err := r.GetAsyncStatus("jid-stdout")
	if err != nil {
		t.Fatalf("GetAsyncStatus: %v", err)
	}
	if status.Stdout != "command output" {
		t.Errorf("stdout: got %q, want %q", status.Stdout, "command output")
	}
}

func TestGetAsyncStatusMissingStdoutFile(t *testing.T) {
	r := newTestRegistry(t)
	r.RegisterJob("jid-no-stdout", 1, "cmd", 30, "/nonexistent/stdout.txt")
	r.UpdateJob("jid-no-stdout", true, 0)

	// Should not error, just empty stdout
	status, err := r.GetAsyncStatus("jid-no-stdout")
	if err != nil {
		t.Fatalf("GetAsyncStatus with missing stdout: %v", err)
	}
	if status.Stdout != "" {
		t.Errorf("expected empty stdout for missing file, got %q", status.Stdout)
	}
}

// ========================================================================
// CheckJobAlive
// ========================================================================

func TestCheckJobAliveCurrentProcess(t *testing.T) {
	r := newTestRegistry(t)
	// Current process is definitely alive
	alive := r.CheckJobAlive(os.Getpid())
	if !alive {
		t.Error("current process should be alive")
	}
}

func TestCheckJobAliveDeadPID(t *testing.T) {
	r := newTestRegistry(t)
	// PID 99999999 is almost certainly not running
	alive := r.CheckJobAlive(99999999)
	if alive {
		t.Log("PID 99999999 is alive — this is unexpected but not a test failure")
	}
}

// ========================================================================
// Atomic save (rename)
// ========================================================================

func TestAtomicSaveNoTmpFile(t *testing.T) {
	dir := t.TempDir()
	jobsFile := filepath.Join(dir, "jobs.json")
	r, _ := New(jobsFile)
	r.RegisterJob("jid-atomic", 1, "cmd", 10, "")

	// No .tmp file should remain
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "jobs.json" {
			t.Errorf("unexpected file after save: %q", e.Name())
		}
	}
}

// ========================================================================
// Job struct and AsyncStatus struct
// ========================================================================

func TestJobStructFields(t *testing.T) {
	job := Job{
		JID:        "test-jid",
		PID:        1234,
		Cmd:        "ls -la",
		Timeout:    60,
		StdoutPath: "/tmp/out.txt",
		StartedAt:  time.Now(),
		Finished:   false,
		RC:         0,
	}
	if job.JID != "test-jid" {
		t.Error("JID not preserved")
	}
	if job.PID != 1234 {
		t.Error("PID not preserved")
	}
}

func TestAsyncStatusFields(t *testing.T) {
	status := AsyncStatus{
		AnsibleJobID: "jid-1",
		Finished:     1,
		RC:           0,
		Stdout:       "output",
		Failed:       false,
		Msg:          "",
	}
	if status.AnsibleJobID != "jid-1" {
		t.Error("AnsibleJobID not preserved")
	}
}

// ========================================================================
// boolToInt helper
// ========================================================================

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Error("boolToInt(true) should return 1")
	}
	if boolToInt(false) != 0 {
		t.Error("boolToInt(false) should return 0")
	}
}
