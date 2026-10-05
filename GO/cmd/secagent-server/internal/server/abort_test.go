package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// After the loss of the lock (Abort) the hooks queue is NOT drained and no queued action runs: the
// events still waiting are dropped, never executed on behalf of a former master.
func TestAbort_QueuedHookActionsNeverRunAndNothingIsDrained(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	hooksFile := filepath.Join(dir, "hooks.json")
	// each event: a 0.4 s shell action THEN a file append; same hostname = one worker = serial
	cfgJSON := `{"hooks":[{"event":"host.up","actions":[` +
		`{"type":"shell","cmd":"/bin/sleep","args":["0.4"],"timeout_seconds":5},` +
		`{"type":"file","path":"` + out + `","append":"ran {{hostname}}\n"}]}]}`
	if err := os.WriteFile(hooksFile, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	n, api, _, _ := startNode(t, func(*Config) { t.Setenv("RELAY_HOOKS_CONFIG", hooksFile) })

	for i := 0; i < 20; i++ {
		hooks.GlobalDispatcher.Dispatch("host.up", "h", "connected", "")
	}
	time.Sleep(150 * time.Millisecond) // the first job is running its sleep

	start := time.Now()
	n.Abort()
	// the process would exit now: Run returns at once (a drain would wait up to hooks.DefaultDrainTimeout)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", api, 200*time.Millisecond); err != nil {
			break
		} else {
			_ = c.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c, err := net.DialTimeout("tcp", api, 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("the listeners must be closed by Abort")
	}
	time.Sleep(1500 * time.Millisecond) // long enough for several queued jobs to have run if they could
	if b, _ := os.ReadFile(out); strings.Contains(string(b), "ran") {
		t.Fatalf("an action ran after the loss of the lock: %q", b)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("abort took %v", time.Since(start))
	}
	n.Abort() // idempotent
}

// The lock is lost DURING the graceful shutdown (SIGTERM already received, hooks being drained): Run
// stops at once with ErrLockLost instead of draining on behalf of a former master.
func TestAbort_LossDuringTheGracefulDrainStopsTheDrain(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	hooksFile := filepath.Join(dir, "hooks.json")
	cfgJSON := `{"hooks":[{"event":"host.up","actions":[` +
		`{"type":"shell","cmd":"/bin/sleep","args":["0.4"],"timeout_seconds":5},` +
		`{"type":"file","path":"` + out + `","append":"ran {{hostname}}\n"}]}]}`
	if err := os.WriteFile(hooksFile, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	n, _, _, _, cancel, done := startNodeCtl(t, func(*Config) { t.Setenv("RELAY_HOOKS_CONFIG", hooksFile) })
	for i := 0; i < 20; i++ { // 20 x 0.4 s on one worker: a drain would take 8 s
		hooks.GlobalDispatcher.Dispatch("host.up", "h", "connected", "")
	}
	time.Sleep(100 * time.Millisecond)
	cancel() // SIGTERM: the graceful path starts, the drain begins
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	n.Abort() // the lock is lost now
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), ErrLockLost.Error()) {
			t.Fatalf("Run returned %v, want ErrLockLost", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run kept draining after the lock was lost")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("stop took %v", time.Since(start))
	}
	time.Sleep(600 * time.Millisecond)
	if b, _ := os.ReadFile(out); strings.Count(string(b), "ran") > 1 {
		t.Errorf("actions kept running after the loss: %q", b)
	}
}
