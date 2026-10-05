package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runStateInit(t *testing.T, dir string, testMode bool) (string, error) {
	t.Helper()
	prevDir, prevMode, prevBits := stateInitDir, stateInitTestMode, stateInitRSABitsFn
	t.Cleanup(func() { stateInitDir, stateInitTestMode, stateInitRSABitsFn = prevDir, prevMode, prevBits })
	stateInitDir, stateInitTestMode = dir, testMode
	stateInitRSABitsFn = func() int { return 2048 }
	var out bytes.Buffer
	stateInitCmd.SetOut(&out)
	err := stateInitCmd.RunE(stateInitCmd, nil)
	return out.String(), err
}

func TestStateInit_CreatesThenRefusesASecondRun(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "cli-test-master-key")
	dir := t.TempDir()
	out, err := runStateInit(t, dir, false)
	if err != nil || !strings.Contains(out, "state initialized in "+dir) {
		t.Fatalf("init: %q %v", out, err)
	}
	if _, err := runStateInit(t, dir, false); err == nil || !strings.Contains(err.Error(), "refusing to initialize") {
		t.Fatalf("second init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "relay.state")); err != nil {
		t.Fatalf("relay.state missing: %v", err)
	}
}

func TestStateInit_WithoutMasterKeyIsRefusedOutsideTestMode(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "")
	if _, err := runStateInit(t, t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "RSA_MASTER_KEY") {
		t.Fatalf("got %v", err)
	}
	if _, err := runStateInit(t, t.TempDir(), true); err != nil {
		t.Fatalf("test mode: %v", err)
	}
}

func TestStateInit_UsesStateDirFromTheEnvironment(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "k")
	dir := t.TempDir()
	t.Setenv("STATE_DIR", dir)
	out, err := runStateInit(t, "", false)
	if err != nil || !strings.Contains(out, dir) {
		t.Fatalf("%q %v", out, err)
	}
}
