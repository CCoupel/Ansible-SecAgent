// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// #214 (v3.0.5, D2) — the server REFUSES TO START with an RSA_MASTER_KEY shorter than 32 bytes
// (configuration read or Build, whichever the implementation chose: the contract is "the start is
// refused before anything is served"), with the remedy in the message, the key nowhere in the logs,
// and the state untouched. A key of 32 bytes or more starts the node as before.

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/state"
)

// startWithMasterKey drives the real start sequence (ConfigFromEnv then Build) with key as
// RSA_MASTER_KEY over stateDir, and returns the logs plus the refusal (nil when the node was built).
func startWithMasterKey(t *testing.T, stateDir, key string) (string, error) {
	t.Helper()
	setServerEnv(t)
	t.Setenv("RSA_MASTER_KEY", key)
	t.Setenv("STATE_DIR", stateDir)
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	t.Setenv("RELAY_ACTION_LOG", t.TempDir()+"/actions.log")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	cfg, err := ConfigFromEnv()
	if err != nil {
		return buf.String(), err
	}
	cfg.AdminAddr = "127.0.0.1:0"
	cfg.WriteGuard = allowWrites
	n, err := Build(cfg)
	if err == nil {
		n.Close()
	}
	return buf.String(), err
}

func newLongKeyState(t *testing.T, key string) string {
	t.Helper()
	dir := t.TempDir()
	if err := state.Init(state.InitOptions{Dir: dir, MasterKey: key, RSABits: 2048}); err != nil {
		t.Fatalf("fixture state: %v", err)
	}
	return dir
}

// (critical) short key: refused, remedy present, key not in the error nor in the logs, state untouched.
func TestSpec214_ServerRefusesToStartWithAShortMasterKey(t *testing.T) {
	long := varKey(48)
	dir := newLongKeyState(t, long)
	before, err := os.ReadFile(filepath.Join(dir, state.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{8, 31} {
		short := strings.Repeat("s", n)
		logs, err := startWithMasterKey(t, dir, short)
		if err == nil {
			t.Fatalf("%d-byte RSA_MASTER_KEY: the server must refuse to start", n)
		}
		for _, want := range []string{"RSA_MASTER_KEY", "32", "openssl rand -base64 48", "state rekey"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%d bytes: the refusal must contain %q: %v", n, want, err)
			}
		}
		if strings.Contains(err.Error(), short) || strings.Contains(logs, short) {
			t.Errorf("%d bytes: the key leaks (error %q, logs %q)", n, err, logs)
		}
		after, _ := os.ReadFile(filepath.Join(dir, state.StateFile))
		if !bytes.Equal(before, after) {
			t.Errorf("%d bytes: relay.state changed on a refused start", n)
		}
		if _, statErr := os.Stat(filepath.Join(dir, state.LockFile)); statErr == nil {
			t.Errorf("%d bytes: a refused start must not take the master lock", n)
		}
	}
}

// 32 bytes and more start (the state of a v3.0.4 deployment with such a key is read unchanged).
func TestSpec214_ServerStartsWithA32BytesOrLongerMasterKey(t *testing.T) {
	for _, n := range []int{32, 48} {
		key := varKey(n)
		dir := newLongKeyState(t, key)
		if logs, err := startWithMasterKey(t, dir, key); err != nil {
			t.Errorf("%d bytes: the server must start: %v\n%s", n, err, logs)
		} else if strings.Contains(logs, key) {
			t.Errorf("%d bytes: the master key is in the logs", n)
		}
	}
}

// The key is never in the logs of a normal start either (RSA_MASTER_KEY and its _FILE variant).
func TestSpec214_MasterKeyIsNeverLoggedAtStart(t *testing.T) {
	key := varKey(40)
	dir := newLongKeyState(t, key)
	if logs, err := startWithMasterKey(t, dir, key); err != nil {
		t.Fatal(err)
	} else if strings.Contains(logs, key) || strings.Contains(logs, "ZZZZZZZZ") {
		t.Errorf("the master key (or a fragment) is in the start logs:\n%s", logs)
	}
}

// M6 (security review): a key read from RSA_MASTER_KEY_FILE is measured after the single trailing newline
// is removed: 32 real bytes + "\n" are accepted, 31 + "\n" (32 bytes on disk) are refused.
func TestSpec214_MasterKeyFileIsMeasuredWithoutItsTrailingNewline(t *testing.T) {
	for _, c := range []struct {
		name    string
		content string
		refused bool
	}{
		{"32 bytes + newline", varKey(32) + "\n", false},
		{"31 bytes + newline (32 on disk)", strings.Repeat("f", 31) + "\n", true},
		{"32 bytes without newline", varKey(32), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setServerEnv(t)
			path := filepath.Join(t.TempDir(), "master.key")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RSA_MASTER_KEY", "")
			t.Setenv("RSA_MASTER_KEY_FILE", path)
			_, err := ConfigFromEnv()
			if (err != nil) != c.refused {
				t.Fatalf("refused=%v, want %v (%v)", err != nil, c.refused, err)
			}
		})
	}
}

// varKey returns a non-predictable test master key of n bytes (the key rules refuse repeated characters and patterns).
func varKey(n int) string {
	const src = "Tq9vXr2LmZk8WcYb4HnJ7sUd1EoGfAp5iBx3NtVw6QyKzRaMlSjCh0e+/=PdFgIuOl"
	out := make([]byte, n)
	for i := range out {
		out[i] = src[(i*7+i/len(src))%len(src)]
	}
	return string(out)
}
