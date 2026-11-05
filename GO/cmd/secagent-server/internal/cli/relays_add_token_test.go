// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

// M14: the push token of `relays add` can come from a file or stdin, never needs argv; --token still works but warns.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const secretToken = "secagent_rp_SECRET-TOKEN-0123456789"

func runCLIStdin(t *testing.T, stdin string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIHelperProcess$")
	cmd.Env = append(os.Environ(), "CLI_HELPER_PROCESS=1", "CLI_HELPER_ARGS="+strings.Join(args, "\x1f"))
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run CLI: %v", err)
		}
		exit = ee.ExitCode()
	}
	return so.String(), se.String(), exit
}

func tokenAPI(t *testing.T) (got func() string) {
	t.Helper()
	var mu sync.Mutex
	var tok string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/admin/relays" {
			var b map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			tok, _ = b["token"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"u1","relay_id":"dmz2","mode":"push","status":"pending"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	return func() string { mu.Lock(); defer mu.Unlock(); return tok }
}

func TestRelaysAdd_TokenFromAFile(t *testing.T) {
	got := tokenAPI(t)
	f := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(f, []byte(secretToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runCLI(t, "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token-file", f)
	if code != 0 || got() != secretToken {
		t.Fatalf("exit %d token %q out=%q err=%q", code, got(), out, errOut)
	}
	if strings.Contains(errOut, "WARNING") || strings.Contains(out+errOut, secretToken) {
		t.Errorf("no warning, and the token must never be printed:\nout=%q err=%q", out, errOut)
	}
}

func TestRelaysAdd_TokenFromStdin(t *testing.T) {
	got := tokenAPI(t)
	out, errOut, code := runCLIStdin(t, secretToken+"\n", "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token-file", "-")
	if code != 0 || got() != secretToken {
		t.Fatalf("exit %d token %q out=%q err=%q", code, got(), out, errOut)
	}
	if _, _, code := runCLIStdin(t, "  \n", "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token-file", "-"); code == 0 {
		t.Error("an empty token on stdin must be refused")
	}
}

func TestRelaysAdd_TokenAndTokenFileTogetherAreRefused(t *testing.T) {
	got := tokenAPI(t)
	f := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(f, []byte(secretToken), 0o600)
	_, errOut, code := runCLI(t, "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token", "x", "--token-file", f)
	if code == 0 || !strings.Contains(errOut, "mutually exclusive") || got() != "" {
		t.Fatalf("exit %d err=%q sent=%q", code, errOut, got())
	}
}

func TestRelaysAdd_TokenFileMustBeProtected(t *testing.T) {
	got := tokenAPI(t)
	f := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(f, []byte(secretToken), 0o644)
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm()&0o077 == 0 {
		t.Skip("this file system does not keep the mode bits (e.g. /mnt/c)")
	}
	out, errOut, code := runCLI(t, "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token-file", f)
	if code == 0 || got() != "" || strings.Contains(out+errOut, secretToken) {
		t.Fatalf("a world-readable token file must be refused, without echoing the token: exit %d sent=%q err=%q", code, got(), errOut)
	}
}

func TestRelaysAdd_TokenOnTheCommandLineStillWorksButWarns(t *testing.T) {
	got := tokenAPI(t)
	_, errOut, code := runCLI(t, "relays", "add", "--id", "dmz2", "--mode", "push", "--url", "wss://dmz2:7772", "--token", secretToken)
	if code != 0 || got() != secretToken {
		t.Fatalf("exit %d token %q", code, got())
	}
	if !strings.Contains(errOut, "WARNING") || !strings.Contains(errOut, "--token-file") || strings.Contains(errOut, secretToken) {
		t.Errorf("a warning pointing at --token-file is expected, without the token:\n%s", errOut)
	}
}
