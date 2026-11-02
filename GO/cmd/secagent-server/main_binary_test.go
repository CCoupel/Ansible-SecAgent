package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/cli"
)

// Builds the real binary and checks that CLI sub-commands answer instead of starting a server
// (the dispatch of main was untested: `keys …` once started a server).
func TestBinary_CLICommandsDoNotStartAServer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "secagent-server")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cases := []struct {
		args    []string
		wantOut string
		wantErr bool
	}{
		{[]string{"keys", "link-status", "--help"}, "link-status", false},
		{[]string{"keys", "rotate-link", "--help"}, "rotate-link", false},
		{[]string{"state", "link-trust", "reset", "--help"}, "reset", false},
		{[]string{"state", "rekey", "--help"}, "NEW_RSA_MASTER_KEY", false},
		{[]string{"tokens", "create", "--help"}, "relay-child", false},
		{[]string{"--help"}, "Usage", false},
		{[]string{"-h"}, "Usage", false},
		{[]string{"--version"}, "secagent-server version", false},
		{[]string{"kyes"}, "unknown command", true},
		{[]string{"-d"}, "unknown shorthand flag", true},
		{[]string{"--config", "/etc/relay.conf"}, "unknown flag", true},
		{[]string{"7770"}, "unknown command", true},
		{[]string{"relays", "add", "--help"}, "relay-child", false},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, "_"), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, c.args...)
			cmd.Env = append(os.Environ(), "JWT_SECRET_KEY=test", "ADMIN_TOKEN=test", "RELAY_API_URL=http://127.0.0.1:1")
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("timeout: the binary probably started a server\n%s", out)
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v (wantErr %v)\n%s", err, c.wantErr, out)
			}
			if !strings.Contains(string(out), c.wantOut) || strings.Contains(string(out), "promoted to master") {
				t.Errorf("unexpected output:\n%s", out)
			}
		})
	}
}

// No argument = server mode: with an empty environment it reaches the server configuration check
// (TLS_CERT/TLS_KEY required) and exits, without printing the CLI help.
func TestBinary_NoArgumentIsServerMode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "secagent-server")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "TLS is required") || strings.Contains(string(out), "Usage") {
		t.Errorf("expected the server start-up path (config error), got err=%v\n%s", err, out)
	}
}

// Replaces the vacuous TestIsCLIMode_EveryRegisteredCommand (#221): isCLIMode is true for ANY argument, so
// the question is not "does main pick the CLI" but "does a registered command ever start a server". The
// list comes from cobra; each top-level command is run with --help on the real binary, which must answer
// with its usage and exit 0 within the timeout. A command that started a server would hang (timeout) or print the
// promotion line; a command missing from the CLI never shows up in the list.
func TestBinary_EveryRegisteredCommandAnswersHelpAndStartsNoServer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	names := cli.CommandNames()
	if len(names) < 8 {
		t.Fatalf("suspicious command list: %v", names)
	}
	bin := filepath.Join(t.TempDir(), "secagent-server")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, name, "--help")
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("timeout: %q probably started a server\n%s", name, out)
			}
			if err != nil || !strings.Contains(string(out), "Usage:") || strings.Contains(string(out), "promoted to master") {
				t.Errorf("%s --help: err=%v\n%s", name, err, out)
			}
		})
	}
}

// #221: no symbol of the test helpers (store on a temporary state, insecure test mode) is in the server binary.
func TestBinary_HasNoTestHelperSymbols(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "secagent-server")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command("go", "tool", "nm", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	for _, sym := range []string{"OpenTemp", "OpenTestDir", "storagetest", "testsupport"} {
		if strings.Contains(string(out), sym) {
			t.Errorf("the server binary contains a test helper symbol %q", sym)
		}
	}
}
