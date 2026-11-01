package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildMinion compiles the REAL binary once per test (optionally with an ldflags version).
func buildMinion(t *testing.T, ldflags string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "secagent-minion")
	args := []string{"build", "-o", bin}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, ".")
	if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// runMinion runs the binary in an isolated data directory; it returns stdout, stderr, the exit code and
// the files left in the data directory.
func runMinion(t *testing.T, bin string, env []string, args ...string) (stdout, stderr string, code int, files []string) {
	t.Helper()
	data := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + data,
		"RELAY_PRIVATE_KEY=" + filepath.Join(data, "id_rsa"),
		"RELAY_JWT_PATH=" + filepath.Join(data, "token.jwt"),
		"RELAY_ASYNC_DIR=" + filepath.Join(data, "async"),
	}, env...)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("timeout: the binary probably started the agent\nstdout=%s\nstderr=%s", so.String(), se.String())
	}
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(data)
	for _, e := range entries {
		files = append(files, e.Name())
	}
	return so.String(), se.String(), code, files
}

func TestBinary_VersionAnswersWithoutStartingAnything(t *testing.T) {
	bin := buildMinion(t, "-X main.Version=9.8.7")
	for _, flag := range []string{"--version", "-v"} {
		out, errOut, code, files := runMinion(t, bin, nil, flag)
		if out != "secagent-minion version 9.8.7\n" || errOut != "" || code != 0 {
			t.Errorf("%s: stdout=%q stderr=%q rc=%d", flag, out, errOut, code)
		}
		if len(files) != 0 {
			t.Errorf("%s: files created in the data directory: %v (a key was generated?)", flag, files)
		}
	}
}

func TestBinary_DefaultVersionIsDev(t *testing.T) {
	out, _, code, _ := runMinion(t, buildMinion(t, ""), nil, "--version")
	if out != "secagent-minion version dev\n" || code != 0 {
		t.Fatalf("stdout=%q rc=%d", out, code)
	}
}

func TestBinary_HelpAnswersWithoutStartingAnything(t *testing.T) {
	bin := buildMinion(t, "")
	for _, flag := range []string{"--help", "-h"} {
		out, errOut, code, files := runMinion(t, bin, nil, flag)
		if code != 0 || !strings.Contains(out, "RELAY_SERVER_URL") || !strings.Contains(out, "--version") || errOut != "" {
			t.Errorf("%s: rc=%d stdout=%q stderr=%q", flag, code, out, errOut)
		}
		if strings.Contains(out, "[INIT]") || len(files) != 0 {
			t.Errorf("%s: something was started: files=%v", flag, files)
		}
	}
}

func TestBinary_AnyOtherArgumentIsRefusedBeforeAnyInitialisation(t *testing.T) {
	bin := buildMinion(t, "")
	for _, args := range [][]string{{"kyes"}, {"-d"}, {"--config", "/etc/x.conf"}, {"7770"}, {"--version", "extra"}, {"--token", "secagent_enr_TOPSECRET"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			out, errOut, code, files := runMinion(t, bin, []string{"RELAY_ENROLLMENT_TOKEN=secagent_enr_x"}, args...)
			if code != 1 || out != "" || !strings.Contains(errOut, "unexpected argument") || !strings.Contains(errOut, "Usage:") {
				t.Errorf("rc=%d stdout=%q stderr=%q", code, out, errOut)
			}
			all := out + errOut
			if strings.Contains(all, "[INIT]") || strings.Contains(all, "[FATAL]") || strings.Contains(all, "enrollment_token=") || strings.Contains(all, "generat") || strings.Contains(all, "TOPSECRET") {
				t.Errorf("initialisation output or echoed argument:\n%s", all)
			}
			if len(files) != 0 {
				t.Errorf("files created: %v", files)
			}
		})
	}
}

// No argument = the agent starts (here it stops at the configuration check: mismatched address lists),
// so the start-up path is reached; nothing is dialed.
func TestBinary_NoArgumentReachesTheStartupPath(t *testing.T) {
	bin := buildMinion(t, "")
	_, errOut, code, _ := runMinion(t, bin, []string{
		"RELAY_SERVER_URL=https://a.invalid:7770,https://b.invalid:7770", "RELAY_WS_URL=wss://a.invalid:7772/ws/agent",
	})
	if code == 0 || !strings.Contains(errOut, "[INIT] Ansible-SecAgent GO Agent") || !strings.Contains(errOut, "[FATAL]") || strings.Contains(errOut, "Usage:") {
		t.Fatalf("rc=%d stderr=%q", code, errOut)
	}
}
