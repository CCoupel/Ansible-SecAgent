package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIsVersionFlag(t *testing.T) {
	tests := map[string]bool{"--version": true, "-v": true, "--list": false, "--host": false, "-V": false, "": false}
	for arg, want := range tests {
		if got := isVersionFlag(arg); got != want {
			t.Errorf("isVersionFlag(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want \"dev\" without ldflags injection", Version)
	}
}

// TestVersionFlagBinary compile le binaire avec -ldflags -X main.Version et vérifie la sortie,
// sans variable d'environnement ni réseau.
func TestVersionFlagBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("compilation du binaire")
	}
	bin := t.TempDir() + "/inv"
	build := exec.Command("go", "build", "-ldflags", "-X main.Version=9.9.9-test", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, flag := range []string{"--version", "-v"} {
		cmd := exec.Command(bin, flag)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "RELAY_SERVER_URL=http://127.0.0.1:1"}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v (stderr %q)", flag, err, stderr.String())
		}
		if got := string(out); got != "secagent-inventory version 9.9.9-test\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n" {
			t.Errorf("%s: stdout = %q", flag, got)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: stderr non vide: %q", flag, stderr.String())
		}
	}
}

// TestVersionFlagExtraArg : un argument en trop avec --version/-v ⇒ rc 1 et message sur stderr (aligné serveur/minion).
func TestVersionFlagExtraArg(t *testing.T) {
	if testing.Short() {
		t.Skip("compilation du binaire")
	}
	bin := t.TempDir() + "/inv"
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, flag := range []string{"--version", "-v"} {
		cmd := exec.Command(bin, flag, "extra")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 1 {
			t.Fatalf("%s extra: err = %v, want exit code 1", flag, err)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s extra: stdout non vide: %q", flag, stdout.String())
		}
		if !strings.Contains(stderr.String(), "unexpected argument") {
			t.Errorf("%s extra: stderr = %q", flag, stderr.String())
		}
	}
}
