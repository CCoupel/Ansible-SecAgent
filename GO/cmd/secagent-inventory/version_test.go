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
		if got := string(out); got != "secagent-inventory version 9.9.9-test\n" {
			t.Errorf("%s: stdout = %q", flag, got)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: stderr non vide: %q", flag, stderr.String())
		}
	}
}
