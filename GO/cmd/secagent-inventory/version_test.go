// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

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
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v (stderr %q)", flag, err, stderr.String())
		}
		assertVersionThreeLines(t, flag, string(out), stderr.String(), "secagent-inventory", "9.9.9-test")
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

// assertVersionThreeLines : exactement 3 lignes, ligne 1 = "<component> version <version>", rien après le dernier \n.
func assertVersionThreeLines(t *testing.T, label, stdout, stderr, component, version string) {
	t.Helper()
	if stderr != "" {
		t.Errorf("%s: stderr = %q, want empty", label, stderr)
	}
	if !strings.HasSuffix(stdout, "\n") || strings.HasSuffix(stdout, "\n\n") {
		t.Errorf("%s: stdout must end with exactly one newline, got %q", label, stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	want := []string{
		component + " version " + version,
		"License: AGPL-3.0-or-later",
		"Source: https://github.com/CCoupel/Ansible-SecAgent",
	}
	if len(lines) != len(want) {
		t.Fatalf("%s: %d lines, want exactly %d: %q", label, len(lines), len(want), stdout)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("%s: line %d = %q, want %q", label, i+1, lines[i], want[i])
		}
	}
}
