// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"strings"
	"testing"
)

// #220 / D5: --version prints the version and exits 0; an extra argument is an error (exit 1), as in the minion.
func TestRootVersion(t *testing.T) {
	for _, a := range []string{"--version", "-v"} {
		out, _, code := runCLI(t, a)
		want := "secagent-server version " + Version + "\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n"
		if code != 0 || out != want {
			t.Errorf("%s: exit %d out %q, want %q", a, code, out, want)
		}
	}
	if _, errOut, code := runCLI(t, "--version", "extra"); code != 1 || errOut == "" {
		t.Errorf("--version extra: exit %d stderr %q, want 1 and a message", code, errOut)
	}
	if _, _, code := runCLI(t, "kyes"); code != 1 {
		t.Errorf("unknown top-level word: exit %d, want 1", code)
	}
}

// assertVersionThreeLines: exactly 3 lines, line 1 = "<component> version <version>", nothing after the last \n.
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

func TestRootVersionThreeExactLines(t *testing.T) {
	for _, a := range []string{"--version", "-v"} {
		out, errOut, code := runCLI(t, a)
		if code != 0 {
			t.Fatalf("%s: exit %d", a, code)
		}
		assertVersionThreeLines(t, a, out, errOut, "secagent-server", Version)
	}
}
