// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantRun    bool
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring
	}{
		{"no argument starts the agent", nil, true, 0, "", ""},
		{"empty slice starts the agent", []string{}, true, 0, "", ""},
		{"--version", []string{"--version"}, false, 0, "secagent-minion version dev\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n", ""},
		{"-v", []string{"-v"}, false, 0, "secagent-minion version dev\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n", ""},
		{"--help", []string{"--help"}, false, 0, "Usage:", ""},
		{"-h", []string{"-h"}, false, 0, "RELAY_ENROLLMENT_TOKEN", ""},
		{"unknown word", []string{"kyes"}, false, 1, "", "unexpected argument"},
		{"-d", []string{"-d"}, false, 1, "", "unexpected argument"},
		{"--config x", []string{"--config", "x"}, false, 1, "", "unexpected argument"},
		{"7770", []string{"7770"}, false, 1, "", "unexpected argument"},
		{"--version extra", []string{"--version", "extra"}, false, 1, "", "unexpected argument"},
		{"--help --version", []string{"--help", "--version"}, false, 1, "", "unexpected argument"},
		{"several arguments", []string{"a", "b", "c"}, false, 1, "", "(3 given)"},
		{"empty string argument", []string{""}, false, 1, "", "unexpected argument"},
		{"--Version (case)", []string{"--Version"}, false, 1, "", "unexpected argument"},
		{"--version=1", []string{"--version=1"}, false, 1, "", "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			run, code := handleArgs(tt.args, &out, &errb)
			if run != tt.wantRun || code != tt.wantCode {
				t.Fatalf("run=%v code=%d, want run=%v code=%d", run, code, tt.wantRun, tt.wantCode)
			}
			if !strings.Contains(out.String(), tt.wantStdout) || !strings.Contains(errb.String(), tt.wantStderr) {
				t.Fatalf("stdout=%q stderr=%q", out.String(), errb.String())
			}
			if tt.wantRun && (out.Len() != 0 || errb.Len() != 0) {
				t.Fatal("starting the agent must print nothing here")
			}
			if tt.wantCode == 1 && (out.Len() != 0 || !strings.Contains(errb.String(), "Usage:")) {
				t.Fatalf("a refusal writes the error and the help on stderr only: out=%q", out.String())
			}
		})
	}
}

// An argument can be a secret typed by mistake: it is never echoed.
func TestHandleArgs_NeverEchoesTheArgument(t *testing.T) {
	var out, errb bytes.Buffer
	handleArgs([]string{"--token", "secagent_enr_TOPSECRET"}, &out, &errb)
	if strings.Contains(out.String()+errb.String(), "TOPSECRET") || strings.Contains(out.String()+errb.String(), "--token") {
		t.Fatalf("the argument was echoed: %q %q", out.String(), errb.String())
	}
}

func TestVersionIsOverridable(t *testing.T) {
	old := Version
	Version = "3.0.4"
	defer func() { Version = old }()
	var out, errb bytes.Buffer
	handleArgs([]string{"--version"}, &out, &errb)
	if out.String() != "secagent-minion version 3.0.4\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestInitBannerCarriesTheInjectedVersion(t *testing.T) {
	old := Version
	Version = "3.0.5"
	defer func() { Version = old }()
	if got, want := initBanner(), "[INIT] Ansible-SecAgent GO Agent 3.0.5"; got != want {
		t.Errorf("initBanner() = %q, want %q", got, want)
	}
	if strings.Contains(initBanner(), "v1.0") {
		t.Error("hard-coded v1.0 still in the banner")
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

func TestVersionThreeExactLines(t *testing.T) {
	old := Version
	Version = "3.0.5"
	defer func() { Version = old }()
	for _, a := range []string{"--version", "-v"} {
		var out, errb bytes.Buffer
		proceed, code := handleArgs([]string{a}, &out, &errb)
		if proceed || code != 0 {
			t.Fatalf("%s: proceed=%v code=%d, want false/0", a, proceed, code)
		}
		assertVersionThreeLines(t, a, out.String(), errb.String(), "secagent-minion", "3.0.5")
	}
}
