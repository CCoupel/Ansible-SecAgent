package cli

import (
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
