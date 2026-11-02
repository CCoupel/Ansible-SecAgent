package cli

import (
	"strings"
	"testing"
)

// #220 / D5: --version prints the version and exits 0; an extra argument is an error (exit 1), as in the minion.
func TestRootVersion(t *testing.T) {
	for _, a := range []string{"--version", "-v"} {
		out, _, code := runCLI(t, a)
		if code != 0 || !strings.Contains(out, "secagent-server version ") {
			t.Errorf("%s: exit %d out %q", a, code, out)
		}
	}
	if _, errOut, code := runCLI(t, "--version", "extra"); code != 1 || errOut == "" {
		t.Errorf("--version extra: exit %d stderr %q, want 1 and a message", code, errOut)
	}
	if _, _, code := runCLI(t, "kyes"); code != 1 {
		t.Errorf("unknown top-level word: exit %d, want 1", code)
	}
}
