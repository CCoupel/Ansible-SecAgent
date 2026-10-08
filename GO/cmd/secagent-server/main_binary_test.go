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
		{[]string{"tokens", "create", "--help"}, "relay-child", false},
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
