package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #185: on a real node started with the server secrets in its environment, a shell hook that dumps
// its environment sees none of them — only the allow-list, the event variables and its own env.
func TestHooksShellEnvironmentIsAnAllowList(t *testing.T) {
	parallel(t)
	var envOut string
	n := startNode(t, nodeSpec{
		ID:  "envnode",
		Env: []string{"FOO=server-only-value", "SOME_SERVICE_SECRET=server-only-secret"},
		Hooks: func(out string) string {
			envOut = filepath.Join(filepath.Dir(out), "shell-env.out")
			return `{"hooks":[{"event":"host.up","actions":[{"type":"shell","cmd":"/bin/sh","args":["-c","env > ` + envOut + `"],` +
				`"timeout_seconds":10,"env":{"HOOK_OWN_TOKEN":"own-{{hostname}}"}}]}]}`
		},
	})
	connectMinion(t, n, "env-host")
	waitFor(t, "the shell hook ran", func() bool { b, _ := os.ReadFile(envOut); return strings.Contains(string(b), "SECAGENT_EVENT=") })
	b, _ := os.ReadFile(envOut)
	text := string(b)
	for _, leak := range []string{n.adminTok, n.jwtSecret, "integration-master-key-envnode", "server-only-value", "server-only-secret",
		"ADMIN_TOKEN", "JWT_SECRET_KEY", "RSA_MASTER_KEY", "REPEATER_UPSTREAM_TOKEN", "FOO="} {
		if strings.Contains(text, leak) {
			t.Errorf("the hook process sees %q:\n%s", leak, text)
		}
	}
	for _, want := range []string{"SECAGENT_EVENT=host.up", "SECAGENT_HOSTNAME=env-host", "HOOK_OWN_TOKEN=own-env-host"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q missing:\n%s", want, text)
		}
	}
}
