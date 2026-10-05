package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// SIGHUP semantics (Node.ReloadHooks): a hooks file that does not load is refused AS A WHOLE and the
// configuration in force keeps firing (fail closed); a valid file replaces it.
func TestReloadHooks_InvalidFileKeepsThePreviousConfigurationActive(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hooks.out")
	hooksFile := filepath.Join(dir, "hooks.json")
	hook := func(tag string) string {
		return `{"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"` + tag + ` {{hostname}}\n"}]}`
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(hooksFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"hooks":[` + hook("V1") + `]}`)
	n, _, _, _ := startNode(t, func(*Config) { t.Setenv("RELAY_HOOKS_CONFIG", hooksFile) })

	lines := func() []string {
		b, _ := os.ReadFile(out)
		var l []string
		for _, s := range strings.Split(string(b), "\n") {
			if s != "" {
				l = append(l, s)
			}
		}
		return l
	}
	// fire dispatches a local event and waits for its line: events are handled in order, so the line
	// of event N proves what the configuration was when it was processed
	fire := func(host, wantPrefix string) {
		t.Helper()
		before := len(lines())
		hooks.GlobalDispatcher.Dispatch("host.up", host, "connected", "")
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if l := lines(); len(l) > before && strings.HasPrefix(l[len(l)-1], wantPrefix+" "+host) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("host %s: expected a %q line, got %q", host, wantPrefix, lines())
	}

	fire("h0", "V1") // the configuration loaded at start-up fires

	invalid := map[string]string{
		"broken JSON":              `{"hooks":[`,
		"empty relay_chain filter": `{"hooks":[` + hook("V2") + `,{"event":"host.down","filter":{},"actions":[]}]}`,
		"malformed relay id":       `{"hooks":[` + hook("V2") + `,{"event":"host.down","filter":{"relay_chain_contains":"bad id!"},"actions":[]}]}`,
		"relay id injection":       `{"hooks":[` + hook("V2") + `,{"event":"host.down","filter":{"relay_chain_contains":"a;rm -rf /"},"actions":[]}]}`,
		"hook without event":       `{"hooks":[` + hook("V2") + `,{"actions":[]}]}`,
	}
	i := 0
	for name, content := range invalid {
		i++
		write(content)
		n.ReloadHooks() // what SIGHUP does
		fire("kept"+string(rune('a'+i)), "V1")
		for _, l := range lines() {
			if strings.HasPrefix(l, "V2") {
				t.Fatalf("%s: a refused file was (partially) applied: %q", name, lines())
			}
		}
	}

	write(`{"hooks":[` + hook("V3") + `]}`) // a valid file replaces the configuration
	n.ReloadHooks()
	fire("replaced", "V3")
}
