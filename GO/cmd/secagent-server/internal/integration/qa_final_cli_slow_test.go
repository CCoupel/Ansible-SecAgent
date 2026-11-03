//go:build slow

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// qaBin is the secagent-server binary compiled by the running test (serverBinary); the tests of this file do not
// run in parallel, so a package variable is enough.
var qaBin string

func qaCLI(t *testing.T, n *node, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(qaBin, args...)
	cmd.Env = append(os.Environ(), "RSA_MASTER_KEY=integration-master-key-0123456789-"+n.id, "STATE_DIR="+n.stateDir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out // stdin = /dev/null: non interactive
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code, out.String()
}

func qaStateHash(t *testing.T, n *node) string {
	b, err := os.ReadFile(filepath.Join(n.stateDir, "relay.state"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestQAFinal_LinkTrustResetAndRestoreCLI(t *testing.T) {
	qaBin = serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "child linked", func() bool { return child.upstreamState() == "connected" })

	// (c1) node running -> refused, code 8, state intact
	h0 := qaStateHash(t, child)
	code, out := qaCLI(t, child, "state", "link-trust", "reset", "--yes")
	t.Logf("c1 running node: code=%d out=%q", code, strings.TrimSpace(out))
	if code != 8 || qaStateHash(t, child) != h0 {
		t.Errorf("c1: want code 8 and intact state, got %d", code)
	}
	// (d) state restore on a running node -> refused code 8, intact
	bak := filepath.Join(t.TempDir(), "copy.state")
	b, _ := os.ReadFile(filepath.Join(child.stateDir, "relay.state"))
	_ = os.WriteFile(bak, b, 0o600)
	code, out = qaCLI(t, child, "state", "restore", "--from", bak)
	t.Logf("d  restore on running node: code=%d out=%q", code, strings.TrimSpace(out))
	if code != 8 || qaStateHash(t, child) != h0 {
		t.Errorf("d: want code 8 and intact state, got %d", code)
	}

	child.stop()
	before := child.statePayload()
	if len(before["link_trust"]) < 5 {
		t.Fatalf("child has no persisted link_trust: %s", before["link_trust"])
	}
	h1 := qaStateHash(t, child)
	// (c2) stopped, no --yes, not a TTY -> code 9
	code, out = qaCLI(t, child, "state", "link-trust", "reset")
	t.Logf("c2 without --yes: code=%d out=%q", code, strings.TrimSpace(lastLine(out)))
	if code != 9 || qaStateHash(t, child) != h1 {
		t.Errorf("c2: want code 9 and intact state, got %d", code)
	}
	// (c3) root (signing key present) stopped -> code 9
	root.stop()
	hr := qaStateHash(t, root)
	code, out = qaCLI(t, root, "state", "link-trust", "reset", "--yes")
	t.Logf("c3 on a root: code=%d out=%q", code, strings.TrimSpace(lastLine(out)))
	if code != 9 || qaStateHash(t, root) != hr {
		t.Errorf("c3: want code 9 and intact state, got %d", code)
	}
	// (c4) the real reset
	code, out = qaCLI(t, child, "state", "link-trust", "reset", "--yes")
	t.Logf("c4 reset: code=%d out=%q", code, strings.TrimSpace(out))
	if code != 0 {
		t.Fatalf("c4: code %d", code)
	}
	ents, _ := filepath.Glob(filepath.Join(child.stateDir, "relay.state.linktrust-reset.*.bak"))
	if len(ents) != 1 {
		t.Fatalf("backups: %v", ents)
	}
	fi, _ := os.Stat(ents[0])
	bb, _ := os.ReadFile(ents[0])
	bh := sha256.Sum256(bb)
	t.Logf("backup %s mode=%04o identical-to-previous-state=%v", filepath.Base(ents[0]), fi.Mode().Perm(), hex.EncodeToString(bh[:]) == h1)
	if fi.Mode().Perm() != 0o600 || hex.EncodeToString(bh[:]) != h1 {
		t.Errorf("backup mode/content wrong")
	}
	pv, _ := os.ReadFile(filepath.Join(child.stateDir, "relay.state.prev"))
	pvh := sha256.Sum256(pv)
	jl, _ := os.ReadFile(filepath.Join(child.stateDir, "state-restore.log"))
	t.Logf("relay.state.prev == previous state: %v ; journal mentions link-trust-reset: %v", hex.EncodeToString(pvh[:]) == h1, strings.Contains(string(jl), "link-trust-reset"))
	if hex.EncodeToString(pvh[:]) != h1 || !strings.Contains(string(jl), "link-trust-reset") {
		t.Errorf("prev/journal claims of STATE_SPEC not verified")
	}
	after := child.statePayload()
	for k, v := range before {
		if k == "link_trust" {
			t.Logf("link_trust before=%s after=%s", v, after[k])
			if len(after[k]) > 4 && string(after[k]) != "{}" {
				t.Errorf("link_trust not cleared: %s", after[k])
			}
			continue
		}
		if k == "server_config" {
			continue
		}
		if string(after[k]) != string(v) {
			t.Errorf("section %s changed by the reset", k)
		}
	}
	var sb, sa map[string]string
	_ = json.Unmarshal(before["server_config"], &sb)
	_ = json.Unmarshal(after["server_config"], &sa)
	for k := range sb {
		if _, ok := sa[k]; !ok {
			t.Errorf("server_config key %s lost", k)
		}
	}
	if len(sa) != len(sb) {
		t.Errorf("server_config keys: %d -> %d", len(sb), len(sa))
	}
	if len(after) != len(before) {
		t.Errorf("sections differ: %d vs %d", len(before), len(after))
	}
	code, out = qaCLI(t, child, "state", "verify", filepath.Join(child.stateDir, "relay.state"))
	t.Logf("state verify after reset: code=%d %q", code, strings.TrimSpace(firstLine(out)))
	if code != 0 {
		t.Errorf("verify after reset: %d %s", code, out)
	}
	// (c5) start under a NEW root (new anchor)
	root2 := startNode(t, nodeSpec{ID: "root2"})
	child.setEnv("REPEATER_UPSTREAM_URL", root2.wssURL())
	child.setEnv("REPEATER_UPSTREAM_TOKEN", root2.registerChild("relay1"))
	child.anchorTo(root2)
	child.restart()
	waitFor(t, "child linked to the NEW root", func() bool { return child.upstreamState() == "connected" })
	t.Logf("c5 child re-pinned on root2: upstream=%s", child.upstreamState())
	// restore on the running node again
	h2 := qaStateHash(t, child)
	code, _ = qaCLI(t, child, "state", "restore", "--from", ents[0])
	if code != 8 || qaStateHash(t, child) != h2 {
		t.Errorf("restore on running node after repin: %d", code)
	}
}

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }
func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}
