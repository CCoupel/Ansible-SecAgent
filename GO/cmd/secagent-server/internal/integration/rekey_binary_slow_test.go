//go:build slow

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rekeyCLI(t *testing.T, bin string, n *node, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	base := []string{}
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "RSA_MASTER_KEY") || strings.HasPrefix(e, "NEW_RSA_MASTER_KEY") || strings.HasPrefix(e, "STATE_DIR") {
			continue
		}
		base = append(base, e)
	}
	cmd.Env = append(base, "STATE_DIR="+n.stateDir)
	cmd.Env = append(cmd.Env, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return code, out.String()
}

func rekeyFileHash(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestRekeyBinary_RealNodesRootAndNonRoot(t *testing.T) {
	bin := serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "child linked", func() bool { return child.upstreamState() == "connected" })
	agentTok := root.enrollAgent("agent-r")
	connectMinionWithToken(t, root, "agent-r", agentTok)
	root.mintParentToken("x") // a token minted on the root: the state holds a link registry entry too
	oldRoot, oldChild := "integration-master-key-root", "integration-master-key-relay1"
	newRoot, newChild := "NEWKEY-root-0123456789-abcdef-0123456789", "NEWKEY-child-0123456789-abcdef-0123456789"
	state := filepath.Join(root.stateDir, "relay.state")

	// (b) running node -> 8, intact
	h0 := rekeyFileHash(t, state)
	code, out := rekeyCLI(t, bin, root, []string{"RSA_MASTER_KEY=" + oldRoot, "NEW_RSA_MASTER_KEY=" + newRoot}, "state", "rekey", "--yes")
	t.Logf("b running node: code=%d", code)
	if code != 8 || rekeyFileHash(t, state) != h0 {
		t.Errorf("b: code %d / state changed", code)
	}
	var allOut strings.Builder
	allOut.WriteString(out)
	root.stop()
	child.stop()
	h1 := rekeyFileHash(t, state)
	env := func(o, n string) []string { return []string{"RSA_MASTER_KEY=" + o, "NEW_RSA_MASTER_KEY=" + n} }
	// (c) no --yes
	code, out = rekeyCLI(t, bin, root, env(oldRoot, newRoot), "state", "rekey")
	allOut.WriteString(out)
	t.Logf("c no --yes: code=%d", code)
	if code != 9 || rekeyFileHash(t, state) != h1 {
		t.Errorf("c: code %d", code)
	}
	// (d) same key / empty new key / wrong current key
	for name, e := range map[string][]string{"same": env(oldRoot, oldRoot), "empty-new": {"RSA_MASTER_KEY=" + oldRoot}, "empty-new-var": {"RSA_MASTER_KEY=" + oldRoot, "NEW_RSA_MASTER_KEY="}, "short-new-key": env(oldRoot, "short-new-key"), "wrong-current": env("WRONG-current-key-0123456789", newRoot), "no-current": {"NEW_RSA_MASTER_KEY=" + newRoot}} {
		code, out = rekeyCLI(t, bin, root, e, "state", "rekey", "--yes")
		allOut.WriteString(out)
		t.Logf("d %s: code=%d %q", name, code, rekeyFirstLine(out))
		if code == 0 || rekeyFileHash(t, state) != h1 {
			t.Errorf("d %s: code %d or state changed", name, code)
		}
		if name == "short-new-key" && code != 11 {
			t.Errorf("a new key shorter than 32 bytes must exit 11, got %d", code)
		}
	}
	// (h) keys as arguments
	for _, a := range [][]string{{"state", "rekey", "--yes", "--new-key", newRoot}, {"state", "rekey", "--yes", newRoot}, {"state", "rekey", "--yes", "--new-master-key=" + newRoot}} {
		code, out = rekeyCLI(t, bin, root, env(oldRoot, newRoot), a...)
		t.Logf("h args %v: code=%d echo-of-the-typed-key-in-error=%v", a[3:], code, strings.Contains(out, newRoot))
		t.Logf("h out: %s", rekeyFirstLine(out))
		if code == 0 || rekeyFileHash(t, state) != h1 {
			t.Errorf("h: accepted a key argument")
		}
	}
	// (a)(f)(j) real rekey, root and non-root
	for _, c := range []struct {
		n        *node
		old, new string
	}{{root, oldRoot, newRoot}, {child, oldChild, newChild}} {
		sp := filepath.Join(c.n.stateDir, "relay.state")
		before := rekeyFileHash(t, sp)
		code, out = rekeyCLI(t, bin, c.n, env(c.old, c.new), "state", "rekey", "--yes")
		allOut.WriteString(out)
		t.Logf("a rekey %s: code=%d out=%q", c.n.id, code, strings.ReplaceAll(strings.TrimSpace(out), "\n", " | "))
		if code != 0 {
			t.Fatalf("rekey %s: %d %s", c.n.id, code, out)
		}
		baks, _ := filepath.Glob(filepath.Join(c.n.stateDir, "relay.state.rekey.*.bak"))
		if len(baks) != 1 {
			t.Fatalf("backups %v", baks)
		}
		fi, _ := os.Stat(baks[0])
		t.Logf("f %s backup %s mode=%04o identical-to-original=%v", c.n.id, filepath.Base(baks[0]), fi.Mode().Perm(), rekeyFileHash(t, baks[0]) == before)
		if fi.Mode().Perm() != 0o600 || rekeyFileHash(t, baks[0]) != before {
			t.Errorf("f: backup mode/content")
		}
		cb, _ := rekeyCLI(t, bin, c.n, []string{"RSA_MASTER_KEY=" + c.old}, "state", "verify", baks[0])
		if cb != 0 {
			t.Errorf("f: backup not verifiable with the OLD key: %d", cb)
		}
		cb, _ = rekeyCLI(t, bin, c.n, []string{"RSA_MASTER_KEY=" + c.new}, "state", "verify", baks[0])
		if cb == 0 {
			t.Errorf("f: backup verifiable with the NEW key")
		}
		cn, o2 := rekeyCLI(t, bin, c.n, []string{"RSA_MASTER_KEY=" + c.new}, "state", "verify", sp)
		co, _ := rekeyCLI(t, bin, c.n, []string{"RSA_MASTER_KEY=" + c.old}, "state", "verify", sp)
		t.Logf("a %s: verify(new)=%d verify(old)=%d (%s)", c.n.id, cn, co, rekeyFirstLine(o2))
		if cn != 0 || co == 0 {
			t.Errorf("a: verify new=%d old=%d", cn, co)
		}
		// (g) no key anywhere
		jl, _ := os.ReadFile(filepath.Join(c.n.stateDir, "state-restore.log"))
		for _, k := range []string{c.old, c.new} {
			if strings.Contains(allOut.String(), k) || strings.Contains(string(jl), k) {
				t.Errorf("g: key %q leaked in output/journal of %s", k, c.n.id)
			}
		}
	}
	// start with the OLD key: refused
	root.setEnv("RSA_MASTER_KEY", oldRoot)
	code, _ = root.runExpectingExit()
	t.Logf("a start with OLD key: exit=%d", code)
	if code <= 0 {
		t.Errorf("a: node started with the old key (exit %d)", code)
	}
	// start with the NEW key; agent token + link token still work
	root.setEnv("RSA_MASTER_KEY", newRoot)
	child.setEnv("RSA_MASTER_KEY", newChild)
	root.restart()
	child.restart()
	waitFor(t, "child relinks with its existing link token", func() bool { return child.upstreamState() == "connected" })
	connectMinionWithToken(t, root, "agent-r", agentTok)
	if r := root.exec("agent-r", map[string]any{"cmd": "true", "timeout": 5}); r.Code != 200 {
		t.Errorf("exec through the existing agent session after rekey: %d %v", r.Code, r.Body)
	}
	for _, n := range []*node{root, child} {
		for _, k := range []string{oldRoot, newRoot, oldChild, newChild} {
			if strings.Contains(n.logs.String(), k) {
				t.Errorf("g: key leaked in node log %s", n.id)
			}
		}
	}
	t.Logf("a: nodes restarted with NEW keys; existing agent JWT and link token still work")
}

// SECURITY.md §11 step 6: "state restore --from relay.state.rekey.<UTC>.bak with the OLD key" is the only way back.
func TestRekeyBinary_RollbackByRestoreWithTheOldKey(t *testing.T) {
	bin := serverBinary(t)
	n := startNode(t, nodeSpec{ID: "solo"})
	n.enrollAgent("agent-s")
	old, nw := "integration-master-key-solo", "NEWKEY-solo-0123456789-abcdef-0123456789"
	n.stop()
	sp := filepath.Join(n.stateDir, "relay.state")
	h0 := rekeyFileHash(t, sp)
	code, out := rekeyCLI(t, bin, n, []string{"RSA_MASTER_KEY=" + old, "NEW_RSA_MASTER_KEY=" + nw}, "state", "rekey", "--yes")
	if code != 0 {
		t.Fatalf("rekey: %d %s", code, out)
	}
	baks, _ := filepath.Glob(filepath.Join(n.stateDir, "relay.state.rekey.*.bak"))
	code, out = rekeyCLI(t, bin, n, []string{"RSA_MASTER_KEY=" + old}, "state", "restore", "--from", baks[0])
	t.Logf("restore from the rekey backup with the OLD key: code=%d out=%q", code, strings.ReplaceAll(strings.TrimSpace(out), "\n", " | "))
	t.Logf("state identical to the original after restore: %v", rekeyFileHash(t, sp) == h0)
	if code != 0 {
		t.Errorf("rollback by restore failed: %d", code)
	}
	cv, _ := rekeyCLI(t, bin, n, []string{"RSA_MASTER_KEY=" + old}, "state", "verify", sp)
	if cv != 0 {
		t.Errorf("restored state does not verify with the old key: %d", cv)
	}
	// and the node starts again with the OLD key
	n.setEnv("RSA_MASTER_KEY", old)
	n.restart()
	if code, _ := n.admin("GET", "/api/admin/status", nil); code != 200 {
		t.Errorf("node does not serve after rollback: %d", code)
	}
}

// MANAGEMENT_CLI_SPECS §6: the real `keys …` commands (compiled binary) against real nodes, exit codes.
func TestKeysCLI_RealBinaryAgainstRealNodes(t *testing.T) {
	bin := serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "child linked", func() bool { return child.upstreamState() == "connected" })
	run := func(n *node, tok string, args ...string) (int, string, string) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "RELAY_API_URL="+n.adminURL(), "ADMIN_TOKEN="+tok, "SSL_CERT_FILE="+certPath)
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return code, so.String(), se.String()
	}
	c, so, se := run(root, root.adminTok, "keys", "link-pubkey")
	t.Logf("link-pubkey: rc=%d stdout-PEM=%v stderr=%q", c, strings.Contains(so, "BEGIN PUBLIC KEY"), strings.TrimSpace(se))
	if c != 0 || !strings.Contains(so, "BEGIN PUBLIC KEY") || !strings.Contains(se, "root_id=") {
		t.Errorf("link-pubkey")
	}
	c, so, se = run(root, root.adminTok, "keys", "rotate-link")
	t.Logf("rotate-link: rc=%d out=%q err=%q", c, strings.ReplaceAll(strings.TrimSpace(so), "\n", " | "), strings.TrimSpace(se))
	c, so, _ = run(root, root.adminTok, "keys", "link-status")
	t.Logf("link-status: rc=%d out=%q", c, strings.ReplaceAll(strings.TrimSpace(so), "\n", " | "))
	c, _, se = run(root, root.adminTok, "keys", "rotate-link")
	t.Logf("2nd rotate-link: rc=%d err=%q (doc: 409 previous_key_not_retired, rc 1)", c, strings.TrimSpace(se))
	if c != 1 {
		t.Errorf("2nd rotate rc=%d", c)
	}
	waitFor(t, "child confirmed", func() bool {
		_, so, _ := run(root, root.adminTok, "keys", "link-status")
		return strings.Contains(so, "true")
	})
	c, so, se = run(root, root.adminTok, "keys", "retire-link-previous")
	t.Logf("retire-link-previous: rc=%d out=%q err=%q", c, strings.TrimSpace(so), strings.TrimSpace(se))
	if c != 0 {
		t.Errorf("retire rc=%d", c)
	}
	c, _, se = run(root, root.adminTok, "keys", "retire-link-previous")
	t.Logf("retire again: rc=%d err=%q (doc: 409 no_previous_key, rc 1)", c, strings.TrimSpace(se))
	c, _, se = run(child, child.adminTok, "keys", "link-pubkey")
	t.Logf("link-pubkey on a non-root: rc=%d err=%q (doc: 409 not_root, rc 1)", c, strings.TrimSpace(se))
	if c != 1 {
		t.Errorf("non-root rc=%d", c)
	}
	c, _, se = run(root, "wrong-token", "keys", "link-status")
	t.Logf("wrong ADMIN_TOKEN: rc=%d err=%q (doc: rc 1)", c, strings.TrimSpace(se))
	if c != 1 {
		t.Errorf("401 rc=%d", c)
	}
}

// serverBinary compiles the real secagent-server (the one the CLI commands of the documentation are run
// with) into a temporary directory removed by the test.
func serverBinary(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is needed to build secagent-server: %v", err)
	}
	out := filepath.Join(t.TempDir(), "secagent-server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, "../..")
	cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build secagent-server: %v\n%s", err, b)
	}
	return out
}

func rekeyFirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// The 32-byte minimum of the NEW master key (68a4a15) at the level of the real binary: 31 bytes are refused
// with exit 11 and nothing is touched (no backup either), 32 bytes are accepted; the message never echoes
// the key; the CURRENT key has no minimum (historical keys must stay openable).
func TestRekeyBinary_NewKeyMinimumIs32Bytes(t *testing.T) {
	bin := serverBinary(t)
	n := startNode(t, nodeSpec{ID: "solo"})
	n.stop()
	old := "integration-master-key-solo" // 27 bytes: shorter than the minimum, and fine as a CURRENT key
	sp := filepath.Join(n.stateDir, "relay.state")
	h0 := rekeyFileHash(t, sp)
	env := func(k string) []string { return []string{"RSA_MASTER_KEY=" + old, "NEW_RSA_MASTER_KEY=" + k} }

	k31, k32 := strings.Repeat("k", 31), strings.Repeat("k", 32)
	code, out := rekeyCLI(t, bin, n, env(k31), "state", "rekey", "--yes")
	if code != 11 || rekeyFileHash(t, sp) != h0 || strings.Contains(out, k31) || !strings.Contains(out, "32 bytes") {
		t.Fatalf("31 bytes: exit %d, state unchanged=%v, output %q (want exit 11, nothing modified, the key not echoed)", code, rekeyFileHash(t, sp) == h0, rekeyFirstLine(out))
	}
	if baks, _ := filepath.Glob(filepath.Join(n.stateDir, "relay.state.rekey.*.bak")); len(baks) != 0 {
		t.Errorf("a refused rekey must not leave a backup: %v", baks)
	}
	code, out = rekeyCLI(t, bin, n, env(k32), "state", "rekey", "--yes")
	if code != 0 || rekeyFileHash(t, sp) == h0 || strings.Contains(out, k32) {
		t.Fatalf("32 bytes: exit %d, output %q", code, rekeyFirstLine(out))
	}
	if c, _ := rekeyCLI(t, bin, n, []string{"RSA_MASTER_KEY=" + k32}, "state", "verify", sp); c != 0 {
		t.Errorf("the rekeyed state does not verify with the new key: %d", c)
	}
}
