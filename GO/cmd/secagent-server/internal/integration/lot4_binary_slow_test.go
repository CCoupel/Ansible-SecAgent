// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

package integration

// LOT-4 v3.0.5, tests on the COMPILED binaries: #233 (minions delete, relays revoke / remove --revoke, hints),
// #219 (command groups exit 1 on an unknown word), #220 (--version on the three binaries, injected by
// -ldflags), #221 (no test helper symbol in a release binary).

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// buildBinary compiles one command of the module into a temporary directory. dir is relative to this package
// (…/cmd/secagent-server/internal/integration), ldflags may be empty. Like the release build: CGO off, trimpath.
func buildBinary(t *testing.T, dir, name, ldflags string, strip bool) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is needed: %v", err)
	}
	out := filepath.Join(t.TempDir(), name)
	args := []string{"build", "-trimpath", "-buildvcs=false"}
	flags := ldflags
	if strip {
		flags = strings.TrimSpace("-s -w " + flags)
	}
	if flags != "" {
		args = append(args, "-ldflags", flags)
	}
	args = append(args, "-o", out, dir)
	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", name, err, b)
	}
	return out
}

// runBin runs a binary with a minimal environment plus extra, stdin on /dev/null (no terminal), and returns
// the exit code, stdout and stderr separately.
func runBin(t *testing.T, bin string, extra []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	home := t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}, extra...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill() // our own child, by handle
		<-done
		t.Fatalf("%s %v did not end in 60 s (a server started?)\nstdout:%s\nstderr:%s", filepath.Base(bin), args, so.String(), se.String())
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code, so.String(), se.String()
}

func adminEnv(n *node) []string {
	return []string{"RELAY_API_URL=" + n.adminURL(), "ADMIN_TOKEN=" + n.adminTok, "SSL_CERT_FILE=" + certPath}
}

// ── #233 ─────────────────────────────────────────────────────────────────────

func TestLot4_MinionsDelete_RealBinaryAgainstARealNode(t *testing.T) {
	bin := serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	env := adminEnv(root)
	root.enrollAgent("del-idle")

	// no --yes and no terminal: refused (exit 9), nothing deleted
	code, so, se := runBin(t, bin, env, "minions", "delete", "del-idle")
	if code != 9 || !strings.Contains(se, "--yes") {
		t.Errorf("without --yes: rc=%d stdout=%q stderr=%q, want rc 9 and the hint to pass --yes", code, so, se)
	}
	if c, _ := root.admin("GET", "/api/admin/minions/del-idle", nil); c != http.StatusOK {
		t.Errorf("a refused delete must leave the agent: GET = %d", c)
	}
	// --yes: deleted
	if code, so, se = runBin(t, bin, env, "minions", "delete", "del-idle", "--yes"); code != 0 {
		t.Errorf("delete --yes: rc=%d stdout=%q stderr=%q", code, so, se)
	}
	if c, _ := root.admin("GET", "/api/admin/minions/del-idle", nil); c != http.StatusNotFound {
		t.Errorf("after delete --yes the agent must be gone: GET = %d", c)
	}
	// unknown agent: error exit, not 0
	if code, _, se = runBin(t, bin, env, "minions", "delete", "nobody-here", "--yes"); code == 0 {
		t.Errorf("deleting an unknown agent must fail, stderr=%q", se)
	}
	// a CONNECTED agent: the operator is told so, with the revoke alternative
	connectMinion(t, root, "del-live")
	waitFor(t, "the agent is connected", func() bool { return agentServed(root, "del-live", 1) })
	code, so, se = runBin(t, bin, env, "minions", "delete", "del-live", "--yes")
	if code != 0 || !strings.Contains(so+se, "connected") || !strings.Contains(so+se, "minions revoke") {
		t.Errorf("connected agent: rc=%d stdout=%q stderr=%q, want a message saying it is connected and pointing at 'minions revoke'", code, so, se)
	}
	// no token in the outputs
	if strings.Contains(so+se, root.adminTok) {
		t.Error("the admin token leaked in the CLI output")
	}
}

func TestLot4_RelaysRevokeAndRemove_RealBinaryAndTheHintWorksAsWritten(t *testing.T) {
	bin := serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	env := adminEnv(root)
	declare := func(id string) string {
		c, m := root.admin("POST", "/api/admin/relays", map[string]any{"relay_id": id, "mode": "pull"})
		if c != http.StatusCreated {
			t.Fatalf("declare %s: %d %v", id, c, m)
		}
		return m["id"].(string)
	}
	listed := func(id string) bool {
		_, m := root.admin("GET", "/api/admin/relays", nil)
		rs, _ := m["relays"].([]any)
		for _, r := range rs {
			if row, ok := r.(map[string]any); ok && row["relay_id"] == id {
				return true
			}
		}
		return false
	}

	// never_seen relay: a plain remove is refused by the node and the message gives a remedy
	declare("nv-name")
	// B49: remove always asks for confirmation: without --yes and without a terminal it is refused (9), nothing done
	if code, _, se := runBin(t, bin, env, "relays", "remove", "nv-name"); code != 9 || !strings.Contains(se, "--yes") || !listed("nv-name") {
		t.Fatalf("remove without --yes: rc=%d stderr=%q listed=%v, want rc 9, the hint to pass --yes and the relay left in place", code, se, listed("nv-name"))
	}
	code, _, se := runBin(t, bin, env, "relays", "remove", "--yes", "nv-name")
	if code != 1 || !strings.Contains(se, "relay_not_revoked") {
		t.Fatalf("remove of a never_seen relay: rc=%d stderr=%q, want rc 1 and relay_not_revoked", code, se)
	}
	// the remedy, executed AS WRITTEN (only the binary path and --yes — no terminal here — are added)
	m := regexp.MustCompile(`'secagent-server (relays remove [^']+)'`).FindStringSubmatch(se)
	if m == nil {
		t.Fatalf("the error must quote a runnable remedy 'secagent-server relays remove …': %q", se)
	}
	if !listed("nv-name") {
		t.Fatal("the failed remove must leave the relay")
	}
	args := append(strings.Fields(m[1]), "--yes")
	if code, so, se2 := runBin(t, bin, env, args...); code != 0 {
		t.Fatalf("the remedy %q does not work: rc=%d stdout=%q stderr=%q", m[1], code, so, se2)
	}
	if listed("nv-name") {
		t.Error("after the remedy the relay must be removed")
	}

	// by UUID too, with revoke then remove as two commands
	uuid := declare("nv-uuid")
	if code, _, se = runBin(t, bin, env, "relays", "revoke", uuid); code != 9 {
		t.Errorf("revoke without --yes and without a terminal: rc=%d stderr=%q, want 9", code, se)
	}
	if code, so, se := runBin(t, bin, env, "relays", "revoke", uuid, "--yes"); code != 0 {
		t.Fatalf("revoke --yes by uuid: rc=%d stdout=%q stderr=%q", code, so, se)
	}
	if code, so, se := runBin(t, bin, env, "relays", "remove", "--yes", uuid); code != 0 {
		t.Errorf("remove after revoke by uuid: rc=%d stdout=%q stderr=%q", code, so, se)
	}
	if listed("nv-uuid") {
		t.Error("the relay must be gone after revoke + remove")
	}
	// unknown relay: error exit
	if code, _, _ = runBin(t, bin, env, "relays", "revoke", "no-such-relay", "--yes"); code == 0 {
		t.Error("revoking an unknown relay must fail")
	}
}

func TestLot4_KeysLinkStatus_OutsideARotationDoesNotSaySinceTheRotation(t *testing.T) {
	bin := serverBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	code, so, se := runBin(t, bin, adminEnv(root), "keys", "link-status")
	if code != 0 {
		t.Fatalf("link-status: rc=%d stderr=%q", code, se)
	}
	if strings.Contains(so, "since the rotation") {
		t.Errorf("no rotation has happened: the output must not say 'since the rotation':\n%s", so)
	}
}

// ── #219 ─────────────────────────────────────────────────────────────────────

var groupNames = []string{"minions", "security", "inventory", "server", "tokens", "hooks", "relays", "state", "keys"}

func TestLot4_CommandGroups_UnknownWordExits1AndHelpGoesToStderr(t *testing.T) {
	bin := serverBinary(t)
	for _, g := range groupNames {
		// the group exists as a group (it lists subcommands)
		code, so, _ := runBin(t, bin, nil, g, "--help")
		if code != 0 || !strings.Contains(so, "Available Commands") {
			t.Errorf("%s --help: rc=%d, want 0 and a list of subcommands (is %q still a group?)", g, code, g)
			continue
		}
		if code, _, _ = runBin(t, bin, nil, g); code != 0 {
			t.Errorf("%s alone: rc=%d, want 0", g, code)
		}
		code, so, se := runBin(t, bin, nil, g, "frobnicate")
		if code != 1 {
			t.Errorf("%s frobnicate: rc=%d, want 1", g, code)
		}
		if !strings.Contains(se, "frobnicate") || !strings.Contains(se, "Available Commands") && !strings.Contains(se, "Usage") {
			t.Errorf("%s frobnicate: the error and the help must be on stderr, got stderr=%q", g, se)
		}
		if strings.TrimSpace(so) != "" {
			t.Errorf("%s frobnicate: nothing may be written to stdout, got %q", g, so)
		}
	}
}

// ── #220 ─────────────────────────────────────────────────────────────────────

func TestLot4_Version_ThreeBinariesInjectedByLdflags(t *testing.T) {
	const v = "9.9.9-lot4"
	bins := []struct{ name, dir, ldflags string }{
		{"secagent-server", "../..", "-X secagent-server/cmd/secagent-server/internal/cli.Version=" + v},
		{"secagent-minion", "../../../secagent-minion", "-X main.Version=" + v},
		{"secagent-inventory", "../../../secagent-inventory", "-X main.Version=" + v},
	}
	for _, b := range bins {
		bin := buildBinary(t, b.dir, b.name, b.ldflags, true)
		want := b.name + " version " + v
		for _, flag := range []string{"--version", "-v"} {
			code, so, se := runBin(t, bin, nil, flag)
			if code != 0 || strings.TrimSpace(so) != want {
				t.Errorf("%s %s: rc=%d stdout=%q stderr=%q, want rc 0 and %q", b.name, flag, code, so, se, want)
			}
		}
	}
	// D5: an extra argument is an error on the server and the minion
	for _, b := range bins[:2] {
		bin := buildBinary(t, b.dir, b.name, b.ldflags, true)
		if code, so, _ := runBin(t, bin, nil, "--version", "extra"); code != 1 || strings.Contains(so, v) {
			t.Errorf("%s --version extra: rc=%d stdout=%q, want rc 1 and no version printed", b.name, code, so)
		}
	}
	// without injection the three binaries say "dev"
	for _, b := range bins {
		bin := buildBinary(t, b.dir, b.name, "", true)
		if _, so, _ := runBin(t, bin, nil, "--version"); strings.TrimSpace(so) != b.name+" version dev" {
			t.Errorf("%s without ldflags: %q, want '… version dev'", b.name, so)
		}
	}
}

// ── #221 ─────────────────────────────────────────────────────────────────────

// A release binary (no build tag) carries no test helper: go tool nm lists none of them. The binary is built
// WITHOUT -s -w (stripped binaries have no symbol table) and the listing must be non-empty and contain main.main,
// otherwise an empty output would pass for a clean one.
func TestLot4_ReleaseServerBinaryHasNoTestHelperSymbols(t *testing.T) {
	bin := buildBinary(t, "../..", "secagent-server", "", false)
	goBin, _ := exec.LookPath("go")
	out, err := exec.Command(goBin, "tool", "nm", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	syms := string(out)
	if !strings.Contains(syms, "main.main") {
		t.Fatalf("the symbol listing is empty or stripped (no main.main): the check would prove nothing (%d bytes)", len(syms))
	}
	for _, bad := range []string{"OpenTemp", "OpenTestDir"} {
		if strings.Contains(syms, bad) {
			t.Errorf("the release binary contains the test helper %q", bad)
		}
	}
}
