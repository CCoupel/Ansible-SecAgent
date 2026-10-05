package integration

// The relays' group vars through the REAL ansible-inventory / ansible (same CI convention as the
// other Ansible tests: ANSIBLE_E2E, skipped when the tools are absent).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func ansibleAdHocTool(t *testing.T, inventoryTool string) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(inventoryTool), "ansible")
	if _, err := os.Stat(p); err != nil {
		if os.Getenv("ANSIBLE_E2E") == "1" {
			t.Fatalf("ANSIBLE_E2E=1 but the ansible command is missing next to ansible-inventory: %v", err)
		}
		t.Skip("ansible command not found")
	}
	return p
}

// root → relayP (pull, vars) → sub (pull, own vars, joins AFTER the link), root ⇢ relayQ (push, vars).
func TestAnsibleInventory_GroupVarsReachTheHostsOfEachRelay(t *testing.T) {
	tool := ansibleInventoryTool(t)
	adhoc := ansibleAdHocTool(t, tool)
	bin := inventoryBinary(t)

	root := startNode(t, nodeSpec{ID: "root"})
	p := startNode(t, nodeSpec{ID: "relayP", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayP"),
		Env: []string{`RELAY_GROUP_VARS={"env":"staging","datacenter":"paris","attempts":3,"labels":["a","b"],"opts":{"fast":true}}`}})
	waitFor(t, "relayP linked", func() bool { return p.upstreamState() == "connected" })
	q := startNode(t, nodeSpec{ID: "relayQ", Env: []string{`RELAY_GROUP_VARS={"env":"prod"}`}})
	linkPush(t, root, q)
	sub := startNode(t, nodeSpec{ID: "sub", ParentURL: p.wssURL(), ParentToken: p.registerChild("sub"), Env: []string{`RELAY_GROUP_VARS={"env":"sub","extra":"x"}`}})
	waitFor(t, "sub linked", func() bool { return sub.upstreamState() == "connected" })
	connectMinion(t, p, "a-p")
	connectMinion(t, q, "a-q")
	connectMinion(t, sub, "a-sub")
	waitFor(t, "the root's inventory carries every group's vars", func() bool {
		g := groupVarsOf(t, root)
		return len(g["relayP"]) > 0 && len(g["relayQ"]) > 0 && len(g["sub"]) > 0
	})
	env := []string{"RELAY_SERVER_URL=" + root.apiURL(), "RELAY_TOKEN=" + root.pluginToken(), "SSL_CERT_FILE=" + certPath}

	t.Run("GraphWithVars", func(t *testing.T) {
		res := runAnsible(t, tool, bin, env, "--graph", "--vars")
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("--graph --vars: %v\n%s", p, res.Stderr)
		}
		for _, want := range []string{"@relayP:", "@relayQ:", "@sub:", "{datacenter = paris}", "{env = staging}", "{env = prod}", "{env = sub}", "{extra = x}", "{attempts = 3}", "{opts = {'fast': True}}"} {
			if !strings.Contains(res.Stdout, want) {
				t.Errorf("--graph --vars lacks %q:\n%s", want, res.Stdout)
			}
		}
	})

	hostVars := func(t *testing.T, host string) map[string]any {
		t.Helper()
		res := runAnsible(t, tool, bin, env, "--host", host)
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("--host %s: %v\n%s", host, p, res.Stderr)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(res.Stdout), &m); err != nil {
			t.Fatalf("--host %s: not JSON: %v\n%s", host, err, res.Stdout)
		}
		return m
	}
	t.Run("HostsSeeTheirRelaysVars", func(t *testing.T) {
		hp := hostVars(t, "a-p")
		if hp["env"] != "staging" || hp["datacenter"] != "paris" || hp["attempts"] != float64(3) ||
			!reflect.DeepEqual(hp["labels"], []any{"a", "b"}) || !reflect.DeepEqual(hp["opts"], map[string]any{"fast": true}) {
			t.Errorf("a-p vars = %v", hp)
		}
		hq := hostVars(t, "a-q")
		if hq["env"] != "prod" || hq["datacenter"] != nil {
			t.Errorf("a-q (push relay) vars = %v: its own env only, nothing from relayP", hq)
		}
	})
	t.Run("SubtreeInheritance", func(t *testing.T) {
		hs := hostVars(t, "a-sub")
		// The var only the PARENT relay defines is inherited by the sub-relay's hosts.
		if hs["datacenter"] != "paris" || hs["extra"] != "x" {
			t.Errorf("a-sub = %v: it must inherit datacenter from relayP and have its own extra", hs)
		}
		// Observed with ansible-core 2.17 and 2.21: when BOTH relays define env, the deeper (child)
		// group wins. Reported, not imposed: it is Ansible's precedence rule, not this project's.
		t.Logf("env seen by a-sub (defined by relayP=staging and sub=sub): %v", hs["env"])
		if hs["env"] != "sub" && hs["env"] != "staging" {
			t.Errorf("env = %v: must come from one of the two relay groups", hs["env"])
		}
	})
	t.Run("AnAnsibleCommandReadsTheVar", func(t *testing.T) {
		// connection forced to local through an EXTRA VAR (highest precedence: the inventory's
		// ansible_connection=relay would otherwise win): the debug module runs on the controller
		run := func(host, variable string) string {
			t.Helper()
			cmd := exec.Command(adhoc, "-i", bin, host, "-m", "debug", "-a", "var="+variable, "-e", "ansible_connection=local")
			cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH"), "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_NOCOLOR=1"}, env...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ansible %s: %v\n%s", host, err, out)
			}
			return string(out)
		}
		if out := run("a-p", "env"); !strings.Contains(out, `"env": "staging"`) {
			t.Errorf("ansible reads env on a-p:\n%s", out)
		}
		if out := run("a-q", "env"); !strings.Contains(out, `"env": "prod"`) {
			t.Errorf("ansible reads env on a-q:\n%s", out)
		}
		if out := run("relayP", "datacenter"); !strings.Contains(out, `"datacenter": "paris"`) { // targeting the GROUP
			t.Errorf("ansible reads datacenter through the group relayP:\n%s", out)
		}
		if out := run("a-sub", "extra"); !strings.Contains(out, `"extra": "x"`) {
			t.Errorf("ansible reads extra on a-sub:\n%s", out)
		}
	})
}
