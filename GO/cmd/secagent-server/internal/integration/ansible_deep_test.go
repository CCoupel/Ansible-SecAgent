package integration

import "strings"
import "testing"

// Four levels, every link a push (each parent dials its child): root → r1 → r2 → r3, the agent on
// r3 and nothing else. The chain is the full path, origin first; scoping on an intermediate relay
// keeps only its subtree.
func TestAnsibleInventory_DeepChainAndScopeOnAnIntermediateRelay(t *testing.T) {
	tool := ansibleInventoryTool(t)
	bin := inventoryBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	r1 := startNode(t, nodeSpec{ID: "r1"})
	r2 := startNode(t, nodeSpec{ID: "r2"})
	r3 := startNode(t, nodeSpec{ID: "r3"})
	connectMinion(t, r3, "deep-host")
	linkPush(t, r2, r3) // bottom-up: every parent learns its whole subtree at link-up
	linkPush(t, r1, r2)
	linkPush(t, root, r1)
	waitFor(t, "the root routes the deep host", func() bool { return root.hasHost("deep-host") })

	env := []string{"RELAY_SERVER_URL=" + root.apiURL(), "RELAY_TOKEN=" + root.pluginToken(), "SSL_CERT_FILE=" + certPath}
	full := expectation{
		hostGroup: map[string]string{"deep-host": "r3"},
		children:  map[string][]string{"root": {"r1"}, "r1": {"r2"}, "r2": {"r3"}, "r3": nil},
		chain:     map[string][]string{"deep-host": {"r3", "r2", "r1"}},
		nextHop:   map[string]string{"deep-host": "r1"},
	}
	for _, mode := range []string{"--list", "--graph"} {
		res := runAnsible(t, tool, bin, env, mode)
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("%s: %v\n%s", mode, p, res.Stderr)
		}
		if mode == "--list" {
			if p := inventoryProblems(res.Stdout, full); len(p) > 0 {
				t.Errorf("deep chain not conform:\n  %s\n%s", strings.Join(p, "\n  "), res.Stdout)
			}
		}
	}
	scoped := runAnsible(t, tool, bin, append(env, "RELAY_SCOPE=r2"), "--list")
	if p := parseProblems(scoped); len(p) > 0 {
		t.Fatalf("scope on r2: %v\n%s", p, scoped.Stderr)
	}
	sub := expectation{
		hostGroup: map[string]string{"deep-host": "r3"},
		children:  map[string][]string{"r2": {"r3"}, "r3": nil},
		chain:     map[string][]string{"deep-host": {"r3", "r2", "r1"}},
		nextHop:   map[string]string{"deep-host": "r1"},
		absent:    []string{"root", "r1"},
	}
	if p := inventoryProblems(scoped.Stdout, sub); len(p) > 0 {
		t.Errorf("scoped on an intermediate relay not conform:\n  %s\n%s", strings.Join(p, "\n  "), scoped.Stdout)
	}
}
