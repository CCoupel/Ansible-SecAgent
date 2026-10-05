package integration

// End-to-end check of the Ansible inventory: the real secagent-inventory binary, driven by the real
// `ansible-inventory` (script inventory plugin), against a real node tree of the harness.
//
// CI convention (shared with the infra job): the test reads ANSIBLE_E2E. When `ansible-inventory`
// is not on PATH it SKIPS, unless ANSIBLE_E2E=1 — then it FAILS (the Ansible CI job is mandatory).
// The "Build + tests Go" job has no Ansible and simply skips it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

func ansibleInventoryTool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ansible-inventory")
	if err != nil {
		if os.Getenv("ANSIBLE_E2E") == "1" {
			t.Fatalf("ANSIBLE_E2E=1 but ansible-inventory is not on PATH: %v", err)
		}
		t.Skip("ansible-inventory not found: install ansible-core (set ANSIBLE_E2E=1 to make this a failure)")
	}
	return path
}

var (
	invBinOnce sync.Once
	invBinPath string
	invBinErr  error
)

// inventoryBinary builds cmd/secagent-inventory once into a temporary directory.
func inventoryBinary(t *testing.T) string {
	t.Helper()
	invBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "secagent-inventory-")
		if err != nil {
			invBinErr = err
			return
		}
		invBinPath = filepath.Join(dir, "secagent-inventory")
		goBin, err := exec.LookPath("go")
		if err != nil {
			invBinErr = err
			return
		}
		cmd := exec.Command(goBin, "build", "-o", invBinPath, "./cmd/secagent-inventory")
		cmd.Dir = "../../../.." // GO/ (module root of the workspace)
		if out, err := cmd.CombinedOutput(); err != nil {
			invBinErr = fmt.Errorf("go build secagent-inventory: %v\n%s", err, out)
		}
	})
	if invBinErr != nil {
		t.Fatal(invBinErr)
	}
	return invBinPath
}

// ansibleResult is the outcome of one ansible-inventory run.
type ansibleResult struct {
	Exit   int
	Stdout string
	Stderr string
}

// runAnsible runs `ansible-inventory -i <script> <args…>` with the given environment on top of a clean one.
func runAnsible(t *testing.T, tool, script string, env []string, args ...string) ansibleResult {
	t.Helper()
	cmd := exec.Command(tool, append([]string{"-i", script}, args...)...)
	cmd.Env = append(os.Environ(),
		"HOME="+t.TempDir(), "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False",
		"ANSIBLE_FORCE_COLOR=0", "ANSIBLE_NOCOLOR=1")
	cmd.Env = append(cmd.Env, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	res := ansibleResult{Stdout: so.String(), Stderr: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		res.Exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run ansible-inventory: %v", err)
	}
	return res
}

// parseProblems lists what shows that Ansible did NOT accept the inventory script's output
// (it never exits non-zero for that: it warns and falls back to an implicit localhost).
func parseProblems(r ansibleResult) []string {
	var p []string
	if r.Exit != 0 {
		p = append(p, fmt.Sprintf("exit code %d", r.Exit))
	}
	for _, bad := range []string{"Failed to parse", "bad data", "No inventory was parsed", "Unable to parse"} {
		if strings.Contains(strings.ReplaceAll(r.Stderr, "\n", " "), bad) {
			p = append(p, "ansible reported: "+bad)
		}
	}
	return p
}

// ── the expected inventory ───────────────────────────────────────────────────

type ansibleDoc struct {
	Meta struct {
		Hostvars map[string]map[string]any `json:"hostvars"`
	} `json:"_meta"`
	Groups map[string]struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	} `json:"-"`
}

func decodeInventory(raw string) (map[string]json.RawMessage, *ansibleDoc, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return nil, nil, fmt.Errorf("not valid JSON: %w", err)
	}
	d := &ansibleDoc{Groups: map[string]struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}{}}
	for k, v := range top {
		if k == "_meta" {
			if err := json.Unmarshal(v, &d.Meta); err != nil {
				return nil, nil, fmt.Errorf("_meta: %w", err)
			}
			continue
		}
		var g struct {
			Hosts    []string `json:"hosts"`
			Children []string `json:"children"`
		}
		if err := json.Unmarshal(v, &g); err != nil {
			return nil, nil, fmt.Errorf("group %q: %w", k, err)
		}
		d.Groups[k] = g
	}
	return top, d, nil
}

// expectation describes the tree root ──▶ relay1 ──▶ relay2.
type expectation struct {
	hostGroup map[string]string   // host → the relay group that must hold it
	children  map[string][]string // relay group → child relay groups
	chain     map[string][]string // host → secagent_relay_chain (origin first)
	nextHop   map[string]string   // host → secagent_next_hop
	absent    []string            // hosts / groups that must not appear
}

// inventoryProblems checks a decoded ansible-inventory document against the expectation and
// returns every deviation (empty = conform). It is also what the self-test feeds with corrupted
// documents: a checker that cannot fail would prove nothing.
func inventoryProblems(raw string, e expectation) []string {
	top, d, err := decodeInventory(raw)
	if err != nil {
		return []string{err.Error()}
	}
	var p []string
	for host, group := range e.hostGroup {
		g, ok := d.Groups[group]
		if !ok {
			p = append(p, fmt.Sprintf("group %q is missing (exact relay name expected)", group))
			continue
		}
		if !contains(g.Hosts, host) {
			p = append(p, fmt.Sprintf("host %q is not in group %q (hosts=%v)", host, group, g.Hosts))
		}
		for other, og := range d.Groups {
			if other != group && other != "all" && contains(og.Hosts, host) {
				p = append(p, fmt.Sprintf("host %q also appears in group %q", host, other))
			}
		}
	}
	for group, kids := range e.children {
		g := d.Groups[group]
		for _, k := range kids {
			if !contains(g.Children, k) {
				p = append(p, fmt.Sprintf("group %q must have the child group %q (children=%v)", group, k, g.Children))
			}
		}
		if len(g.Children) != len(kids) { // set comparison: the order of children is not meaningful
			p = append(p, fmt.Sprintf("group %q has children %v, want exactly %v", group, g.Children, kids))
		}
	}
	for host, chain := range e.chain {
		hv, ok := d.Meta.Hostvars[host]
		if !ok {
			p = append(p, fmt.Sprintf("no hostvars for %q", host))
			continue
		}
		if hv["ansible_connection"] != "relay" {
			p = append(p, fmt.Sprintf("%s: ansible_connection = %v, want relay", host, hv["ansible_connection"]))
		}
		got := toStrings(hv["secagent_relay_chain"])
		if !reflect.DeepEqual(got, chain) {
			p = append(p, fmt.Sprintf("%s: secagent_relay_chain = %v, want %v (origin first)", host, got, chain))
		}
		if hv["secagent_next_hop"] != e.nextHop[host] {
			p = append(p, fmt.Sprintf("%s: secagent_next_hop = %v, want %v", host, hv["secagent_next_hop"], e.nextHop[host]))
		}
	}
	for _, name := range e.absent {
		if _, g := d.Groups[name]; g {
			p = append(p, fmt.Sprintf("group %q must not appear", name))
		}
		if _, h := d.Meta.Hostvars[name]; h {
			p = append(p, fmt.Sprintf("host %q must not appear", name))
		}
	}
	// no group cycle (Ansible would loop or reject it)
	state := map[string]int{}
	var visit func(string) bool
	visit = func(g string) bool {
		switch state[g] {
		case 1:
			return false
		case 2:
			return true
		}
		state[g] = 1
		for _, c := range d.Groups[g].Children {
			if !visit(c) {
				return false
			}
		}
		state[g] = 2
		return true
	}
	names := make([]string, 0, len(d.Groups))
	for g := range d.Groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		if !visit(g) {
			p = append(p, "the group graph contains a cycle through "+g)
			break
		}
	}
	_ = top
	return p
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ── scenarios ────────────────────────────────────────────────────────────────

func TestAnsibleInventory(t *testing.T) {
	tool := ansibleInventoryTool(t)
	bin := inventoryBinary(t)

	// root ──push──▶ relay1 ◀──pull── relay2 / relay3. relay1 has NO agent of its own (a purely
	// intermediate relay: its group has children but no host — the shape a script inventory must
	// still serialise as "hosts": []). relay2 and relay3 are declared to the root by relay1's
	// snapshot, so the root knows the whole subtree.
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1"})
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	relay3 := startNode(t, nodeSpec{ID: "relay3", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay3")})
	waitFor(t, "relay2 and relay3 linked", func() bool {
		return relay2.upstreamState() == "connected" && relay3.upstreamState() == "connected"
	})
	enroll(t, root, "a-root") // enrolled: it is listed by the root's own inventory
	connectMinion(t, root, "a-root")
	connectMinion(t, relay2, "a-l2")
	connectMinion(t, relay3, "a-l3")
	waitFor(t, "relay1 knows both deep agents", func() bool { return relay1.hasHost("a-l2") && relay1.hasHost("a-l3") })
	linkPush(t, root, relay1)
	waitFor(t, "the root's inventory is complete", func() bool {
		return root.hasHost("a-root") && root.hasHost("a-l2") && root.hasHost("a-l3")
	})

	env := []string{"RELAY_SERVER_URL=" + root.apiURL(), "RELAY_TOKEN=" + root.pluginToken(), "SSL_CERT_FILE=" + certPath}
	want := expectation{
		hostGroup: map[string]string{"a-root": "root", "a-l2": "relay2", "a-l3": "relay3"},
		children:  map[string][]string{"root": {"relay1"}, "relay1": {"relay2", "relay3"}, "relay2": nil, "relay3": nil},
		chain:     map[string][]string{"a-l2": {"relay2", "relay1"}, "a-l3": {"relay3", "relay1"}},
		nextHop:   map[string]string{"a-l2": "relay1", "a-l3": "relay1"},
	}

	t.Run("List", func(t *testing.T) {
		res := runAnsible(t, tool, bin, env, "--list")
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("ansible-inventory did not accept the inventory: %v\nstderr:\n%s\nstdout:\n%s", p, res.Stderr, res.Stdout)
		}
		if p := inventoryProblems(res.Stdout, want); len(p) > 0 {
			t.Errorf("inventory not conform:\n  %s\nstdout:\n%s", strings.Join(p, "\n  "), res.Stdout)
		}
	})

	t.Run("HostVarsOfOneHost", func(t *testing.T) {
		res := runAnsible(t, tool, bin, env, "--host", "a-l2")
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("ansible-inventory --host failed: %v\n%s", p, res.Stderr)
		}
		var hv map[string]any
		if err := json.Unmarshal([]byte(res.Stdout), &hv); err != nil {
			t.Fatalf("--host output is not JSON: %v\n%s", err, res.Stdout)
		}
		if hv["ansible_connection"] != "relay" || hv["secagent_next_hop"] != "relay1" ||
			!reflect.DeepEqual(toStrings(hv["secagent_relay_chain"]), []string{"relay2", "relay1"}) {
			t.Errorf("--host a-l2 = %v", hv)
		}
	})

	t.Run("ScopeLimitsTheInventoryToASubtree", func(t *testing.T) {
		res := runAnsible(t, tool, bin, append(env, "RELAY_SCOPE=relay1"), "--list")
		if p := parseProblems(res); len(p) > 0 {
			t.Fatalf("scoped inventory rejected: %v\n%s", p, res.Stderr)
		}
		scoped := expectation{
			hostGroup: map[string]string{"a-l2": "relay2", "a-l3": "relay3"},
			children:  map[string][]string{"relay1": {"relay2", "relay3"}, "relay2": nil, "relay3": nil},
			chain:     map[string][]string{"a-l2": {"relay2", "relay1"}, "a-l3": {"relay3", "relay1"}},
			nextHop:   map[string]string{"a-l2": "relay1", "a-l3": "relay1"},
			absent:    []string{"a-root", "root"},
		}
		if p := inventoryProblems(res.Stdout, scoped); len(p) > 0 {
			t.Errorf("scoped inventory not conform:\n  %s\nstdout:\n%s", strings.Join(p, "\n  "), res.Stdout)
		}
	})

	t.Run("RejectsAWrongToken", func(t *testing.T) {
		bad := []string{"RELAY_SERVER_URL=" + root.apiURL(), "RELAY_TOKEN=not-a-token", "SSL_CERT_FILE=" + certPath}
		res := runAnsible(t, tool, bin, bad, "--list")
		if len(parseProblems(res)) == 0 {
			t.Errorf("an unauthorized inventory must not look like a valid one:\nstdout: %s\nstderr: %s", res.Stdout, res.Stderr)
		}
	})
}

// The checks above must be able to FAIL: corrupted documents and a script whose output Ansible
// rejects (hosts: null — the shape a group without direct hosts used to be serialised to) are
// detected.
func TestAnsibleInventory_ChecksCanFail(t *testing.T) {
	tool := ansibleInventoryTool(t)
	good := `{"_meta":{"hostvars":{
	  "a-l1":{"ansible_connection":"relay","secagent_relay_chain":["relay1"],"secagent_next_hop":"relay1"},
	  "a-l2":{"ansible_connection":"relay","secagent_relay_chain":["relay2","relay1"],"secagent_next_hop":"relay1"}}},
	 "all":{"hosts":["a-l1","a-l2"],"children":["relay1"]},
	 "relay1":{"hosts":["a-l1"],"children":["relay2"]},
	 "relay2":{"hosts":["a-l2"]}}`
	want := expectation{
		hostGroup: map[string]string{"a-l1": "relay1", "a-l2": "relay2"},
		children:  map[string][]string{"relay1": {"relay2"}, "relay2": nil},
		chain:     map[string][]string{"a-l1": {"relay1"}, "a-l2": {"relay2", "relay1"}},
		nextHop:   map[string]string{"a-l1": "relay1", "a-l2": "relay1"},
	}
	if p := inventoryProblems(good, want); len(p) != 0 {
		t.Fatalf("the reference document must be conform: %v", p)
	}
	corruptions := map[string]string{
		"missing relay group":           strings.Replace(good, `"relay2":{"hosts":["a-l2"]}`, `"other":{"hosts":["a-l2"]}`, 1),
		"relay not a child group":       strings.Replace(good, `"children":["relay2"]`, `"children":[]`, 1),
		"host in the wrong group":       strings.Replace(good, `"relay1":{"hosts":["a-l1"]`, `"relay1":{"hosts":["a-l1","a-l2"]`, 1),
		"chain order reversed":          strings.Replace(good, `["relay2","relay1"]`, `["relay1","relay2"]`, 1),
		"wrong next hop":                strings.Replace(good, `"secagent_next_hop":"relay1"}}}`, `"secagent_next_hop":"relay2"}}}`, 1),
		"cyclic groups":                 strings.Replace(good, `"relay2":{"hosts":["a-l2"]}`, `"relay2":{"hosts":["a-l2"],"children":["relay1"]}`, 1),
		"not JSON":                      `{"all":`,
		"wrong ansible_connection":      strings.Replace(good, `"ansible_connection":"relay"`, `"ansible_connection":"ssh"`, 1),
		"no hostvars for a listed host": strings.Replace(good, `"a-l1":{"ansible_connection":"relay","secagent_relay_chain":["relay1"],"secagent_next_hop":"relay1"},`, ``, 1),
	}
	for name, doc := range corruptions {
		if len(inventoryProblems(doc, want)) == 0 {
			t.Errorf("corruption %q went undetected", name)
		}
	}

	// a script that prints a group with hosts: null, run through the REAL ansible-inventory
	script := filepath.Join(t.TempDir(), "bad-inventory.sh")
	body := "#!/bin/sh\ncat <<'EOF'\n{\"_meta\":{\"hostvars\":{}},\"all\":{\"hosts\":[],\"children\":[\"root\"]},\"root\":{\"hosts\":null,\"children\":[\"relay1\"]},\"relay1\":{\"hosts\":[]}}\nEOF\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	res := runAnsible(t, tool, script, nil, "--list")
	if len(parseProblems(res)) == 0 {
		t.Errorf("an inventory Ansible rejects (hosts: null) must be detected:\nstdout: %s\nstderr: %s", res.Stdout, res.Stderr)
	}
}
