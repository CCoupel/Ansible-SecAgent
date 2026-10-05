package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ── hierarchical inventory pass-through (#128) ───────────────────────────────

const hierarchicalResponse = `{
  "_meta": {"hostvars": {
    "minion-A": {"ansible_connection": "relay", "secagent_relay_chain": ["dmz1","zone2"], "secagent_next_hop": "zone2"},
    "minion-C": {"ansible_connection": "relay", "secagent_relay_chain": ["zone2"], "secagent_next_hop": "zone2"}}},
  "all": {"hosts": ["minion-A","minion-C"], "children": ["zone2"]},
  "zone2": {"hosts": ["minion-C"], "children": ["dmz1"]},
  "dmz1": {"hosts": ["minion-A"]}
}`

func serveInventory(t *testing.T, body string, seenURL *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seenURL != nil {
			*seenURL = r.URL.String()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func captureList(t *testing.T, cfg config) string {
	t.Helper()
	old := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = pw
	runErr := cmdList(cfg)
	_ = pw.Close()
	os.Stdout = old
	if runErr != nil {
		t.Fatalf("cmdList: %v", runErr)
	}
	buf := make([]byte, 16384)
	n, _ := pr.Read(buf)
	return string(buf[:n])
}

func TestCmdList_PassesTheRelayGroupsThrough(t *testing.T) {
	srv := serveInventory(t, hierarchicalResponse, nil)
	out := captureList(t, config{serverURL: srv.URL})

	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"_meta", "all", "zone2", "dmz1"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("group %q lost by the binary:\n%s", k, out)
		}
	}
	var res AnsibleInventory
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.All.Children) != 1 || res.All.Children[0] != "zone2" ||
		len(res.Groups["zone2"].Children) != 1 || res.Groups["zone2"].Children[0] != "dmz1" ||
		len(res.Groups["dmz1"].Hosts) != 1 || res.Groups["dmz1"].Hosts[0] != "minion-A" {
		t.Errorf("hierarchy altered: %+v", res)
	}
	if !strings.Contains(string(res.Meta.Hostvars["minion-A"]), `"secagent_next_hop": "zone2"`) &&
		!strings.Contains(string(res.Meta.Hostvars["minion-A"]), `"secagent_next_hop":"zone2"`) {
		t.Errorf("hostvars altered: %s", res.Meta.Hostvars["minion-A"])
	}
}

func TestCmdList_FlatInventoryOutputUnchanged(t *testing.T) {
	srv := serveInventory(t, `{"all":{"hosts":["h1"]},"_meta":{"hostvars":{"h1":{"ansible_connection":"relay"}}}}`, nil)
	out := captureList(t, config{serverURL: srv.URL})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 2 {
		t.Errorf("a flat inventory must not grow groups: %v", doc)
	}
	if strings.Contains(out, "children") {
		t.Errorf("no children expected:\n%s", out)
	}
}

func TestFetchInventory_ScopeRelayIsSentAndEscaped(t *testing.T) {
	var seen string
	srv := serveInventory(t, hierarchicalResponse, &seen)
	if _, err := fetchInventory(config{serverURL: srv.URL, scopeRelay: "dmz1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen, "relay=dmz1") {
		t.Errorf("request = %s, want relay=dmz1", seen)
	}
	if _, err := fetchInventory(config{serverURL: srv.URL, scopeRelay: "a b&x=1"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seen, "&x=1") {
		t.Errorf("the scope must be query-escaped, got %s", seen)
	}
	if _, err := fetchInventory(config{serverURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seen, "relay=") {
		t.Errorf("no scope requested: %s", seen)
	}
}

func TestLoadConfig_ScopeFromEnv(t *testing.T) {
	t.Setenv("RELAY_SCOPE", "zone2")
	if got := loadConfig().scopeRelay; got != "zone2" {
		t.Errorf("scopeRelay = %q", got)
	}
}

func TestCmdList_PassesGroupVarsThrough(t *testing.T) {
	srv := serveInventory(t, `{"_meta":{"hostvars":{}},"all":{"hosts":["a"],"children":["dmz1"]},
		"dmz1":{"hosts":["a"],"vars":{"env":"staging","replicas":3,"flags":{"x":true}}},"zone2":{"hosts":[]}}`, nil)
	out := captureList(t, config{serverURL: srv.URL})
	var res AnsibleInventory
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	v := res.Groups["dmz1"].Vars
	if string(v["env"]) != `"staging"` || string(v["replicas"]) != `3` || !strings.Contains(string(v["flags"]), `"x"`) {
		t.Errorf("vars altered: %v", v)
	}
	if len(res.Groups["zone2"].Vars) != 0 || strings.Contains(out, `"zone2": {`+"\n"+`    "hosts": [],`+"\n"+`    "vars"`) {
		t.Errorf("a group without vars must not grow a vars key:\n%s", out)
	}
}
