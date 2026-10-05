package hooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── relay_chain filter, template variables and upstream hand-off (#126) ──────

func TestHookFilter_Matches(t *testing.T) {
	var nilFilter *HookFilter
	tests := []struct {
		name   string
		filter *HookFilter
		chain  []string
		want   bool
	}{
		{"nil filter always matches (local event)", nilFilter, nil, true},
		{"nil filter always matches (remote event)", nilFilter, []string{"dmz1"}, true},
		{"contains: match", &HookFilter{RelayChainContains: "dmz1"}, []string{"dmz1", "zone2"}, true},
		{"contains: match in the middle", &HookFilter{RelayChainContains: "dmz1"}, []string{"zone-a", "dmz1", "zone2"}, true},
		{"contains: no match", &HookFilter{RelayChainContains: "dmz9"}, []string{"dmz1", "zone2"}, false},
		{"contains: local event has no chain", &HookFilter{RelayChainContains: "dmz1"}, nil, false},
		{"contains: exact id, not a prefix", &HookFilter{RelayChainContains: "dmz"}, []string{"dmz1"}, false},
	}
	for _, tt := range tests {
		if got := tt.filter.Matches(tt.chain); got != tt.want {
			t.Errorf("%s: Matches(%v) = %v, want %v", tt.name, tt.chain, got, tt.want)
		}
	}
}

func TestConfigValidate_FilterIsFailClosed(t *testing.T) {
	ok := func(f *HookFilter) HooksConfig {
		return HooksConfig{Hooks: []HookDef{{Event: "host.up", Filter: f, Actions: []ActionDef{{Type: "shell", Cmd: "true"}}}}}
	}
	for name, cfg := range map[string]HooksConfig{
		"no filter":    ok(nil),
		"valid filter": ok(&HookFilter{RelayChainContains: "dmz1"}),
	} {
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]HooksConfig{
		"empty filter object":     ok(&HookFilter{}),
		"relay id with a space":   ok(&HookFilter{RelayChainContains: "dmz 1"}),
		"relay id with a newline": ok(&HookFilter{RelayChainContains: "dmz1\nx"}),
		"relay id with a comma":   ok(&HookFilter{RelayChainContains: "a,b"}),
		"relay id with a slash":   ok(&HookFilter{RelayChainContains: "../x"}),
		"missing event":           {Hooks: []HookDef{{Actions: []ActionDef{{Type: "shell", Cmd: "true"}}}}},
	}
	for name, cfg := range bad {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestLoadConfig_RejectsInvalidFilterAsAWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(`{"hooks":[
		{"event":"host.up","actions":[{"type":"shell","cmd":"true"}]},
		{"event":"host.down","filter":{},"actions":[{"type":"shell","cmd":"true"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err == nil || cfg != nil {
		t.Fatalf("an invalid filter must reject the whole file (fail closed): cfg=%v err=%v", cfg, err)
	}
	// a valid file with the issue's example loads
	if err := os.WriteFile(path, []byte(`{"hooks":[
		{"event":"host.up","actions":[{"type":"shell","cmd":"notify-all.sh"}]},
		{"event":"host.down","filter":{"relay_chain_contains":"dmz1"},"actions":[{"type":"webhook","url":"https://soc.example.com/dmz1-alert"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(path)
	if err != nil || cfg == nil || cfg.Hooks[1].Filter == nil || cfg.Hooks[1].Filter.RelayChainContains != "dmz1" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

func TestBuildVars_RelayChainAndOrigin(t *testing.T) {
	v := buildVars("host.up", "h", "connected", "ts", "", []string{"dmz1", "zone2"})
	if v["relay_chain"] != "dmz1,zone2" || v["relay_origin"] != "dmz1" {
		t.Errorf("vars = %v", v)
	}
	local := buildVars("host.up", "h", "connected", "ts", "", nil)
	if local["relay_chain"] != "" || local["relay_origin"] != "" {
		t.Errorf("a local event has an empty chain: %v", local)
	}
	if got := Render("{{relay_origin}}|{{relay_chain}}", v); got != "dmz1|dmz1,zone2" {
		t.Errorf("Render = %q", got)
	}
}

// runDispatch sends events through a started dispatcher and returns the content of the files
// each hook appends to.
func startedDispatcher(t *testing.T, cfg *HooksConfig) *Dispatcher {
	t.Helper()
	d := NewDispatcher(&mockLogger{}, 50)
	d.SetConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.Start(ctx)
	return d
}

func readFileEventually(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never written", path)
	return ""
}

func TestDispatcher_FilterMatchAndNoMatch(t *testing.T) {
	dir := t.TempDir()
	match, noMatch, always := filepath.Join(dir, "match"), filepath.Join(dir, "nomatch"), filepath.Join(dir, "always")
	// distinct events so that "first matching hook wins" does not hide a hook
	cfg := &HooksConfig{Hooks: []HookDef{
		{Event: "host.down", Filter: &HookFilter{RelayChainContains: "dmz1"}, Actions: []ActionDef{{Type: "file", Path: match, Append: "M {{hostname}} chain={{relay_chain}} origin={{relay_origin}}\n"}}},
		{Event: "host.up", Filter: &HookFilter{RelayChainContains: "dmz9"}, Actions: []ActionDef{{Type: "file", Path: noMatch, Append: "NOMATCH\n"}}},
		{Event: "host.new", Actions: []ActionDef{{Type: "file", Path: always, Append: "ALWAYS {{hostname}} [{{relay_chain}}]\n"}}},
	}}
	d := startedDispatcher(t, cfg)

	d.DispatchChain("host.down", "deep-host", "disconnected", "", []string{"dmz1", "zone2"}) // 2 hops, filter matches
	d.DispatchChain("host.up", "deep-host", "connected", "", []string{"dmz1", "zone2"})      // filter does not match
	d.Dispatch("host.new", "local-host", "disconnected", "")                                 // local event, no filter
	d.DispatchChain("host.new", "one-hop-host", "disconnected", "", []string{"dmz1"})        // 1 hop, no filter

	if got := readFileEventually(t, match); got != "M deep-host chain=dmz1,zone2 origin=dmz1\n" {
		t.Errorf("filter match: %q", got)
	}
	got := readFileEventually(t, always)
	if !strings.Contains(got, "ALWAYS local-host []") {
		t.Errorf("local event (chain empty): %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(noMatch); err == nil {
		t.Error("a hook whose filter does not match the relay_chain must not run")
	}
	if got := readFileEventually(t, always); !strings.Contains(got, "ALWAYS one-hop-host [dmz1]") {
		t.Errorf("1 hop: %q", got)
	}
}

// ── upstream hand-off ────────────────────────────────────────────────────────

type sink struct {
	mu   sync.Mutex
	got  []string
	args [][4]string
}

func (s *sink) fn(event, hostname, status, enrolledAt string) {
	s.mu.Lock()
	s.got = append(s.got, event+"/"+hostname)
	s.args = append(s.args, [4]string{event, hostname, status, enrolledAt})
	s.mu.Unlock()
}

func TestDispatcher_LocalEventsOfPropagatedKindsGoUpstream(t *testing.T) {
	d := startedDispatcher(t, nil)
	s := &sink{}
	d.SetUpstream(s.fn)
	d.Dispatch("host.up", "a", "connected", "")
	d.Dispatch("host.down", "b", "disconnected", "")
	d.Dispatch("host.new", "c", "disconnected", "2026-10-05T09:00:00Z")
	d.Dispatch("host.revoked", "d", "revoked", "") // not a propagated kind
	d.Dispatch("host.conflict", "e", "x->y", "")   // handled by the relay layer, not here
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) != 3 || s.got[0] != "host.up/a" || s.got[1] != "host.down/b" || s.got[2] != "host.new/c" {
		t.Errorf("forwarded = %v, want host.up, host.down, host.new only", s.got)
	}
	if s.args[2][3] != "2026-10-05T09:00:00Z" {
		t.Errorf("enrolled_at lost: %v", s.args[2])
	}
}

func TestDispatcher_DispatchChainNeverForwardsUpstream(t *testing.T) {
	d := startedDispatcher(t, nil)
	s := &sink{}
	d.SetUpstream(s.fn)
	d.DispatchChain("host.up", "a", "connected", "", []string{"dmz1"}) // received from a child
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) != 0 {
		t.Errorf("a received event must not be handed to the upstream forwarder: %v", s.got)
	}
}

func TestPropagated(t *testing.T) {
	for ev, want := range map[string]bool{"host.up": true, "host.down": true, "host.new": true,
		"host.revoked": false, "host.deleted": false, "host.conflict": false, "": false, "host.UP": false} {
		if Propagated(ev) != want {
			t.Errorf("Propagated(%q) = %v, want %v", ev, !want, want)
		}
	}
}
