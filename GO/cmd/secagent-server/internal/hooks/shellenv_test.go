package hooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestShellEnvironment_AllowListOnly(t *testing.T) {
	server := []string{
		"ADMIN_TOKEN=a", "JWT_SECRET_KEY=j", "RSA_MASTER_KEY=r", "REPEATER_UPSTREAM_TOKEN=u", "RELAY_ENROLLMENT_TOKEN=e",
		"FOO=bar", "MY_API_KEY=k", "DB_SECRET=s", "PATH=/evil/bin", "HOME=/home/svc", "LANG=fr_FR.UTF-8", "LC_ALL=C", "TZ=UTC",
		"LD_PRELOAD=/x.so", "TLS_KEY=/k",
	}
	vars := map[string]string{"event": "host.up", "hostname": "h1", "timestamp": "T", "status": "connected",
		"enrolled_at": "E", "relay_chain": "r1,r2", "relay_origin": "r1"}
	got := envMap(shellEnvironment(server, map[string]string{"HOOK_TOKEN": "own-{{hostname}}"}, vars))

	want := map[string]string{
		"PATH": safePath, "HOME": "/home/svc", "LANG": "fr_FR.UTF-8", "LC_ALL": "C", "TZ": "UTC",
		"SECAGENT_EVENT": "host.up", "SECAGENT_HOSTNAME": "h1", "SECAGENT_TIMESTAMP": "T", "SECAGENT_STATUS": "connected",
		"SECAGENT_ENROLLED_AT": "E", "SECAGENT_RELAY_CHAIN": "r1,r2", "SECAGENT_RELAY_ORIGIN": "r1",
		"HOOK_TOKEN": "own-h1",
	}
	if len(got) != len(want) {
		t.Errorf("unexpected variables: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, leaked := range []string{"ADMIN_TOKEN", "JWT_SECRET_KEY", "RSA_MASTER_KEY", "REPEATER_UPSTREAM_TOKEN", "RELAY_ENROLLMENT_TOKEN", "FOO", "MY_API_KEY", "DB_SECRET", "LD_PRELOAD", "TLS_KEY"} {
		if _, ok := got[leaked]; ok {
			t.Errorf("%s must never be inherited", leaked)
		}
	}
}

func TestShellEnvironment_DefaultsAndEventVariablesWin(t *testing.T) {
	got := envMap(shellEnvironment(nil, nil, map[string]string{"event": "e", "hostname": "h", "timestamp": "t", "status": "s"}))
	if got["HOME"] != "/nonexistent" || got["PATH"] != safePath {
		t.Errorf("defaults: %v", got)
	}
	if _, ok := got["SECAGENT_ENROLLED_AT"]; ok {
		t.Error("SECAGENT_ENROLLED_AT only when set")
	}
}

func TestValidate_EnvRules(t *testing.T) {
	cfg := func(a ActionDef) *HooksConfig {
		return &HooksConfig{Hooks: []HookDef{{Event: "host.up", Actions: []ActionDef{a}}}}
	}
	ok := ActionDef{Type: "shell", Cmd: "/bin/true", Env: map[string]string{"HOOK_TOKEN": "x", "MY_API_KEY": "own-secret"}}
	if err := cfg(ok).Validate(); err != nil {
		t.Errorf("a hook's own secret is allowed: %v", err)
	}
	for name, a := range map[string]ActionDef{
		"ADMIN_TOKEN":      {Type: "shell", Env: map[string]string{"ADMIN_TOKEN": "x"}},
		"JWT_SECRET_KEY":   {Type: "shell", Env: map[string]string{"JWT_SECRET_KEY": "x"}},
		"RSA_MASTER_KEY":   {Type: "shell", Env: map[string]string{"RSA_MASTER_KEY": "x"}},
		"upstream token":   {Type: "shell", Env: map[string]string{"REPEATER_UPSTREAM_TOKEN": "x"}},
		"enrollment":       {Type: "shell", Env: map[string]string{"RELAY_ENROLLMENT_TOKEN": "x"}},
		"case-insensitve":  {Type: "shell", Env: map[string]string{"admin_token": "x"}},
		"SECAGENT_ prefix": {Type: "shell", Env: map[string]string{"SECAGENT_EVENT": "x"}},
		"bad name":         {Type: "shell", Env: map[string]string{"A=B": "x"}},
		"not a shell":      {Type: "webhook", URL: "https://h", Env: map[string]string{"A": "x"}},
	} {
		if err := cfg(a).Validate(); err == nil {
			t.Errorf("%s: the configuration must be refused", name)
		}
	}
}

// What the other executors emit never contains a variable of the server's environment.
func TestOtherExecutorsNeverEmitServerEnvironment(t *testing.T) {
	const secret = "SERVER-ENV-SECRET-VALUE"
	t.Setenv("ADMIN_TOKEN", secret)
	t.Setenv("RSA_MASTER_KEY", secret)
	t.Setenv("SOME_OTHER_VAR", secret)

	var mu sync.Mutex
	var seen strings.Builder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hdr, _ := json.Marshal(r.Header)
		mu.Lock()
		seen.WriteString(r.URL.String() + string(hdr) + string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "out")
	vars := map[string]string{"event": "host.up", "hostname": "h", "timestamp": "t", "status": "s"}
	d := NewDispatcher(nil, 1)
	for _, a := range []ActionDef{
		{Type: "webhook", URL: srv.URL + "/w", Secret: "hmac", TimeoutSeconds: 3},
		{Type: "api", Method: "POST", URL: srv.URL + "/a", Body: map[string]string{"k": "v"}, TimeoutSeconds: 3},
		{Type: "file", Path: out, Append: "{{event}} {{hostname}}\n"},
	} {
		if ok, msg, _ := map[string]Executor{"webhook": d.webhookExec, "api": d.apiExec, "file": d.fileExec}[a.Type].Execute(context.Background(), a, vars); !ok {
			t.Fatalf("%s: %s", a.Type, msg)
		}
	}
	file, _ := os.ReadFile(out)
	mu.Lock()
	all := seen.String() + string(file)
	mu.Unlock()
	if strings.Contains(all, secret) {
		t.Errorf("a server variable leaked: %s", all)
	}
}

// Real subprocess: the script sees the allow-list, the event variables and the declared env only.
func TestShellExecutor_RealProcessSeesOnlyTheAllowList(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "LEAK-ADMIN")
	t.Setenv("JWT_SECRET_KEY", "LEAK-JWT")
	t.Setenv("RSA_MASTER_KEY", "LEAK-RSA")
	t.Setenv("REPEATER_UPSTREAM_TOKEN", "LEAK-UP")
	t.Setenv("FOO", "bar")
	out := filepath.Join(t.TempDir(), "env.out")
	action := ActionDef{Type: "shell", Cmd: "/bin/sh", Args: []string{"-c", "env > " + out}, TimeoutSeconds: 5,
		Env: map[string]string{"HOOK_OWN_TOKEN": "own-secret"}}
	vars := map[string]string{"event": "host.up", "hostname": "h1", "timestamp": "T", "status": "connected"}
	if ok, msg, _ := (&ShellExecutor{}).Execute(context.Background(), action, vars); !ok {
		t.Fatal(msg)
	}
	b, _ := os.ReadFile(out)
	text := string(b)
	for _, leak := range []string{"LEAK-", "FOO=", "ADMIN_TOKEN", "JWT_SECRET_KEY", "RSA_MASTER_KEY", "REPEATER_UPSTREAM_TOKEN"} {
		if strings.Contains(text, leak) {
			t.Errorf("the hook process sees %q:\n%s", leak, text)
		}
	}
	for _, want := range []string{"SECAGENT_EVENT=host.up", "SECAGENT_HOSTNAME=h1", "HOOK_OWN_TOKEN=own-secret", "PATH=" + safePath} {
		if !strings.Contains(text, want) {
			t.Errorf("%q missing:\n%s", want, text)
		}
	}
}

// A forged hostname (control characters) can not add a variable to the hook's environment, and the
// event variables are the only values sanitised.
func TestShellEnvironment_ControlCharactersOfEventDataAreReplaced(t *testing.T) {
	vars := map[string]string{"event": "host.up", "hostname": "a\nB=c", "timestamp": "T\x00x", "status": "s\x1b[31m\x7f", "relay_chain": "r1,\nr2", "relay_origin": "r1\r"}
	env := shellEnvironment(nil, map[string]string{"MULTI": "line1\nline2", "FROM_EVENT": "{{hostname}}"}, vars)
	for _, kv := range env {
		if strings.ContainsAny(strings.SplitN(kv, "=", 2)[1], "\n\r\x00\x1b\x7f") && !strings.HasPrefix(kv, "MULTI=") {
			t.Errorf("control character in %q", kv)
		}
	}
	got := envMap(env)
	if got["SECAGENT_HOSTNAME"] != "a_B=c" || got["SECAGENT_TIMESTAMP"] != "T_x" || got["SECAGENT_STATUS"] != "s_[31m_" ||
		got["SECAGENT_RELAY_CHAIN"] != "r1,_r2" || got["FROM_EVENT"] != "a_B=c" {
		t.Errorf("sanitised values: %v", got)
	}
	if _, injected := got["B"]; injected {
		t.Error("a forged hostname must not inject a variable")
	}
	if got["MULTI"] != "line1\nline2" {
		t.Errorf("an operator-declared value is kept as written: %q", got["MULTI"])
	}
	// a real process: NUL in a hostname used to make the start fail
	out := filepath.Join(t.TempDir(), "env.out")
	ok, msg, _ := (&ShellExecutor{}).Execute(context.Background(), ActionDef{Type: "shell", Cmd: "/bin/sh", Args: []string{"-c", "echo $SECAGENT_HOSTNAME > " + out}, TimeoutSeconds: 5},
		map[string]string{"event": "e", "hostname": "x\x00y\nZ=1", "timestamp": "t", "status": "s"})
	if b, _ := os.ReadFile(out); !ok || strings.TrimSpace(string(b)) != "x_y_Z=1" {
		t.Errorf("ok=%v msg=%q out=%q", ok, msg, b)
	}
}
