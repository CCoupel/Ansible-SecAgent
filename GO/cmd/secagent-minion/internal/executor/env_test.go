package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"strings"
	"sync"
	"testing"
)

func envMap(entries []string) map[string]string {
	m := map[string]string{}
	for _, kv := range entries {
		if n, v, ok := strings.Cut(kv, "="); ok {
			m[n] = v
		}
	}
	return m
}

func TestTaskEnv_AllowListOnly(t *testing.T) {
	got := envMap(TaskEnv([]string{
		"PATH=/usr/bin:/bin", "HOME=/home/svc", "LANG=fr_FR.UTF-8", "LC_ALL=C", "LC_TIME=en_GB", "TZ=UTC", "USER=svc",
		"LOGNAME=svc", "SHELL=/bin/bash", "TMPDIR=/tmp/x",
		// never passed
		"RELAY_ENROLLMENT_TOKEN=tok", "RELAY_JWT_PATH=/etc/jwt", "RELAY_PRIVATE_KEY=/etc/key", "RELAY_SERVER_URL=https://x",
		"FOO_TOKEN=t", "AWS_SECRET_ACCESS_KEY=k", "DB_PASSWORD=p", "API_KEY=k", "MY_SECRET=s", "SSH_AUTH_SOCK=/s", "EDITOR=vi",
		"malformed", "=novalue",
	}))
	for _, want := range []string{"PATH", "HOME", "LANG", "LC_ALL", "LC_TIME", "TZ", "USER", "LOGNAME", "SHELL", "TMPDIR"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s must be passed", want)
		}
	}
	if len(got) != 10 {
		t.Errorf("only the allow-listed variables may pass: %v", got)
	}
	for _, bad := range []string{"RELAY_ENROLLMENT_TOKEN", "RELAY_JWT_PATH", "RELAY_PRIVATE_KEY", "RELAY_SERVER_URL", "FOO_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "API_KEY", "MY_SECRET", "SSH_AUTH_SOCK", "EDITOR"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s must NOT be passed", bad)
		}
	}
}

func TestTaskEnv_DefaultPathAndForbiddenNames(t *testing.T) {
	if p := envMap(TaskEnv(nil))["PATH"]; p != DefaultPath {
		t.Errorf("PATH default = %q", p)
	}
	for _, name := range []string{"RELAY_X", "relay_x", "A_TOKEN", "a_key", "SOME_SECRET", "X_PASSWORD", "X_PASS"} {
		if !forbiddenEnv(name) {
			t.Errorf("%s must be forbidden", name)
		}
	}
	for _, name := range []string{"PATH", "HOME", "LANG", "LC_ALL", "USER", "TMPDIR"} {
		if forbiddenEnv(name) {
			t.Errorf("%s must be allowed", name)
		}
	}
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// A real subprocess: the minion's secrets are in ITS environment, a task running `env` sees none.
func TestRun_TaskDoesNotInheritTheMinionEnvironment(t *testing.T) {
	t.Setenv("RELAY_ENROLLMENT_TOKEN", "SUPER-ENROLLMENT-TOKEN")
	t.Setenv("RELAY_JWT_PATH", "/etc/secagent-minion/token.jwt")
	t.Setenv("RELAY_PRIVATE_KEY", "/etc/secagent-minion/id_rsa")
	t.Setenv("FOO_TOKEN", "FOO-SECRET-VALUE")
	t.Setenv("HOME", "/home/minion-user")
	t.Setenv("TMPDIR", t.TempDir())
	res := New().Run(context.Background(), ExecRequest{TaskID: "t1", Cmd: "env", Timeout: 10})
	if res.RC != 0 {
		t.Fatalf("env: rc %d stderr %q", res.RC, res.Stderr)
	}
	for _, leak := range []string{"SUPER-ENROLLMENT-TOKEN", "RELAY_", "FOO-SECRET-VALUE", "FOO_TOKEN", "token.jwt", "id_rsa"} {
		if strings.Contains(res.Stdout, leak) {
			t.Errorf("the task sees %q:\n%s", leak, res.Stdout)
		}
	}
	got := envMap(strings.Split(strings.TrimSpace(res.Stdout), "\n"))
	if got["HOME"] != "/home/minion-user" || got["TMPDIR"] == "" || got["PATH"] == "" {
		t.Errorf("HOME/PATH/TMPDIR must be those of the minion: %v", got)
	}
}

// environment: of a playbook is part of the command line (VAR=value cmd, built by Ansible's shell
// plugin): it is NOT lost by the allow-list.
func TestRun_AnsibleEnvironmentPrefixIsPreserved(t *testing.T) {
	res := New().Run(context.Background(), ExecRequest{TaskID: "t2", Cmd: `MYVAR=hello OTHER='a b' /bin/sh -c 'echo "$MYVAR|$OTHER"'`, Timeout: 10})
	if res.RC != 0 || strings.TrimSpace(res.Stdout) != "hello|a b" {
		t.Fatalf("rc %d stdout %q stderr %q", res.RC, res.Stdout, res.Stderr)
	}
}

// become_pass travels on stdin: never in the subprocess environment nor in the logs.
func TestRun_BecomePassStaysOnStdin(t *testing.T) {
	logs := &logBuf{}
	prev := log.Writer()
	log.SetOutput(logs)
	defer log.SetOutput(prev)
	const pass = "S3CR3T-BECOME-PASS"
	res := New().Run(context.Background(), ExecRequest{
		TaskID: "t3", Cmd: `env; echo "--stdin--"; cat`, Timeout: 10, Become: true,
		StdinB64: base64.StdEncoding.EncodeToString([]byte(pass + "\n")),
	})
	if res.RC != 0 {
		t.Fatalf("rc %d %q", res.RC, res.Stderr)
	}
	env, stdin, _ := strings.Cut(res.Stdout, "--stdin--")
	if strings.Contains(env, pass) {
		t.Error("become_pass is in the subprocess environment")
	}
	if !strings.Contains(stdin, pass) {
		t.Error("become_pass must reach the subprocess on stdin")
	}
	if strings.Contains(logs.String(), pass) {
		t.Errorf("become_pass in the logs:\n%s", logs.String())
	}
}
