package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An Ansible control node for the E2E scenarios: the REAL ansible-playbook (ansible-core pinned in
// .github/ci/requirements-ansible.txt), the REAL connection plugin SECAGENT-PYTHON/…/relay.py with a
// 0600 token file, real nodes (TLS, test CA) and a real minion binary on the same machine (no Docker).
// Nothing is installed or written outside the test's temporary directories (ANSIBLE_HOME, HOME, tmp).

// requireAnsibleE2E gates EVERY test that needs Ansible: they run only when ANSIBLE_E2E=1 is set (the
// mandatory "Inventaire Ansible" job sets it, in a throw-away venv holding ansible-core AND httpx).
// The presence of ansible on the PATH never decides: a runner that happens to have ansible-playbook
// but not httpx (the "Build + tests Go" job) must SKIP, not fail halfway.
func requireAnsibleE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("ANSIBLE_E2E") != "1" {
		t.Skip("Ansible E2E tests are opt-in: set ANSIBLE_E2E=1 (with ansible-core and httpx from .github/ci/requirements-ansible.txt installed in a venv on the PATH)")
	}
}

// ansiblePlaybookBin returns ansible-playbook for the rig. Under ANSIBLE_E2E=1 a missing tool, or a
// missing httpx in the Python of ansible-playbook (the relay.py connection plugin imports it), is a
// FAILURE with an actionable message: never a skip, never a half-run.
func ansiblePlaybookBin(t *testing.T) string {
	t.Helper()
	requireAnsibleE2E(t)
	path, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Fatalf("ANSIBLE_E2E=1 but ansible-playbook is not on PATH: %v (install .github/ci/requirements-ansible.txt in a venv and put its bin first on the PATH)", err)
	}
	python := playbookPython(path)
	if out, err := exec.Command(python, "-c", "import httpx").CombinedOutput(); err != nil {
		t.Fatalf("ANSIBLE_E2E=1 but httpx cannot be imported by the Python of ansible-playbook (%s): %v\n%s\nthe relay.py connection plugin requires it: install .github/ci/requirements-ansible.txt in that environment", python, err, out)
	}
	return path
}

// playbookPython is the interpreter ansible-playbook runs with: the python next to the script (a venv's
// bin/ holds both; pip's console scripts start with "#!/bin/sh" and re-exec it), else the one named by
// a plain shebang, else python3 from the PATH.
func playbookPython(playbook string) string {
	if real, err := filepath.EvalSymlinks(playbook); err == nil {
		playbook = real
	}
	for _, name := range []string{"python3", "python"} {
		if p := filepath.Join(filepath.Dir(playbook), name); fileExists(p) {
			return p
		}
	}
	if b, err := os.ReadFile(playbook); err == nil {
		if first, _, _ := strings.Cut(string(b), "\n"); strings.HasPrefix(first, "#!") {
			if f := strings.Fields(strings.TrimPrefix(first, "#!")); len(f) > 0 && filepath.Base(f[0]) != "sh" {
				if filepath.Base(f[0]) == "env" && len(f) > 1 {
					if p, err := exec.LookPath(f[1]); err == nil {
						return p
					}
				} else {
					return f[0]
				}
			}
		}
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p
	}
	return "python3"
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// pluginDir is SECAGENT-PYTHON/ansible_plugins/connection_plugins of the repository.
func pluginDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs("../../../../../SECAGENT-PYTHON/ansible_plugins/connection_plugins")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "relay.py")); err != nil {
		t.Fatalf("connection plugin not found: %v", err)
	}
	return d
}

type ansibleRig struct {
	t         *testing.T
	bin       string
	dir       string
	inv       string
	host      string
	apis      []string
	tokenFile string
}

// newAnsibleRig prepares the inventory of one host reached through the relay plugin with the given
// server API addresses (the plugin tries them in order) and the plugin token of the node.
func newAnsibleRig(t *testing.T, host, pluginToken string, apis ...string) *ansibleRig {
	t.Helper()
	r := &ansibleRig{t: t, bin: ansiblePlaybookBin(t), dir: t.TempDir(), host: host, apis: apis}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 not found for the target modules: %v", err)
	}
	tokenFile := filepath.Join(r.dir, "plugin.jwt")
	if err := os.WriteFile(tokenFile, []byte(pluginToken), 0o600); err != nil {
		t.Fatal(err)
	}
	r.inv = filepath.Join(r.dir, "inventory.ini")
	r.tokenFile = tokenFile
	// The plugin reads its options from the environment (RELAY_*): see start()
	inv := fmt.Sprintf("[target]\n%s ansible_connection=relay ansible_python_interpreter=%s\n", host, python)
	if err := os.WriteFile(r.inv, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// play writes a playbook file and returns its path.
func (r *ansibleRig) play(name, body string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, name+".yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// start launches ansible-playbook and returns a handle; Wait returns its exit code and combined output.
func (r *ansibleRig) start(playbook string, extra ...string) *ansibleRun {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	args := append([]string{"-i", r.inv, playbook}, extra...)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"HOME="+r.dir, "ANSIBLE_HOME="+filepath.Join(r.dir, "ansible-home"),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(r.dir, "local-tmp"),
		"ANSIBLE_CONNECTION_PLUGINS="+pluginDir(r.t),
		"ANSIBLE_HOST_KEY_CHECKING=False", "ANSIBLE_NOCOLOR=1", "ANSIBLE_FORCE_COLOR=0",
		"ANSIBLE_RETRY_FILES_ENABLED=False", "ANSIBLE_DEPRECATION_WARNINGS=False",
		"ANSIBLE_INTERPRETER_PYTHON_FALLBACK=",
		"RELAY_SERVER_URL="+strings.Join(r.apis, ","), "RELAY_TOKEN_FILE="+r.tokenFile, "RELAY_CA_BUNDLE="+certPath,
		"RELAY_CONNECT_TIMEOUT=3",
	)
	run := &ansibleRun{cancel: cancel, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = &run.out, &run.out
	if err := cmd.Start(); err != nil {
		cancel()
		r.t.Fatal(err)
	}
	go func() {
		err := cmd.Wait()
		run.rc = 0
		if ee, ok := err.(*exec.ExitError); ok {
			run.rc = ee.ExitCode()
		} else if err != nil {
			run.rc = -1
		}
		close(run.done)
	}()
	r.t.Cleanup(func() { cancel(); <-run.done })
	return run
}

// run is start + Wait.
func (r *ansibleRig) run(playbook string, extra ...string) (int, string) {
	r.t.Helper()
	return r.start(playbook, extra...).Wait(r.t)
}

type ansibleRun struct {
	cancel func()
	done   chan struct{}
	out    bytes.Buffer
	rc     int
}

func (a *ansibleRun) Wait(t *testing.T) (int, string) {
	t.Helper()
	select {
	case <-a.done:
	case <-time.After(5 * time.Minute):
		t.Fatalf("ansible-playbook did not end:\n%s", a.out.String())
	}
	return a.rc, a.out.String()
}

// markerRuns is the number of executions recorded in a marker file ("run\n" per execution).
func markerRuns(path string) int {
	b, _ := os.ReadFile(path)
	return strings.Count(string(b), "run\n")
}
