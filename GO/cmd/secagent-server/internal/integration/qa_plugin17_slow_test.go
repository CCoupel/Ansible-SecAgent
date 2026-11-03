// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// QA lot 6: a blocking exec of 17 s driven by the REAL Python plugin (relay.Connection.exec_command)
// against a real node; the simulated agent answers after 17 s with 256 KiB.
func TestQAWriteTimeout_PythonPluginExec17s(t *testing.T) {
	parallel(t)
	// the REAL plugin of the repository, run by the python3 of the PATH: it needs ansible-core and httpx
	//; without them the test is skipped, not failed (the Go side of the same
	// regression is TestExec_AnAnswerLongerThanTheAPIWriteTimeoutArrivesIntact)
	py3, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	if out, err := exec.Command(py3, "-I", "-c", "import ansible, httpx").CombinedOutput(); err != nil {
		t.Skipf("python3 cannot import ansible and httpx (pip install ansible-core httpx): %s", strings.TrimSpace(string(out)))
	}
	plug, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "..", "SECAGENT-PYTHON"))
	if err != nil {
		t.Fatal(err)
	}
	n := startNode(t, nodeSpec{ID: "root"})
	m := heldMinions(t, n, "slow-host")["slow-host"]
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte(n.pluginToken()), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.py")
	py := `
import io, sys, time
sys.path.insert(0, %q)
from ansible.playbook.play_context import PlayContext
from ansible_plugins.connection_plugins import relay
pc = PlayContext(); pc.remote_addr = "slow-host"
c = relay.Connection(pc, io.StringIO())
t0 = time.time()
rc, out, err = c.exec_command("sleep 17", sudoable=False)
print("RESULT rc=%%d stdout_len=%%d err_len=%%d elapsed=%%.1f" %% (rc, len(out), len(err), time.time()-t0))
`
	if err := os.WriteFile(script, []byte(fmt.Sprintf(py, plug)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py3, "-I", script)
	cmd.Env = append(os.Environ(), "RELAY_SERVER_URL="+n.apiURL(), "RELAY_TOKEN_FILE="+tok, "RELAY_TIMEOUT=60", "RELAY_CONNECT_TIMEOUT=5", "RELAY_CA_BUNDLE="+certPath,
		"PYTHONPATH="+plug)
	done := make(chan string, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		done <- string(out) + fmt.Sprintf(" [exit err=%v]", err)
	}()
	waitReceived(t, m, 1)
	time.Sleep(17 * time.Second)
	payload := strings.Repeat("0123456789abcdef", 16<<10)
	m.write(map[string]any{"task_id": m.received()[0], "type": "result", "rc": 0, "stdout": payload})
	select {
	case out := <-done:
		t.Logf("python plugin output: %s", strings.TrimSpace(out))
		if !strings.Contains(out, fmt.Sprintf("RESULT rc=0 stdout_len=%d", len(payload))) {
			t.Errorf("answer not intact through the plugin: %s", out)
		}
	case <-time.After(70 * time.Second):
		t.Fatal("plugin never returned")
	}
}
