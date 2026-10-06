package integration

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #171 D — async/poll end to end: real ansible-playbook, real connection plugin, real server, real minion.
// The async wrapper and the async_status module both run ON the minion (no server route); the target
// command appends one line to a marker file per EXECUTION: the central assertion is always "exactly 1".

// rigWithMinion starts one node, one minion for host and the Ansible rig pointing at the node.
func asyncSetup(t *testing.T, host string) (n *node, m *minionProc, r *ansibleRig) {
	t.Helper()
	ansiblePlaybookBin(t) // skip (or fail under ANSIBLE_E2E=1) before starting anything heavy
	n = startNode(t, nodeSpec{ID: "root"})
	addr := nodeAddrs{api: strings.TrimPrefix(n.apiURL(), "https://"), ws: strings.TrimPrefix(n.wssURL(), "wss://")}
	m = startMinionProc(t, host, enrollmentToken(t, n, host), addr)
	m.waitConnections(1, "the minion is connected")
	waitFor(t, "the server serves the agent", func() bool { return agentServed(n, host, 1) })
	r = newAnsibleRig(t, host, n.pluginToken(), n.apiURL())
	return n, m, r
}

// D1: async + poll > 0, no switch-over: the long task finishes, rc and stdout come back, one execution.
func TestAnsibleAsync_D1_PollReturnsTheResultOfASingleExecution(t *testing.T) {
	parallel(t)
	_, _, r := asyncSetup(t, "async-d1")
	marker := filepath.Join(t.TempDir(), "runs")
	pb := r.play("d1", `- hosts: target
  gather_facts: false
  tasks:
    - name: long task, polled
      ansible.builtin.shell: "echo run >> `+marker+`; sleep 4; echo ok-d1"
      async: 60
      poll: 1
      register: res
    - name: the result is the one of the minion
      ansible.builtin.assert:
        that:
          - res.rc == 0
          - res.stdout == 'ok-d1'
          - res.finished == 1
`)
	rc, out := r.run(pb)
	if rc != 0 {
		t.Fatalf("playbook rc=%d:\n%s", rc, out)
	}
	if got := markerRuns(marker); got != 1 {
		t.Errorf("the task ran %d times, want exactly 1", got)
	}
}

// D2: fire-and-forget (poll 0), then async_status (a module run on the minion) until finished.
func TestAnsibleAsync_D2_FireAndForgetThenAsyncStatus(t *testing.T) {
	parallel(t)
	_, _, r := asyncSetup(t, "async-d2")
	marker := filepath.Join(t.TempDir(), "runs")
	pb := r.play("d2", `- hosts: target
  gather_facts: false
  tasks:
    - name: start and forget
      ansible.builtin.shell: "echo run >> `+marker+`; sleep 3; echo ok-d2"
      async: 60
      poll: 0
      register: job
    - name: the job is waited for with async_status
      ansible.builtin.async_status:
        jid: "{{ job.ansible_job_id }}"
      register: res
      until: res.finished
      retries: 30
      delay: 1
    - ansible.builtin.assert:
        that:
          - res.rc == 0
          - res.stdout == 'ok-d2'
`)
	rc, out := r.run(pb)
	if rc != 0 {
		t.Fatalf("playbook rc=%d:\n%s", rc, out)
	}
	if got := markerRuns(marker); got != 1 {
		t.Errorf("the task ran %d times, want exactly 1", got)
	}
}
