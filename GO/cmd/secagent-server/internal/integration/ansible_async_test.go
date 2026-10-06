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

// asyncFailover starts the master A, a standby B on one state, a minion with the list [A, B] and the
// Ansible rig whose plugin lists both API addresses.
func asyncFailover(t *testing.T, host string) (a, b *node, m *minionProc, r *ansibleRig) {
	t.Helper()
	ansiblePlaybookBin(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a = startNode(t, nodeSpec{ID: "root", Env: addrA.env()})
	b = a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	m = startMinionProc(t, host, enrollmentToken(t, a, host), addrA, addrB)
	m.waitConnections(1, "the minion is connected to the master")
	waitFor(t, "A serves the agent", func() bool { return agentServed(a, host, 1) })
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	r = newAnsibleRig(t, host, a.pluginToken(), "https://"+addrA.api, "https://"+addrB.api)
	return a, b, m, r
}

var jidRE = regexp.MustCompile(`JID\[([a-z0-9_]+)\]=([A-Za-z0-9_.-]+)`)

// startJobs runs a playbook that launches fire-and-forget jobs and prints their ids ("JID[name]=<id>").
func startJobs(t *testing.T, r *ansibleRig, pb string) map[string]string {
	t.Helper()
	rc, out := r.run(pb)
	if rc != 0 {
		t.Fatalf("job launcher rc=%d:\n%s", rc, out)
	}
	ids := map[string]string{}
	for _, m := range jidRE.FindAllStringSubmatch(out, -1) {
		ids[m[1]] = m[2]
	}
	return ids
}

// D3: an async job is launched, the master is stopped cleanly while it runs on the minion. The job goes
// on (independently of the relay); the minion reconnects to the new master through its list; an
// async_status issued AFTER the switch-over returns the real state (finished, rc, stdout); the marker
// holds exactly one execution.
func TestAnsibleAsync_D3_JobSurvivesACleanStopOfTheMasterAndIsReadAfterwards(t *testing.T) {
	parallel(t)
	a, b, m, r := asyncFailover(t, "async-d3")
	marker := filepath.Join(t.TempDir(), "runs")
	ids := startJobs(t, r, r.play("d3-start", `- hosts: target
  gather_facts: false
  tasks:
    - ansible.builtin.shell: "echo run >> `+marker+`; sleep 12; echo ok-d3"
      async: 120
      poll: 0
      register: job
    - ansible.builtin.debug:
        msg: "JID[job]={{ job.ansible_job_id }}"
`))
	waitFor(t, "the job started on the minion (marker written)", func() bool { return markerRuns(marker) >= 1 })

	a.stop() // clean stop: the lock is released, B takes over
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over; logs:\n%s", b.logs.String())
	}
	m.waitConnections(2, "the minion reconnected to the new master")
	waitFor(t, "the new master serves the agent", func() bool { return agentServed(b, "async-d3", 1) })

	rc, out := r.run(r.play("d3-status", `- hosts: target
  gather_facts: false
  tasks:
    - ansible.builtin.async_status:
        jid: "`+ids["job"]+`"
      register: res
      until: res.finished
      retries: 40
      delay: 1
    - ansible.builtin.assert:
        that:
          - res.rc == 0
          - res.stdout == 'ok-d3'
`))
	if rc != 0 {
		t.Fatalf("async_status after the switch-over rc=%d:\n%s", rc, out)
	}
	if got := markerRuns(marker); got != 1 {
		t.Errorf("the job ran %d times across the switch-over, want exactly 1", got)
	}
}

// D3 (variant): the playbook is POLLING (poll > 0) when the master is stopped. Whatever happens to the
// task on the Ansible side (a poll in flight fails without replay; a later poll may reach the new master),
// the job is never started again: the marker holds exactly one execution and ansible-playbook ends.
func TestAnsibleAsync_D3_PollInFlightAtTheStopNeverRerunsTheJob(t *testing.T) {
	parallel(t)
	a, b, m, r := asyncFailover(t, "async-d3b")
	marker := filepath.Join(t.TempDir(), "runs")
	run := r.start(r.play("d3b", `- hosts: target
  gather_facts: false
  tasks:
    - ansible.builtin.shell: "echo run >> `+marker+`; sleep 12; echo ok-d3b"
      async: 120
      poll: 1
      register: res
`))
	waitFor(t, "the job started on the minion (marker written)", func() bool { return markerRuns(marker) >= 1 })
	a.stop()
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over; logs:\n%s", b.logs.String())
	}
	m.waitConnections(2, "the minion reconnected to the new master")
	rc, out := run.Wait(t) // success or UNREACHABLE/FAILED: both are acceptable, a hang or a re-run is not
	t.Logf("playbook ended with rc=%d", rc)
	if got := markerRuns(marker); got != 1 {
		t.Errorf("the job ran %d times, want exactly 1 (playbook output:\n%s)", got, out)
	}
}

// D4: two jobs (different rc and stdout) started BEFORE a kill -9 of the master are read AFTER the take-over:
// each result is exactly what the minion produced for THAT job (no loss, no mix-up), one execution each.
func TestAnsibleAsync_D4_ResultsAfterAKillMatchTheirJobs(t *testing.T) {
	parallel(t)
	a, b, m, r := asyncFailover(t, "async-d4")
	dir := t.TempDir()
	m1, m2 := filepath.Join(dir, "runs1"), filepath.Join(dir, "runs2")
	ids := startJobs(t, r, r.play("d4-start", `- hosts: target
  gather_facts: false
  tasks:
    - ansible.builtin.shell: "echo run >> `+m1+`; sleep 10; echo out-one"
      async: 120
      poll: 0
      register: job1
    - ansible.builtin.shell: "echo run >> `+m2+`; sleep 10; echo out-two; exit 3"
      async: 120
      poll: 0
      register: job2
    - ansible.builtin.debug:
        msg: "JID[one]={{ job1.ansible_job_id }} JID[two]={{ job2.ansible_job_id }}"
`))
	if ids["one"] == "" || ids["two"] == "" || ids["one"] == ids["two"] {
		t.Fatalf("two distinct job ids expected, got %v", ids)
	}
	waitFor(t, "both jobs started", func() bool { return markerRuns(m1) >= 1 && markerRuns(m2) >= 1 })

	a.killNow()
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over after the kill -9; logs:\n%s", b.logs.String())
	}
	m.waitConnections(2, "the minion reconnected to the new master")
	waitFor(t, "the new master serves the agent", func() bool { return agentServed(b, "async-d4", 1) })

	rc, out := r.run(r.play("d4-status", `- hosts: target
  gather_facts: false
  tasks:
    - ansible.builtin.async_status:
        jid: "`+ids["one"]+`"
      register: one
      until: one.finished
      retries: 40
      delay: 1
      failed_when: false
    - ansible.builtin.async_status:
        jid: "`+ids["two"]+`"
      register: two
      until: two.finished
      retries: 40
      delay: 1
      failed_when: false
    - ansible.builtin.assert:
        that:
          - one.rc == 0
          - one.stdout == 'out-one'
          - two.rc == 3
          - two.stdout == 'out-two'
`))
	if rc != 0 {
		t.Fatalf("results after the take-over rc=%d:\n%s", rc, out)
	}
	for name, p := range map[string]string{"one": m1, "two": m2} {
		if got := markerRuns(p); got != 1 {
			t.Errorf("job %s ran %d times, want exactly 1", name, got)
		}
	}
}
