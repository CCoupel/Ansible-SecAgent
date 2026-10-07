package ws

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func setLimits(t *testing.T, perAgent, inflight int, budget int64) {
	t.Helper()
	resetAdmission()
	SetTaskLimits(perAgent, inflight, budget)
	t.Cleanup(resetAdmission)
}

func TestAdmission_PerAgentGlobalAndBudgetRefusalsAreTyped(t *testing.T) {
	setLimits(t, 2, 3, 12<<20)
	for _, id := range []string{"a1", "a2"} {
		if _, err := RegisterFuture(id, "host-a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RegisterFuture("a3", "host-a"); !errors.Is(err, ErrAgentBusy) {
		t.Errorf("3rd task of one agent: %v, want ErrAgentBusy", err)
	}
	if _, err := RegisterFuture("b1", "host-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterFuture("c1", "host-c"); !errors.Is(err, ErrTooManyTasks) {
		t.Errorf("4th task of the node: %v, want ErrTooManyTasks", err)
	}
	if inFlightAll() != 3 || inFlightOf("host-a") != 2 {
		t.Errorf("a refusal must not count: all=%d host-a=%d", inFlightAll(), inFlightOf("host-a"))
	}
	// the budget: 12 MiB, 8 MiB held leave 4 MiB < 5 MiB
	resetAdmission()
	SetTaskLimits(10, 100, 12<<20)
	_, _ = RegisterFuture("m1", "h1")
	_, _ = RegisterFuture("m2", "h2")
	for _, id := range []string{"m1", "m2"} {
		HandleMessage(Message{TaskID: id, Type: "stdout", Chunk: strings.Repeat("x", 4<<20)}, "h")
	}
	if got := stdoutHeldBytes(); got != 8<<20 {
		t.Fatalf("held = %d, want 8 MiB", got)
	}
	if _, err := RegisterFuture("m3", "h3"); !errors.Is(err, ErrMemoryBudget) {
		t.Errorf("budget exhausted: %v, want ErrMemoryBudget", err)
	}
	HandleMessage(Message{TaskID: "m1", Type: "result"}, "h1")
	if _, err := RegisterFuture("m3", "h3"); err != nil {
		t.Errorf("after a release: %v", err)
	}
}

// A purge runs exactly once: a second result, an unregister after the result, or a disconnection of
// the host must never release a slot that belongs to another task.
func TestAdmission_ReleaseIsIdempotent(t *testing.T) {
	setLimits(t, 2, 10, 0)
	_, _ = RegisterFuture("t1", "h")
	_, _ = RegisterFuture("t2", "h")
	HandleMessage(Message{TaskID: "t1", Type: "result"}, "h")
	HandleMessage(Message{TaskID: "t1", Type: "result"}, "h") // duplicated result
	UnregisterFuture("t1")                                    // timeout racing the result
	if got := inFlightOf("h"); got != 1 {
		t.Fatalf("counter = %d, want 1 (t2 still running)", got)
	}
	if _, err := RegisterFuture("t3", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterFuture("t4", "h"); !errors.Is(err, ErrAgentBusy) {
		t.Errorf("the agent must be at its limit (2), got %v", err)
	}
	ResolveFuturesForHostname("h", "agent_disconnected")
	ResolveFuturesForHostname("h", "agent_disconnected")
	if inFlightAll() != 0 || inFlightOf("h") != 0 || stdoutHeldBytes() != 0 {
		t.Errorf("after the disconnection: all=%d host=%d stdout=%d, want 0", inFlightAll(), inFlightOf("h"), stdoutHeldBytes())
	}
	// re-registering a task id never counts twice
	_, _ = RegisterFuture("same", "h")
	_, _ = RegisterFuture("same", "h")
	if inFlightOf("h") != 1 {
		t.Errorf("re-registration counted twice: %d", inFlightOf("h"))
	}
}

func TestAdmission_StdoutIsTruncatedWhenTheBudgetRunsOutMidway(t *testing.T) {
	setLimits(t, 10, 100, 6<<20)
	_, _ = RegisterFuture("big", "h")
	_, _ = RegisterFuture("big2", "h2")
	HandleMessage(Message{TaskID: "big", Type: "stdout", Chunk: strings.Repeat("x", 4<<20)}, "h")
	HandleMessage(Message{TaskID: "big2", Type: "stdout", Chunk: strings.Repeat("y", 4<<20)}, "h2") // only 2 MiB fit
	if got := stdoutHeldBytes(); got != 6<<20 {
		t.Errorf("held = %d, want the 6 MiB budget", got)
	}
	// stdout of a task that was never admitted keeps nothing
	HandleMessage(Message{TaskID: "ghost", Type: "stdout", Chunk: "zzz"}, "h")
	buffersMu.RLock()
	_, kept := stdoutBuffers["ghost"]
	buffersMu.RUnlock()
	if kept && stdoutBuffers["ghost"] != "" {
		t.Error("stdout of an unknown task must be dropped")
	}
	UnregisterFuture("big")
	UnregisterFuture("big2")
	if stdoutHeldBytes() != 0 {
		t.Errorf("held after release = %d", stdoutHeldBytes())
	}
}

func TestAdmission_RelayedTasksAreCountedInTheGlobalLimitAndOwnedByTheirRelay(t *testing.T) {
	setLimits(t, 10, 2, 0)
	t.Cleanup(func() {
		relayTasksMu.Lock()
		relayPendingTasks = make(map[string]chan RelayTaskResult)
		relayTaskOwner = make(map[string]string)
		relayTasksMu.Unlock()
	})
	if _, err := RegisterRelayTaskFuture("r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterFuture("l1", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterRelayTaskFuture("r2"); !errors.Is(err, ErrTooManyTasks) {
		t.Errorf("relayed task over the global limit: %v, want ErrTooManyTasks", err)
	}
	UnregisterRelayTaskFuture("r1")
	UnregisterRelayTaskFuture("r1")
	if inFlightAll() != 1 {
		t.Errorf("global counter = %d, want 1", inFlightAll())
	}
	// a relay only answers the tasks dispatched to it
	ch, _ := RegisterRelayTaskFuture("owned")
	relayTasksMu.Lock()
	relayTaskOwner["owned"] = "relay-a"
	relayTasksMu.Unlock()
	handleRelayMessage(&RelayConnection{RelayID: "relay-b"}, RelayMessage{Type: "task_result", TaskID: "owned", RC: 0})
	select {
	case <-ch:
		t.Error("relay-b resolved a task dispatched to relay-a")
	default:
	}
	handleRelayMessage(&RelayConnection{RelayID: "relay-a"}, RelayMessage{Type: "task_result", TaskID: "owned", RC: 0})
	select {
	case <-ch:
	default:
		t.Error("the owner must resolve its task")
	}
	if got := inFlightAll(); got != 1 {
		t.Errorf("global counter after the owner's result = %d, want 1 (l1)", got)
	}
	_ = fmt.Sprint()
}
