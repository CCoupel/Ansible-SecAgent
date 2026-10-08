package ws

import (
	"testing"
	"time"
)

// A task relayed through an intermediate node holds a slot (and 5 MiB of budget) on EVERY hop: it must
// be freed when the child answers (the waiter of forward.go does not unregister it, ws does), and when
// the child link ends. A forgotten release would end in a permanent 429 too_many_tasks (#179, QA).
func TestAdmission_RelayedTaskSlotIsFreedByTheResultOfTheChild(t *testing.T) {
	setLimits(t, 10, 5, 0)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("child1", "relay"))
	handshake(t, c, "child1")

	for i := 0; i < 20; i++ { // far more tasks than the limit (5): a leak would refuse the 6th
		ch, err := DispatchToRelay("child1", RelayMessage{Type: "task_dispatch", TaskID: "t" + string(rune('a'+i)), Hostname: "h"})
		if err != nil {
			t.Fatalf("task %d refused (a slot leaked): %v", i, err)
		}
		if inFlightAll() != 1 {
			t.Fatalf("in flight = %d, want 1", inFlightAll())
		}
		m := readMsg(t, c)
		if err := c.WriteJSON(RelayMessage{Type: "task_result", TaskID: m.TaskID, RC: 0}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal("no result")
		}
		if !awaitCondition(2*time.Second, func() bool { return inFlightAll() == 0 }) {
			t.Fatalf("task %d: the slot is not freed after the result (in flight = %d)", i, inFlightAll())
		}
	}
}

func TestAdmission_RelayedTaskSlotIsFreedWhenTheChildDisconnects(t *testing.T) {
	setLimits(t, 10, 5, 0)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("child1", "relay"))
	handshake(t, c, "child1")
	if _, err := DispatchToRelay("child1", RelayMessage{Type: "task_dispatch", TaskID: "d1", Hostname: "h"}); err != nil {
		t.Fatal(err)
	}
	if _, err := DispatchToRelay("child1", RelayMessage{Type: "task_dispatch", TaskID: "d2", Hostname: "h"}); err != nil {
		t.Fatal(err)
	}
	if inFlightAll() != 2 {
		t.Fatalf("in flight = %d, want 2", inFlightAll())
	}
	_ = c.Close()
	if !awaitCondition(3*time.Second, func() bool { return inFlightAll() == 0 }) {
		t.Fatalf("slots leaked after relay_disconnected: in flight = %d", inFlightAll())
	}
}

// Another relay's disconnection must not free (nor fail) the tasks of a relay that stays connected.
func TestAdmission_AnotherRelaysDisconnectionKeepsMyTasks(t *testing.T) {
	setLimits(t, 10, 5, 0)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	a := dialRelay(t, srv, makeRelayJWT("child-a", "relay"))
	handshake(t, a, "child-a")
	b := dialRelay(t, srv, makeRelayJWT("child-b", "relay"))
	handshake(t, b, "child-b")
	if _, err := DispatchToRelay("child-a", RelayMessage{Type: "task_dispatch", TaskID: "ta", Hostname: "h"}); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("child-b") }) {
		t.Fatal("child-b still connected")
	}
	time.Sleep(100 * time.Millisecond)
	if inFlightAll() != 1 {
		t.Errorf("the task of child-a must still hold its slot: in flight = %d", inFlightAll())
	}
}
