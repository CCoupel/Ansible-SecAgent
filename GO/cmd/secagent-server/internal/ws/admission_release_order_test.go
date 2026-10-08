package ws

import (
	"testing"
	"time"
)

// Whoever receives the answer of a task must find its admission slot already released: a client that
// chains a request right after the answer would otherwise be refused (transient 429 too_many_tasks).
//
// The test is deterministic: it HOLDS the admission lock (admMu) while the answer is produced. The
// release needs that lock, so with the right order (release, then deliver) the answer cannot reach the
// waiter while the lock is held; with the old order (deliver, then release) the answer is already in
// the channel — the failing case is detected immediately, the passing case waits for the bound below,
// which only has to exceed the time to run a channel send.
const deliveryBound = 300 * time.Millisecond

func assertReleasedBeforeDelivery(t *testing.T, name string, produce func(), ch <-chan Message) {
	t.Helper()
	admMu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			admMu.Unlock()
		}
	}
	defer unlock()
	done := make(chan struct{})
	go func() { produce(); close(done) }()
	early := false
	select {
	case <-ch:
		early = true
		t.Errorf("%s: the answer was delivered while the slot was still held (release must come first)", name)
	case <-time.After(deliveryBound):
	}
	unlock()
	if !early {
		select {
		case <-ch: // delivered once the slot could be released
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the answer was never delivered", name)
		}
	}
	<-done
	if got := inFlightAll(); got != 0 {
		t.Errorf("%s: slot not released after the answer: %d in flight", name, got)
	}
}

func TestAdmission_ResultReleasesTheSlotBeforeItIsDelivered(t *testing.T) {
	setLimits(t, 10, 100, 0)
	ch, err := RegisterFuture("order-result", "host-order")
	if err != nil {
		t.Fatal(err)
	}
	assertReleasedBeforeDelivery(t, "result", func() {
		HandleMessage(Message{TaskID: "order-result", Type: "result", RC: 0}, "host-order")
	}, ch)
}

func TestAdmission_DisconnectReleasesTheSlotBeforeItIsDelivered(t *testing.T) {
	setLimits(t, 10, 100, 0)
	ch, err := RegisterFuture("order-disc", "host-disc")
	if err != nil {
		t.Fatal(err)
	}
	assertReleasedBeforeDelivery(t, "disconnection", func() {
		ResolveFuturesForHostname("host-disc", "agent_disconnected")
	}, ch)
}

// The same guarantee, observed from the receiver: the instant the answer is received, a new task of
// another agent is admitted even though the global limit is 1.
func TestAdmission_AnswerReceiverCanImmediatelyAdmitTheNextTask(t *testing.T) {
	setLimits(t, 1, 1, 0)
	for i := 0; i < 200; i++ {
		ch, err := RegisterFuture("chain-a", "host-a")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		go HandleMessage(Message{TaskID: "chain-a", Type: "result"}, "host-a")
		<-ch
		if _, err := RegisterFuture("chain-b", "host-b"); err != nil {
			t.Fatalf("iteration %d: refused right after the answer: %v", i, err)
		}
		UnregisterFuture("chain-b")
	}
}
