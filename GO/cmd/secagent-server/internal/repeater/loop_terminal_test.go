package repeater

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ── invariant: Status()==refused_permanent ⇒ Terminal()!=nil (no polling, no sleeping) ──

func TestRunLoop_TerminalIsAssignedBeforeTheStatusFlips(t *testing.T) {
	tr := newLinkTracker()
	var stateAtTerminal LinkState
	var gotTerminal error
	terr := runLoop(context.Background(), "child x", time.Millisecond, 2*time.Millisecond, tr,
		func(err error) {
			gotTerminal = err
			stateAtTerminal = tr.get().State // what an observer would see at this very moment
		},
		func(context.Context) (bool, error) {
			return false, &refusedError{reason: "peer closed with code 4010 (token revoked)", permanent: true}
		})
	if !errors.Is(terr, ErrPermanentRefusal) || !errors.Is(gotTerminal, ErrPermanentRefusal) {
		t.Fatalf("terminal = %v / callback = %v", terr, gotTerminal)
	}
	if stateAtTerminal == LinkRefusedPermanent {
		t.Error("the terminal error must be recorded BEFORE the status becomes refused_permanent, otherwise an observer can see a permanent status with Terminal()==nil")
	}
	if st := tr.get(); st.State != LinkRefusedPermanent {
		t.Errorf("final status = %+v", st)
	}
}

func TestRunLoop_NoTerminalCallbackForCorrectableOrCancel(t *testing.T) {
	called := false
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := runLoop(ctx, "p", time.Millisecond, 2*time.Millisecond, newLinkTracker(),
		func(error) { called = true },
		func(context.Context) (bool, error) {
			attempts++
			if attempts == 3 {
				cancel()
			}
			return false, &refusedError{reason: "peer closed with code 4012 (retry)"} // correctable
		})
	if err != nil || called {
		t.Errorf("err = %v called = %v: a correctable refusal / cancellation is never terminal", err, called)
	}
}

// End to end: a Client and a Dialer both honour the invariant.
func TestTerminalInvariantHoldsForClientAndDialer(t *testing.T) {
	check := func(name string, status func() LinkStatus, terminal func() error, done <-chan struct{}) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for status().State != LinkRefusedPermanent {
			if time.Now().After(deadline) {
				t.Fatalf("%s never became refused_permanent", name)
			}
			time.Sleep(time.Millisecond)
		}
		// the instant the status is permanent, Terminal() must already be set
		if terminal() == nil {
			t.Errorf("%s: Status()==refused_permanent but Terminal()==nil", name)
		}
		_ = done
	}
	p := newRefusalPeer(t, CloseCodePermanent, "central")
	c, _ := refusalClient(t, p)
	check("client", c.Status, c.Terminal, c.Done())
	p2 := newRefusalPeer(t, CloseCodePermanent, "child1")
	d, _ := refusalDialer(t, p2, "child1", func(string) bool { return false })
	check("dialer", d.Status, d.Terminal, nil)
}
