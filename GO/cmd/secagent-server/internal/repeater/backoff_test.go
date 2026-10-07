package repeater

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The backoff is a pure function of the attempt history (min, 2*min, 4*min... capped at max, reset to
// min after a link that reached steady state). The tests below check the SEQUENCE OF DELAYS the loop
// asks for, through an injected clock — never wall-clock gaps between connection attempts, which are
// dominated by TLS handshakes and scheduling noise and made the former tests flaky under load.

// fakeAfter records the delays requested by the loop. The first `release` waits fire at once; the
// next ones never fire (the loop then blocks until its context is cancelled).
type fakeAfter struct {
	mu      sync.Mutex
	waits   []time.Duration
	release int
	seen    chan struct{}
}

func newFakeAfter(release int) *fakeAfter {
	return &fakeAfter{release: release, seen: make(chan struct{}, 256)}
}

func (f *fakeAfter) after(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	f.waits = append(f.waits, d)
	n := len(f.waits)
	f.mu.Unlock()
	select {
	case f.seen <- struct{}{}:
	default:
	}
	if n > f.release {
		return nil // never fires
	}
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func (f *fakeAfter) snapshot() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

// waitN blocks (bounded) until n delays were requested and returns the first n.
func (f *fakeAfter) waitN(t *testing.T, n int) []time.Duration {
	t.Helper()
	deadline := time.After(30 * time.Second) // failure-only bound
	for {
		if w := f.snapshot(); len(w) >= n {
			return w[:n]
		}
		select {
		case <-f.seen:
		case <-deadline:
			t.Fatalf("only %d backoff delays requested, want %d: %v", len(f.snapshot()), n, f.snapshot())
		}
	}
}

// assertBackoffSequence checks the delays against the exponential law min, 2*min, ... capped at max.
func assertBackoffSequence(t *testing.T, got []time.Duration, minB, maxB time.Duration) {
	t.Helper()
	want := make([]time.Duration, len(got))
	for i := range want {
		d := minB
		for j := 0; j < i && d < maxB; j++ {
			d *= 2
		}
		want[i] = min(d, maxB)
	}
	for i, d := range got {
		if d > maxB {
			t.Errorf("delay #%d = %v exceeds the cap %v: %v", i, d, maxB, got)
		}
		if i > 0 && d < got[i-1] {
			t.Errorf("delay #%d = %v shrank (previous %v): %v", i, d, got[i-1], got)
		}
	}
	if got[0] != minB {
		t.Errorf("first delay = %v, want the minimum %v: %v", got[0], minB, got)
	}
	if got[len(got)-1] != maxB {
		t.Errorf("the backoff never reached its cap %v: %v", maxB, got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("backoff sequence = %v, want %v (min %v, max %v)", got, want, minB, maxB)
			return
		}
	}
}

func TestRunLoop_BackoffSequences(t *testing.T) {
	const minB, maxB = 20 * time.Millisecond, 80 * time.Millisecond
	type step struct {
		established bool
		err         error
	}
	fail := step{false, errors.New("connect refused")}
	corr := step{false, &refusedError{reason: "retry"}} // 4012: correctable
	lost := step{true, errors.New("link dropped")}      // reached steady state, then lost
	ms := func(v ...int) []time.Duration {
		var out []time.Duration
		for _, x := range v {
			out = append(out, time.Duration(x)*time.Millisecond)
		}
		return out
	}
	tests := []struct {
		name  string
		steps []step
		want  []time.Duration
	}{
		{"connect failures grow then cap", []step{fail, fail, fail, fail, fail}, ms(20, 40, 80, 80, 80)},
		{"correctable refusals grow then cap like failures", []step{corr, corr, corr, corr, corr}, ms(20, 40, 80, 80, 80)},
		{"mixed failures and refusals share one sequence", []step{fail, corr, fail, corr}, ms(20, 40, 80, 80)},
		{"a lost established link restarts the sequence", []step{fail, fail, fail, lost, fail, fail}, ms(20, 40, 80, 20, 20, 40)},
		{"a lost link right after a long failure run", []step{fail, fail, fail, fail, lost, fail}, ms(20, 40, 80, 80, 20, 20)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeAfter(len(tc.steps) - 1) // the last wait blocks: the loop ends on cancel
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			i := 0
			done := make(chan error, 1)
			go func() {
				done <- runLoopAfter(ctx, "peer", minB, maxB, newLinkTracker(), nil, func(context.Context) (bool, error) {
					s := tc.steps[i]
					i++
					return s.established, s.err
				}, clock.after)
			}()
			got := clock.waitN(t, len(tc.want))
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("loop ended with %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("delays = %v, want %v", got, tc.want)
			}
			for k := range got {
				if got[k] != tc.want[k] {
					t.Fatalf("delays = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestRunLoop_PermanentRefusalNeverWaits(t *testing.T) {
	clock := newFakeAfter(10)
	err := runLoopAfter(context.Background(), "peer", time.Millisecond, time.Second, newLinkTracker(), nil,
		func(context.Context) (bool, error) { return false, &refusedError{reason: "revoked", permanent: true} }, clock.after)
	if !errors.Is(err, ErrPermanentRefusal) {
		t.Fatalf("err = %v, want ErrPermanentRefusal", err)
	}
	if w := clock.snapshot(); len(w) != 0 {
		t.Errorf("a permanent refusal must stop at once, no retry delay: %v", w)
	}
}
