// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

// #217 H3 — the renewal loop of a connection ends with the connection (close, 4001 revocation,
// replacement, shutdown) and never outlives it: an orphan goroutine that keeps issuing tokens for a
// revoked or disconnected host would bypass #193.

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startLoop(ctx context.Context, host string, exp time.Time) (done chan struct{}) {
	done = make(chan struct{})
	go func() { defer close(done); runRenewal(ctx, host, exp) }()
	return done
}

func withRenewal(t *testing.T, ttl, interval time.Duration, fn RenewFunc) {
	t.Helper()
	SetRenewal(ttl, interval, fn)
	t.Cleanup(func() { SetRenewal(0, 0, nil) })
}

func ended(done chan struct{}, within time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// The loop stops when its context is cancelled (the connection closed), also while waiting for the
// next deadline, and issues nothing afterwards.
func TestSecH3_TheLoopEndsWhenTheConnectionContextIsCancelled(t *testing.T) {
	var calls atomic.Int32
	withRenewal(t, 600*time.Millisecond, 200*time.Millisecond, func(string) (time.Time, error) {
		calls.Add(1)
		return time.Now().Add(600 * time.Millisecond), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := startLoop(ctx, "h3-cancel", time.Now().Add(600*time.Millisecond))
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("the loop did not renew (%d calls)", calls.Load())
	}
	cancel()
	if !ended(done, time.Second) {
		t.Fatal("the loop did not end after the cancellation of the connection")
	}
	n := calls.Load()
	time.Sleep(600 * time.Millisecond)
	if calls.Load() != n {
		t.Errorf("a renewal was issued after the connection ended (%d → %d)", n, calls.Load())
	}
}

// A cancellation that arrives while the renewal function runs does not start another cycle.
func TestSecH3_ACancellationDuringARenewalEndsTheLoopAfterIt(t *testing.T) {
	var calls atomic.Int32
	inFn := make(chan struct{})
	release := make(chan struct{})
	withRenewal(t, 600*time.Millisecond, 200*time.Millisecond, func(string) (time.Time, error) {
		if calls.Add(1) == 1 {
			close(inFn)
			<-release
		}
		return time.Now().Add(600 * time.Millisecond), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := startLoop(ctx, "h3-midflight", time.Now())
	select {
	case <-inFn:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal function never called")
	}
	cancel()
	close(release)
	if !ended(done, time.Second) {
		t.Fatal("the loop must end once the in-flight renewal returned")
	}
	if calls.Load() != 1 {
		t.Errorf("%d renewals, want exactly the in-flight one", calls.Load())
	}
}

// Revocation (ErrRenewStop, also wrapped) ends the loop for good: no further call, not even a retry.
func TestSecH3_TheLoopEndsOnRevocationAndNeverRetries(t *testing.T) {
	var calls atomic.Int32
	withRenewal(t, 600*time.Millisecond, 100*time.Millisecond, func(string) (time.Time, error) {
		calls.Add(1)
		return time.Time{}, errors.Join(errors.New("revoked"), ErrRenewStop)
	})
	done := startLoop(context.Background(), "h3-revoked", time.Now())
	if !ended(done, 3*time.Second) {
		t.Fatal("the loop must end when the agent is revoked")
	}
	time.Sleep(400 * time.Millisecond)
	if calls.Load() != 1 {
		t.Errorf("%d calls after a revocation, want exactly 1", calls.Load())
	}
}

// A transient failure (read-only state, send error) is retried, it does not end the loop: the opposite
// of H3 would silently reintroduce the fleet-wide stop of #217.
func TestSecH3_ATransientFailureIsRetriedNotFatal(t *testing.T) {
	var calls atomic.Int32
	withRenewal(t, 600*time.Millisecond, 100*time.Millisecond, func(string) (time.Time, error) {
		if calls.Add(1) < 3 {
			return time.Time{}, errors.New("state is read-only")
		}
		return time.Now().Add(600 * time.Millisecond), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startLoop(ctx, "h3-transient", time.Now())
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 4 {
		t.Fatalf("the loop gave up after a transient error (%d calls)", calls.Load())
	}
}

// Non-leak: 300 connections opened and closed (half by revocation) leave no goroutine behind.
func TestSecH3_NoGoroutineSurvivesItsConnection(t *testing.T) {
	withRenewal(t, 600*time.Millisecond, 50*time.Millisecond, func(h string) (time.Time, error) {
		if h[len(h)-1]%2 == 0 {
			return time.Time{}, ErrRenewStop
		}
		return time.Now().Add(600 * time.Millisecond), nil
	})
	runtime.GC()
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := startLoop(ctx, "h3-leak-"+string(rune('a'+i%26)), time.Now())
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(150 * time.Millisecond)
			cancel()
			<-done
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Fatalf("goroutine leak: %d before, %d after the connections ended", before, after)
	}
}

// No renewal function configured (feature disabled) ⇒ the loop returns at once.
func TestSecH3_WithoutConfigurationTheLoopReturnsImmediately(t *testing.T) {
	SetRenewal(0, 0, nil)
	if !ended(startLoop(context.Background(), "h3-off", time.Now()), time.Second) {
		t.Fatal("a disabled renewal must not block")
	}
}
