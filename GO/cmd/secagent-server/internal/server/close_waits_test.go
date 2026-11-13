// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
	"time"
)

// #263: Node.Close waits for the dispatcher (and its reporter) and for the purge goroutine, so the
// log is quiet once it has returned: the "[HOOKS] Dispatcher stopped" line is already there and no
// line follows. A race detector run (-race -count=20) also catches a late write to the captured buffer.
func TestNodeClose_WaitsForTheDispatcherAndThePurge_NoLogAfterReturn(t *testing.T) {
	buf := captureLogs(t)
	n, _, _, _ := startNode(t, func(c *Config) { c.PurgeInterval = 5 * time.Millisecond })
	time.Sleep(50 * time.Millisecond) // several purge ticks

	n.Close()
	after := buf.String()
	if !strings.Contains(after, "[HOOKS] Dispatcher stopped") {
		t.Fatalf("Close returned before the dispatcher logged its stop line; log:\n%s", after)
	}
	time.Sleep(200 * time.Millisecond)
	if later := buf.String(); later != after {
		t.Errorf("log written after Close returned:\n%s", strings.TrimPrefix(later, after))
	}
}

// Close stays idempotent with the new waits (Run calls it again on exit).
func TestNodeClose_IsIdempotentAndReturns(t *testing.T) {
	n, _, _, _ := startNode(t, nil)
	done := make(chan struct{})
	go func() { n.Close(); n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocks")
	}
}
