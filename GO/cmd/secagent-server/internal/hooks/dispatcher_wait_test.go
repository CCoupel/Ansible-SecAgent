// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// #263: Dispatcher.Wait waits for the WORKERS as well as the reporter. Once it has returned, no
// event is being processed any more and nothing is appended to the action journal: Node.Close can
// then close the journal and the store safely. Complements the reporter test in dispatcher_test.go.
func TestDispatcher_WaitReturnsOnlyOnceNoWorkerIsRunningAndNothingIsJournalledLater(t *testing.T) {
	dir := t.TempDir()
	logger := &mockLogger{}
	d := NewDispatcher(logger, 200)
	d.SetConfig(fileHookConfig("host.new", filepath.Join(dir, "out.log"), "x\n"))

	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	for i := 0; i < 100; i++ {
		d.Dispatch("host.new", "host", "disconnected", "2026-11-09T00:00:00Z")
	}
	cancel() // stop while events are queued or running
	d.Wait()

	if got := d.inflight.Load(); got != 0 {
		t.Fatalf("Wait returned with %d event(s) still being processed", got)
	}
	after := logger.entryCount()
	time.Sleep(150 * time.Millisecond)
	if later := logger.entryCount(); later != after {
		t.Errorf("%d journal entr(ies) written after Wait returned", later-after)
	}
}

// Wait is repeatable and safe after the context is already cancelled (Node.Close then Run's own Close).
func TestDispatcher_WaitIsRepeatable(t *testing.T) {
	d := NewDispatcher(&mockLogger{}, 10)
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	cancel()
	d.Wait()
	done := make(chan struct{})
	go func() { d.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a second Wait blocks")
	}
}
