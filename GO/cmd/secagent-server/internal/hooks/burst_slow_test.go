//go:build slow

// Slow suite: run with `-tags slow`, in its own CI job (slow-tests). See .github/workflows/ci.yml.

package hooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #183: a burst of 3 000 events (everybody reconnects after a failover) with the DEFAULT settings:
// every action runs and is journaled, nothing is dropped.
func TestBurst_3000EventsAreAllExecutedAndJournaled(t *testing.T) {
	const events = 3000
	out := filepath.Join(t.TempDir(), "burst.out")
	logger := &mockLogger{}
	d := NewDispatcher(logger, QueueSizeFromEnv())
	d.SetConfig(fileHookConfig("host.up", out, "{{hostname}}\n"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	start := time.Now()
	for i := 0; i < events; i++ {
		d.Dispatch("host.up", fmt.Sprintf("host-%04d", i), "connected", "")
	}
	logger.waitEntries(t, events, 60*time.Second)
	t.Logf("%d events executed and journaled in %v (burst enqueued in the first %v)", events, time.Since(start), "…")
	if d.DroppedEvents() != 0 || d.DroppedActions() != 0 {
		t.Errorf("dropped events=%d actions=%d, want 0/0", d.DroppedEvents(), d.DroppedActions())
	}
	b, _ := os.ReadFile(out)
	if n := strings.Count(string(b), "\n"); n != events {
		t.Errorf("%d lines written, want %d", n, events)
	}
}

// Beyond the queue the loss is EXPLICIT: counted exactly, announced by ONE aggregated warning and
// ONE journal entry, never a line per event.
