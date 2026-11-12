// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// LOT-3.2 (#246a) — upstream queue of a child relay while its uplink is CUT: bounded (RELAY_UPSTREAM_QUEUE_SIZE,
// default 10 000, min 256), measured (status: upstream_dropped_events / upstream_queue_depth / upstream_queue_capacity),
// loss reported ONCE per minute (a [WARN] line + one `upstream_dropped` journal entry), replay cadenced under the
// parent quota. RED on e0d1970: fixed queue of 256, one log line per lost event, no counters.

// cutTree: a root (fixed addresses, so that it can come back), a linked child relay1 whose hooks journal every
// relay.* event it produces, and fake grandchildren gc0..gcN declared on the child BEFORE the cut (minting a link
// token needs the root). A parent accepts 40 snapshots per minute and per identity (ws.snapshotReplaceLimit): one
// fake grandchild links at most 30 times, i.e. produces 60 relay.up / relay.down events, hence one identity per 60 events.
type cutTree struct {
	root, child *node
	ids, tokens []string
}

const eventsPerIdentity = 60

func newCutTree(t *testing.T, events int, childEnv ...string) *cutTree {
	t.Helper()
	addr := newNodeAddrs(t)
	root := startNode(t, nodeSpec{ID: "root", Env: addr.env(), Hooks: lot32Hooks})
	tok := root.registerChild("relay1")
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tok, Hooks: lot32Hooks, Env: childEnv})
	waitFor(t, "the child is linked to the root", func() bool { return child.upstreamState() == "connected" })
	waitFor(t, "the root saw relay.up of the child", func() bool { return len(root.eventsOf("relay.up", map[string]string{"relay": "relay1"})) == 1 })
	c := &cutTree{root: root, child: child}
	for i := 0; i < (events+eventsPerIdentity-1)/eventsPerIdentity; i++ {
		id := fmt.Sprintf("gc%d", i)
		c.ids = append(c.ids, id)
		c.tokens = append(c.tokens, child.registerChild(id))
	}
	return c
}

// cut stops the root and waits for the child to notice (its uplink is down, the relay.* events pile up in its queue).
func (c *cutTree) cut(t *testing.T) {
	t.Helper()
	c.root.stop()
	waitFor(t, "the child's uplink is down", func() bool { return c.child.upstreamState() != "connected" })
}

// back restarts the root on its previous addresses and waits for the child to be linked again.
func (c *cutTree) back(t *testing.T) {
	t.Helper()
	c.root.launch([]string{"NODE_API_ADDR=" + c.root.ready.API, "NODE_ADMIN_ADDR=" + c.root.ready.Admin, "NODE_WS_ADDR=" + c.root.ready.WS})
	waitFor(t, "the child is linked again", func() bool { return c.child.upstreamState() == "connected" })
}

// count is the number of relay.discover + relay.up + relay.down lines the node journaled for the fake grandchildren.
func (c *cutTree) count(n *node) int {
	total := 0
	for _, id := range c.ids {
		w := map[string]string{"relay": id}
		// relay.discover (#266): the first link of each declared grandchild also queues one event
		total += len(n.eventsOf("relay.discover", w)) + len(n.eventsOf("relay.up", w)) + len(n.eventsOf("relay.down", w))
	}
	return total
}

// produce links and unlinks the fake grandchildren on the child (30 times each, `workers` at a time).
func (c *cutTree) produce(t *testing.T, workers int) {
	t.Helper()
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	errs := make(chan error, len(c.ids))
	for i := range c.ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := flap(c.child, c.ids[i], c.tokens[i], eventsPerIdentity/2); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

// (6) 300 relay events produced with the uplink cut, default queue (10 000): all 300 are replayed at the
// reconnection, none dropped, the counters say so. (Over 256 slots: the v3.0.5 queue would lose 44.)
func TestUpstreamQueue_300EventsWhileCut_AllReplayedNoneDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("replay")
	}
	parallel(t)
	c := newCutTree(t, 300)
	c.cut(t)
	c.produce(t, 2)
	waitFor(t, "300 events produced by the child", func() bool { return c.count(c.child) >= 300 })
	produced := c.count(c.child)
	if v, ok := c.child.statusField("upstream_queue_capacity"); !ok || v != 10000 {
		t.Errorf("upstream_queue_capacity = %v (present %v), want the default 10000", v, ok)
	}

	c.back(t)
	waitFor(t, "every produced event is replayed to the root", func() bool {
		return c.count(c.root) >= produced
	})
	if v, ok := c.child.statusField("upstream_dropped_events"); !ok || v != 0 {
		t.Errorf("upstream_dropped_events = %v (present %v), want 0", v, ok)
	}
	if c.child.logs.has("event(s) dropped in the last minute") || c.child.logs.has("upstream event queue full") {
		t.Errorf("nothing was dropped, nothing must be reported:\n%s", c.child.logs.String())
	}
	if c.root.logs.has("event_forward rate limit exceeded") {
		t.Errorf("the replay must stay under the parent quota (200/s):\n%s", c.root.logs.String())
	}
}

// (6) full queue: RELAY_UPSTREAM_QUEUE_SIZE=256 (the minimum), 300 produced while cut => the loss is COUNTED exactly and
// the 256 events kept are replayed (the ONE aggregated [WARN] and ONE `upstream_dropped` entry: slow suite, same scenario).
func TestUpstreamQueue_FullQueue_ExactCounterAndReplayOfTheKeptEvents(t *testing.T) {
	fullQueue(t, false)
}

// fullQueue is the full-queue scenario. withReport also waits (up to 75 s: the report is aggregated per minute) for the
// ONE [WARN] line and the ONE `upstream_dropped` journal entry: that part runs in the slow suite only.
func fullQueue(t *testing.T, withReport bool) {
	t.Helper()
	parallel(t)
	c := newCutTree(t, 300, "RELAY_UPSTREAM_QUEUE_SIZE=256")
	c.cut(t)
	c.produce(t, 2)
	waitFor(t, "300 events produced by the child", func() bool { return c.count(c.child) >= 300 })
	produced := c.count(c.child)
	wantDropped := produced - 256

	if v, ok := c.child.statusField("upstream_queue_capacity"); !ok || v != 256 {
		t.Errorf("upstream_queue_capacity = %v (present %v), want 256", v, ok)
	}
	var dropped float64
	waitFor(t, "the counter reaches the exact number of lost events", func() bool {
		dropped, _ = c.child.statusField("upstream_dropped_events")
		return int(dropped) == wantDropped
	})
	if n := c.child.logs.count("upstream event queue full, event"); n != 0 {
		t.Errorf("%d per-event \"queue full\" lines, want 0 (aggregated report only)", n)
	}
	if withReport {
		// the aggregated report comes once per minute: wait for it, then check there is exactly one
		deadline := time.Now().Add(75 * time.Second)
		for !c.child.logs.has("event(s) dropped in the last minute") && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
		}
		if n := c.child.logs.count("event(s) dropped in the last minute"); n != 1 {
			t.Errorf("%d aggregated [WARN] lines, want exactly 1 (never one line per lost event)", n)
		}
		if n := strings.Count(c.child.hookJournal("*", 200), `"upstream_dropped"`); n != 1 {
			t.Errorf("%d `upstream_dropped` journal entries, want exactly 1:\n%s", n, c.child.hookJournal("*", 200))
		}
	}
	if v, _ := c.child.statusField("upstream_dropped_events"); int(v) != wantDropped {
		t.Errorf("upstream_dropped_events = %v, want %d (produced %d - capacity 256)", v, wantDropped, produced)
	}

	// what stayed in the queue (256) is replayed, the lost ones are not: the root gets exactly 256 of them
	c.back(t)
	waitFor(t, "the 256 events kept are replayed", func() bool {
		return c.count(c.root) >= 256
	})
	time.Sleep(settle)
	if got := c.count(c.root); got != 256 {
		t.Errorf("the root received %d events of the grandchild, want exactly 256 (the queue's content)", got)
	}
}

// the bounds of RELAY_UPSTREAM_QUEUE_SIZE: out of range (below 256) => the default (10 000) and a [WARN] at start.
func TestUpstreamQueue_SizeOutOfBoundsFallsBackToDefaultWithWarn(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Env: []string{"RELAY_UPSTREAM_QUEUE_SIZE=10"}})
	waitFor(t, "linked", func() bool { return child.upstreamState() == "connected" })
	if v, ok := child.statusField("upstream_queue_capacity"); !ok || v != 10000 {
		t.Errorf("upstream_queue_capacity = %v (present %v) with RELAY_UPSTREAM_QUEUE_SIZE=10, want the default 10000", v, ok)
	}
	if !child.logs.has("RELAY_UPSTREAM_QUEUE_SIZE") {
		t.Errorf("an out-of-range RELAY_UPSTREAM_QUEUE_SIZE must be reported by a [WARN] at start:\n%s", child.logs.String())
	}
}

// a root without a parent: the three counters are always present (0 dropped, 0 depth, capacity N).
func TestUpstreamQueue_StatusFieldsPresentOnARootWithoutParent(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	for _, f := range []string{"upstream_dropped_events", "upstream_queue_depth", "upstream_queue_capacity"} {
		if _, ok := root.statusField(f); !ok {
			t.Errorf("GET /api/admin/status lacks %s", f)
		}
	}
	if v, _ := root.statusField("upstream_dropped_events"); v != 0 {
		t.Errorf("upstream_dropped_events = %v on a root, want 0", v)
	}
	if v, _ := root.statusField("upstream_queue_depth"); v != 0 {
		t.Errorf("upstream_queue_depth = %v on a root, want 0", v)
	}
}
