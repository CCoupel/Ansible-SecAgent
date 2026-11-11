// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// RELAY_CONVERGENCE_TIMEOUT: how long a freshly promoted node waits for its declared child relays to
// come back before announcing relay.converged with what it has (#246).
const (
	DefaultConvergenceTimeout = 60 * time.Second
	MinConvergenceTimeout     = time.Second // below the 5 s of the plan so that a test can set 2 s
	MaxConvergenceTimeout     = 10 * time.Minute
	// convergenceSettle bounds the wait for the hooks queue to drain before relay.converged is handed
	// to it, so that the journal reads relay.failover < relay.up/reconnect < relay.converged.
	convergenceSettle = time.Second
)

// ConvergenceTimeoutFromEnv returns RELAY_CONVERGENCE_TIMEOUT (a Go duration such as "30s", or a number
// of seconds), within [1s, 10m]; anything else gives the default 60 s and a warning.
func ConvergenceTimeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RELAY_CONVERGENCE_TIMEOUT"))
	if raw == "" {
		return DefaultConvergenceTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		if n, nerr := time.ParseDuration(raw + "s"); nerr == nil {
			d, err = n, nil
		}
	}
	if err != nil || d < MinConvergenceTimeout || d > MaxConvergenceTimeout {
		log.Printf("[WARN] RELAY_CONVERGENCE_TIMEOUT=%q is not a duration in [%s, %s]: using the default %s", raw, MinConvergenceTimeout, MaxConvergenceTimeout, DefaultConvergenceTimeout)
		return DefaultConvergenceTimeout
	}
	return d
}

// convergence follows the return of the child relays declared on a node that has just been promoted.
// relay.converged is emitted ONCE: when every expected relay has come back (as a direct link or as a
// relay declared below one), or at the timeout with the relays still missing. A node without declared
// child emits at once. Nothing is emitted after stop (the node is closing).
type convergence struct {
	emit func(connected, missing int)

	mu      sync.Mutex
	total   int
	missing map[string]struct{}
	done    bool
	timer   *time.Timer
}

func newConvergence(expected []string, emit func(connected, missing int)) *convergence {
	c := &convergence{emit: emit, total: len(expected), missing: make(map[string]struct{}, len(expected))}
	for _, id := range expected {
		c.missing[id] = struct{}{}
	}
	return c
}

// start arms the timeout, or emits at once when nothing is expected.
func (c *convergence) start(timeout time.Duration) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	if len(c.missing) == 0 {
		c.done = true
		c.mu.Unlock()
		c.emit(c.total, 0)
		return
	}
	c.timer = time.AfterFunc(timeout, c.expire)
	c.mu.Unlock()
}

func (c *convergence) expire() { c.finish() }

// linkUp records relays that are back. It never blocks on the emission.
func (c *convergence) linkUp(ids ...string) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	for _, id := range ids {
		delete(c.missing, id)
	}
	left := len(c.missing)
	c.mu.Unlock()
	if left == 0 {
		go c.finish()
	}
}

// finish emits once, with the counts at this instant.
func (c *convergence) finish() {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	missing := len(c.missing)
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	c.emit(c.total-missing, missing)
}

// stop disarms the tracker: nothing is emitted afterwards.
func (c *convergence) stop() {
	c.mu.Lock()
	c.done = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
}

// startConvergence begins the follow-up right after relay.failover (any node, root or not).
func (n *Node) startConvergence(selfID string) {
	if n.store == nil || n.dispatcher == nil {
		return
	}
	nodes, err := n.store.ListValidRelayNodes()
	if err != nil {
		log.Printf("[WARN] relay.converged: list relay nodes: %v", err)
		nodes = nil
	}
	expected := make([]string, 0, len(nodes))
	for _, rn := range nodes {
		expected = append(expected, rn.RelayID)
	}
	conv := newConvergence(expected, func(connected, missing int) { n.emitConverged(selfID, connected, missing) })
	n.convMu.Lock()
	if n.conv != nil {
		n.conv.stop()
	}
	n.conv = conv
	n.convMu.Unlock()
	conv.start(ConvergenceTimeoutFromEnv())
}

// emitConverged hands relay.converged to the hooks (and up to the parent, like relay.failover).
func (n *Node) emitConverged(selfID string, connected, missing int) {
	ctx := n.dispatchCtx
	// let the relay.up / relay.reconnect events already handed to the dispatcher reach the journal first
	for deadline := time.Now().Add(convergenceSettle); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if st := n.dispatcher.Stats(); st.QueueDepth == 0 && st.Inflight == 0 {
			break
		}
		if ctx != nil && ctx.Err() != nil {
			return
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return // the node is closing
	}
	routed := 0
	if routes, err := n.store.ListRelayRoutes(); err == nil {
		routed = len(routes)
	}
	var dropped int64
	if n.upQueue != nil {
		dropped, _, _ = n.upQueue.Stats()
	}
	n.dispatcher.DispatchEvent(hooks.Event{Name: "relay.converged", RelayID: selfID, Detail: hooks.Detail{
		RelaysConnected: connected, RelaysMissing: missing, HostsDirect: len(ws.GetConnectedHostnames()),
		HostsRouted: routed, UpstreamDroppedEventsTotal: dropped}})
}

// linkEstablished is the ws notification of a child link (or the relays below it) that is back.
func (n *Node) linkEstablished(relayID string, below []string) {
	n.convMu.Lock()
	conv := n.conv
	n.convMu.Unlock()
	if conv != nil {
		conv.linkUp(append([]string{relayID}, below...)...)
	}
}
