package ws

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Keepalive of the /ws/agent connections (#217, N1).
//
// Before v3.0.5 the relay neither pinged an agent nor set a read deadline: a connection cut without a
// FIN was noticed by the TCP keepalive only, about 150 s later. The relay now pings every `interval`
// and closes a connection that sends nothing (no pong, no frame) for 2 x interval. The same ping is
// the probe of the N1 rule: a handshake carrying the replaced JTI while a connection looks alive
// first asks that connection to answer within a short delay; a dead one is dropped and the handshake
// is accepted.
//
// Cost: no goroutine per connection (the ping is a rescheduled timer), no global sweep; gorilla's
// WriteControl may be called concurrently with the other writers.

type keepaliveParams struct {
	interval time.Duration
}

var keepalive atomic.Pointer[keepaliveParams]

// SetAgentKeepalive enables the ping of the agent connections every interval (read deadline: 2 x
// interval). A non-positive interval disables it (unit tests of other packages).
func SetAgentKeepalive(interval time.Duration) {
	if interval <= 0 {
		keepalive.Store(nil)
		return
	}
	keepalive.Store(&keepaliveParams{interval: interval})
}

// sig returns the wake-up channel of the probe (created on first use: connections are built by literal).
func (c *AgentConnection) sig() chan struct{} {
	c.sigOnce.Do(func() { c.aliveSig = make(chan struct{}, 1) })
	return c.aliveSig
}

// markAlive records that the peer of c just sent something (pong or any frame).
func (c *AgentConnection) markAlive() {
	c.lastAlive.Store(time.Now().UnixNano())
	select { // wake a probe waiting for a sign of life (B12); never blocks
	case c.sig() <- struct{}{}:
	default:
	}
}

// startKeepalive arms the read deadline and the ping timer of c; the returned function stops them.
// Without keepalive configuration it does nothing.
func startKeepalive(c *AgentConnection) (stop func()) {
	p := keepalive.Load()
	if p == nil {
		return func() {}
	}
	conn := c.Conn
	deadline := 2 * p.interval
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	c.markAlive()
	conn.SetPongHandler(func(string) error {
		c.markAlive()
		return conn.SetReadDeadline(time.Now().Add(deadline))
	})
	// The callback reads `timer` under tmu and the assignment happens under tmu too, so a callback that
	// fired before the assignment finished (impossible with a real interval, but not by construction) waits.
	var tmu sync.Mutex
	var timer *time.Timer
	var stopped atomic.Bool
	tmu.Lock()
	timer = time.AfterFunc(p.interval, func() {
		if stopped.Load() {
			return
		}
		_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(p.interval))
		tmu.Lock()
		defer tmu.Unlock()
		if !stopped.Load() {
			timer.Reset(p.interval)
		}
	})
	tmu.Unlock()
	return func() { stopped.Store(true); tmu.Lock(); timer.Stop(); tmu.Unlock() }
}

// extendReadDeadline is called after every frame received: traffic proves the peer is alive.
func (c *AgentConnection) extendReadDeadline() {
	if p := keepalive.Load(); p != nil {
		c.markAlive()
		_ = c.Conn.SetReadDeadline(time.Now().Add(2 * p.interval))
	}
}

// MaxConcurrentProbes caps the probes in flight on the whole relay (B11): a probe holds a handshake for
// up to AGENT_WS_PROBE_TIMEOUT, so an unbounded number would let replayed JWTs pin the accept path.
// Past the cap a handshake carrying the replaced JTI is refused (401) without probing.
const MaxConcurrentProbes = 64

var probeSlots = make(chan struct{}, MaxConcurrentProbes)

// lastProbeCapLog rate-limits the "probe cap reached" journal line (once per 10 s).
var lastProbeCapLog atomic.Int64

type probeState struct {
	mu     sync.Mutex
	doneAt time.Time
	alive  bool
}

// ProbeConnection decides whether the live connection of hostname is dead (false) or must be kept
// (true). It concludes "dead" only when BOTH hold (N2): the last sign of life (pong or frame) is at
// least one ping interval old — at least one ping went unanswered — AND the connection does not answer
// a probe ping within timeout. In every other case (recent sign of life, probe answered, probe cap
// reached) it returns true and the connection is kept. A dead connection is closed (its handler then
// unregisters it). No connection at all returns false. Concurrent probes of the same host share one
// result (single-flight), so a handshake waits at most the probe delay.
func ProbeConnection(hostname string, timeout time.Duration) bool {
	c, err := GetConnection(hostname)
	if err != nil {
		return false
	}
	arrived := time.Now()
	c.probe.mu.Lock()
	defer c.probe.mu.Unlock()
	if c.probe.doneAt.After(arrived) { // a probe finished while we waited for the lock: same answer
		return c.probe.alive
	}
	if p := keepalive.Load(); p != nil && time.Since(time.Unix(0, c.lastAlive.Load())) < p.interval {
		return true // recent sign of life: the connection is fine, no probe
	}
	select {
	case probeSlots <- struct{}{}:
		defer func() { <-probeSlots }()
	default:
		if now := time.Now().UnixNano(); now-lastProbeCapLog.Load() > int64(10*time.Second) {
			lastProbeCapLog.Store(now)
			log.Printf("[WARN] agent probe cap reached (%d in flight): replaced-JTI handshakes are refused without probing", MaxConcurrentProbes)
		}
		return true
	}
	started := time.Now()
	for len(c.sig()) > 0 { // drop stale signals
		<-c.sig()
	}
	alive := false
	if err := c.Conn.WriteControl(websocket.PingMessage, nil, started.Add(timeout)); err == nil {
		end := time.NewTimer(timeout)
		defer end.Stop()
		for !alive {
			if c.lastAlive.Load() >= started.UnixNano() {
				alive = true
				break
			}
			select {
			case <-c.sig():
			case <-end.C:
				alive = c.lastAlive.Load() >= started.UnixNano()
				goto done
			}
		}
	}
done:
	if !alive {
		log.Printf("[WARN] agent connection did not answer the probe, dropped: hostname=%q", hostname)
		_ = c.Conn.Close()
	}
	c.probe.alive, c.probe.doneAt = alive, time.Now()
	return alive
}
