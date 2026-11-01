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

// markAlive records that the peer of c just sent something (pong or any frame).
func (c *AgentConnection) markAlive() { c.lastAlive.Store(time.Now().UnixNano()) }

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
	var timer *time.Timer
	var stopped atomic.Bool
	timer = time.AfterFunc(p.interval, func() {
		if stopped.Load() {
			return
		}
		_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(p.interval))
		if !stopped.Load() {
			timer.Reset(p.interval)
		}
	})
	return func() { stopped.Store(true); timer.Stop() }
}

// extendReadDeadline is called after every frame received: traffic proves the peer is alive.
func (c *AgentConnection) extendReadDeadline() {
	if p := keepalive.Load(); p != nil {
		c.markAlive()
		_ = c.Conn.SetReadDeadline(time.Now().Add(2 * p.interval))
	}
}

type probeState struct {
	mu     sync.Mutex
	doneAt time.Time
	alive  bool
}

// ProbeConnection checks that the live connection of hostname still answers: it sends a ping and waits
// at most timeout for any sign of life (pong or frame). A connection that does not answer is closed
// (its handler then unregisters it) and false is returned. It also returns false when there is no
// connection. Concurrent probes of the same host share one result (single-flight): the handshake is
// blocked for at most the probe delay.
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
	started := time.Now()
	alive := false
	if err := c.Conn.WriteControl(websocket.PingMessage, nil, started.Add(timeout)); err == nil {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for end := started.Add(timeout); time.Now().Before(end); {
			if c.lastAlive.Load() >= started.UnixNano() {
				alive = true
				break
			}
			<-tick.C
		}
	}
	if !alive {
		log.Printf("[WARN] agent connection did not answer the probe, dropped: hostname=%q", hostname)
		_ = c.Conn.Close()
	}
	c.probe.alive, c.probe.doneAt = alive, time.Now()
	return alive
}
