// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

// Slow suite (job CI slow-tests): I6 of #217 on 3 000 real agent links. Run with `-tags slow`.

package integration

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// renewClient is a held agent link that counts (and dates) the rekey frames it receives.
type renewClient struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	rekeys []time.Time
	frames []map[string]any // kept only for the sampled agents
	keep   bool
	closed chan struct{}
}

func dialRenewClient(n *node, host, tok string, keep bool) (*renewClient, error) {
	h := http.Header{"Authorization": {"Bearer " + tok}}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 30 * time.Second}
	conn, _, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	c := &renewClient{conn: conn, keep: keep, closed: make(chan struct{})}
	go func() {
		defer close(c.closed)
		for {
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg["type"] == "rekey" {
				c.mu.Lock()
				c.rekeys = append(c.rekeys, time.Now())
				if c.keep {
					c.frames = append(c.frames, msg)
				}
				c.mu.Unlock()
			}
		}
	}()
	return c, nil
}

// I6 (perf): 3 000 agents connected at the same time renew their JWT without a burst: within the
// observation window every agent gets about one rekey per period (budget: <= 1 UpdateTokenJTI per
// agent and per period, +1 for the window edges), the arrivals are spread over time (no second
// carries more than a quarter of the park), no link is cut, the admin API keeps answering, and the
// node's RSS stays under 2 GiB.
func TestSpec217_I6_Renewal3000AgentsWithoutBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	const agents = 3000
	const ttl, interval = 60 * time.Second, 20 * time.Second
	const periods = 3
	n := startNode(t, nodeSpec{ID: "load", NodeBinary: testHelpersPlainBinary(t), Env: renewalEnv(ttl.String(), interval.String())})
	rss := startRSSSampler(t, n.cmd.Process.Pid)

	tokens := make([]string, agents)
	forEach(t, agents, 64, func(i int) error {
		tok, err := n.enrollAgentErr(fmt.Sprintf("renew-%04d", i))
		tokens[i] = tok
		return err
	})
	clients := make([]*renewClient, agents)
	connectStart := time.Now()
	forEach(t, agents, 64, func(i int) error {
		c, err := dialRenewClient(n, fmt.Sprintf("renew-%04d", i), tokens[i], i%100 == 0)
		clients[i] = c
		return err
	})
	t.Cleanup(func() {
		for _, c := range clients {
			if c != nil {
				_ = c.conn.Close()
			}
		}
	})
	t.Logf("%d links established in %s", agents, time.Since(connectStart).Round(time.Second))

	// observe `periods` renewal periods; the admin API must keep answering all along
	windowStart := time.Now()
	var slowAdmin atomic.Int32
	stop := make(chan struct{})
	adminDone := make(chan struct{})
	go func() {
		defer close(adminDone)
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Second):
			}
			begin := time.Now()
			if code, _, err := n.callErr("GET", n.adminURL(), "/api/admin/status", n.adminTok, nil); err != nil || code != http.StatusOK || time.Since(begin) > 5*time.Second {
				slowAdmin.Add(1)
			}
		}
	}()
	time.Sleep(periods*interval + 5*time.Second)
	close(stop)
	<-adminDone
	window := time.Since(windowStart)

	// per-agent budget and per-second arrival histogram
	perSecond := map[int64]int{}
	var total, noRenewal, overBudget int
	maxPerAgent := int(window/interval) + 2 // one per period + edge effects (the first one is due ~interval after the connection)
	for i, c := range clients {
		select {
		case <-c.closed:
			t.Errorf("agent %d: its link was cut during the renewals", i)
			continue
		default:
		}
		c.mu.Lock()
		got := append([]time.Time(nil), c.rekeys...)
		c.mu.Unlock()
		total += len(got)
		if len(got) == 0 {
			noRenewal++
		}
		if len(got) > maxPerAgent {
			overBudget++
		}
		for _, ts := range got {
			perSecond[ts.Unix()]++
		}
	}
	peak := 0
	for _, v := range perSecond {
		if v > peak {
			peak = v
		}
	}
	hwm, vanished := rss.finish()
	t.Logf("window %s: %d rekeys for %d agents, peak %d/s, peak RSS %.0f MiB, slow admin polls %d", window.Round(time.Second), total, agents, peak, float64(hwm)/(1<<20), slowAdmin.Load())

	if vanished {
		t.Errorf("the node process disappeared during the renewals (exit code %d)", n.exitCode)
	}
	if noRenewal != 0 {
		t.Errorf("%d agent(s) received no renewal in %s (period %s)", noRenewal, window.Round(time.Second), interval)
	}
	if overBudget != 0 {
		t.Errorf("%d agent(s) were renewed more than %d times in the window: budget is one state write per agent and per period", overBudget, maxPerAgent)
	}
	if peak > agents/4 {
		t.Errorf("renewal burst: %d rekeys in one second (> %d = a quarter of the park): the deadlines must be spread (jitter)", peak, agents/4)
	}
	if slowAdmin.Load() != 0 {
		t.Errorf("the admin API stalled or failed %d time(s) during the renewals", slowAdmin.Load())
	}
	if hwm == 0 {
		t.Fatal("no RSS sample")
	}
	if hwm > 2<<30 {
		t.Errorf("node peak RSS %.0f MiB exceeds 2 GiB", float64(hwm)/(1<<20))
	}
	// sampled agents: the frames are valid JWTs for the right host, the last one is the current JTI
	for i := 0; i < agents; i += 100 {
		c := clients[i]
		c.mu.Lock()
		frames := append([]map[string]any(nil), c.frames...)
		c.mu.Unlock()
		if len(frames) == 0 {
			continue
		}
		raw := openRekey(t, frames[len(frames)-1])
		if cl := claimsOf(t, raw); cl["sub"] != fmt.Sprintf("renew-%04d", i) || cl["role"] != "agent" {
			t.Errorf("sampled agent %d: claims %v", i, cl)
		}
	}
}

// testHelpersPlainBinary: the load test's node binary (no -race) with the testhelpers seam for the short
// TTL of the renewal. Same build as testHelpersNodeBinary, which is never built with -race either.
func testHelpersPlainBinary(t *testing.T) string { return testHelpersNodeBinary(t) }
