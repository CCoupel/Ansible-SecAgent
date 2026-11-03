// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

// #216 (LOT-3) — the rate limit of `event_forward` (200 per second, maxEventsPerSecond) is carried by the
// IDENTITY (relay_id = the verified jwt.sub), not by the link: a reconnection must not reset the counter
// (the same defect #156 fixed for the topology snapshots). Acceptance criteria of the issue:
//
//	1. 200 events, immediate reconnection, a new event in the same second → ignored AND journalized
//	2. two relay_id have independent quotas
//	3. the table is bounded and purged after inactivity
//	4. mutation "counter reset on every link" (today's behaviour) killed; -race
//
// The window is one second and the limit 200: nothing is shortened, so each scenario measures its own
// duration and is replayed (with a fresh identity) when a slow machine let the window roll.
//
// Against a per-link counter these tests FAIL — that failure IS the mutant being killed. The purge test
// needs the size of the table: dev-relay wires specEventQuotaEntries in an init() of a *_test.go file
// (like snapshot_quota_spec_wire_test.go); until then it is skipped.

import (
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// specEventQuotaEntries returns the number of identities tracked by the event quota table (nil = the purge
// test is skipped until dev-relay wires it).
var specEventQuotaEntries func() int

// quotaEventSink counts the events handed upstream, by the relay that sent them (last element of the chain).
type quotaEventSink struct {
	mu sync.Mutex
	by map[string]int
}

func newQuotaEventSink(t *testing.T) *quotaEventSink {
	t.Helper()
	s := &quotaEventSink{by: map[string]int{}}
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if n := len(m.RelayChain); n > 0 {
			s.by[m.RelayChain[n-1]]++
		}
	})
	return s
}

func (s *quotaEventSink) count(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.by[id]
}

// sendEvents opens a NEW link as id, sends n valid host.up events and waits until they were all processed (a
// heartbeat round-trip proves it), then closes the link.
func sendEvents(t *testing.T, srv *httptest.Server, id string, n int) {
	t.Helper()
	c := dialRelay(t, srv, makeRelayJWT(id, "relay"))
	handshake(t, c, id)
	for i := 0; i < n; i++ {
		if err := c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Hostname: "h", Status: "connected", RelayChain: []string{id}}); err != nil {
			t.Fatalf("event %d of %s: %v", i, id, err)
		}
	}
	if err := c.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if m := readMsg(t, c); m.Type != "heartbeat_ack" {
		t.Fatalf("%s: expected heartbeat_ack, got %+v", id, m)
	}
	_ = c.Close()
}

// withinOneWindow runs the scenario with fresh identities until one attempt finished inside a single
// one-second window (a slow machine can let the window roll, which would excuse the child legitimately).
func withinOneWindow(t *testing.T, scenario func(id string) (elapsed time.Duration)) string {
	t.Helper()
	for attempt := 0; attempt < 6; attempt++ {
		id := fmt.Sprintf("relay-w%d", attempt)
		if el := scenario(id); el < 700*time.Millisecond {
			return id
		}
	}
	t.Skip("the machine is too slow to run the scenario inside one 1 s window (6 attempts)")
	return ""
}

// lockedLog is a goroutine-safe log sink.
type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// 1. The quota survives the reconnection: the events of the new link, in the same window, are ignored.
func TestEventQuota_AReconnectionDoesNotResetTheCounter(t *testing.T) {
	sink := newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	var firstLink, secondLink int
	id := withinOneWindow(t, func(id string) time.Duration {
		start := time.Now()
		sendEvents(t, srv, id, maxEventsPerSecond) // the whole quota of the identity, one link
		firstLink = sink.count(id)
		sendEvents(t, srv, id, 50) // immediate reconnection: the child ignores its backoff
		secondLink = sink.count(id) - firstLink
		return time.Since(start)
	})
	if firstLink != maxEventsPerSecond {
		t.Fatalf("%s: the first link forwarded %d events, want exactly its quota (%d)", id, firstLink, maxEventsPerSecond)
	}
	if secondLink != 0 {
		t.Fatalf("%s: %d event(s) of the NEW link were forwarded in the same second: the quota belongs to the relay_id, a reconnection must not reset it", id, secondLink)
	}
}

// 1b. Several quick reconnections never add up to more than one quota in the window.
func TestEventQuota_ManyQuickReconnectionsStayWithinOneQuota(t *testing.T) {
	sink := newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	var total int
	id := withinOneWindow(t, func(id string) time.Duration {
		start := time.Now()
		for i := 0; i < 5; i++ {
			sendEvents(t, srv, id, 120) // 5 links x 120 = 600 asked, in a single second
		}
		total = sink.count(id)
		return time.Since(start)
	})
	if total > maxEventsPerSecond {
		t.Fatalf("%s: %d events forwarded for 5 successive links in one window, limit %d per identity", id, total, maxEventsPerSecond)
	}
	if total < maxEventsPerSecond-10 {
		t.Fatalf("%s: only %d forwarded: the quota must be consumed, not the whole identity blocked", id, total)
	}
}

// 2. The excess is IGNORED and journalized once per excess, naming the relay and leaking no token.
func TestEventQuota_TheExcessIsJournalizedWithTheRelayID(t *testing.T) {
	out := &lockedLog{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	_ = newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	id := withinOneWindow(t, func(id string) time.Duration {
		start := time.Now()
		sendEvents(t, srv, id, maxEventsPerSecond)
		sendEvents(t, srv, id, 3)
		return time.Since(start)
	})
	logs := out.String()
	want := fmt.Sprintf("event_forward rate limit exceeded: relay_id=%q", id)
	if !strings.Contains(logs, want) {
		t.Fatalf("the excess of a reconnected link must be journalized (%q):\n%s", want, logs)
	}
	for _, leak := range []string{"Bearer ", "eyJ"} {
		if strings.Contains(logs, leak) {
			t.Errorf("the log contains %q", leak)
		}
	}
}

// 3. Two identities have independent quotas.
func TestEventQuota_DistinctIdentitiesHaveIndependentQuotas(t *testing.T) {
	sink := newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	var a, b, c int
	id := withinOneWindow(t, func(id string) time.Duration {
		start := time.Now()
		sendEvents(t, srv, id, maxEventsPerSecond+50) // exhausts "id"
		sendEvents(t, srv, id+"-b", 100)              // untouched by the abuse of "id"
		sendEvents(t, srv, id+"-c", 100)
		a, b, c = sink.count(id), sink.count(id+"-b"), sink.count(id+"-c")
		return time.Since(start)
	})
	if a != maxEventsPerSecond {
		t.Errorf("%s: %d events forwarded, want its quota (%d)", id, a, maxEventsPerSecond)
	}
	if b != 100 || c != 100 {
		t.Errorf("the other identities were affected by %s: %d and %d events forwarded, want 100 and 100", id, b, c)
	}
}

// 4. No permanent block: once the window is over the identity is served again.
func TestEventQuota_TheIdentityIsServedAgainWhenTheWindowIsOver(t *testing.T) {
	sink := newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	id := withinOneWindow(t, func(id string) time.Duration {
		start := time.Now()
		sendEvents(t, srv, id, maxEventsPerSecond+20)
		return time.Since(start)
	})
	before := sink.count(id)
	time.Sleep(1200 * time.Millisecond) // window (1 s) over
	sendEvents(t, srv, id, 25)
	if got := sink.count(id) - before; got != 25 {
		t.Fatalf("%s: %d of 25 events forwarded after the window: a permanent block (or a partial reset)", id, got)
	}
}

// 5. The table is bounded: identities that stopped sending are dropped after the window.
func TestEventQuota_TheTableIsPurgedAfterInactivity(t *testing.T) {
	if specEventQuotaEntries == nil {
		t.Skip("PENDING #216: specEventQuotaEntries is not wired (event_quota_spec_wire_test.go)")
	}
	_ = newQuotaEventSink(t)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	for i := 0; i < 30; i++ {
		sendEvents(t, srv, fmt.Sprintf("relay-%c%c", 'a'+i%26, 'a'+i/26), 1)
	}
	if n := specEventQuotaEntries(); n == 0 || n > 30 {
		t.Fatalf("entries = %d, want 1..30 (one per identity seen)", n)
	}
	time.Sleep(1300 * time.Millisecond)
	sendEvents(t, srv, "relay-late", 1) // activity triggers the purge
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if specEventQuotaEntries() <= 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("entries = %d after inactivity longer than the window: not purged", specEventQuotaEntries())
}

var _ = websocket.CloseNormalClosure
