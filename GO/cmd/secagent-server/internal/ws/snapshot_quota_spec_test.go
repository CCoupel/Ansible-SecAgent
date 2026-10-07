package ws

// #156 (L4) — the rate limit of the topology snapshots is carried by the IDENTITY (relay_id = jwt.sub),
// not by the link: a reconnection must not reset the counter. The six acceptance criteria of the issue:
//
//	1. 40 snapshots, disconnect, immediate reconnection, new snapshot → refused (4012) until the window is over
//	2. after the window, the child is accepted again (no permanent block)
//	3. two distinct relay_id have independent quotas
//	4. the counter table is purged (bounded after inactivity)
//	5. mutation "counter reset on every link" (today's behaviour) killed
//	6. no secret in the logs; -race
//
// Rule of the plan (v1 L4): memory only, the FIRST snapshot of a link counts too, thresholds 40 / 60 s;
// the refusal comes at the /ws/relay handshake (4012, correctable) — a refusal at the HTTP upgrade or a
// 4012 close before any topology_ack are both "refused before any snapshot processing".
//
// The tests are ARMED by one switch, specSnapshotQuotaByIdentity: dev-relay sets it to true in the
// commit of #156 (the tests then run, red or green). Armed against today's code they FAIL: that is the
// mutation "counter per link" being killed (report test-writer-20261007-batch0).

import (
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const specSnapshotQuotaByIdentity = false // dev-relay: true when #156 lands

// specSnapshotQuotaEntries returns the number of identities tracked by the quota table. Wired by
// dev-relay (snapshot_quota_spec_wire_test.go) once the table exists; nil = the purge test is skipped.
var specSnapshotQuotaEntries func() int

func requireQuotaByIdentity(t *testing.T) {
	t.Helper()
	if !specSnapshotQuotaByIdentity {
		t.Skip("PENDING #156: the snapshot quota is still per link (set specSnapshotQuotaByIdentity = true when #156 lands)")
	}
}

func setQuota(t *testing.T, limit int, window time.Duration) {
	t.Helper()
	prevL, prevW := snapshotReplaceLimit, snapshotReplaceWindow
	snapshotReplaceLimit, snapshotReplaceWindow = limit, window
	t.Cleanup(func() { snapshotReplaceLimit, snapshotReplaceWindow = prevL, prevW })
}

// attempt is the outcome of one connection + hello + one snapshot.
type attempt struct {
	dialFailed bool // refused at the HTTP upgrade
	accepted   bool // the snapshot was acknowledged
	closeCode  int  // close code observed, 0 if none
}

func specDial(t *testing.T, base, id string) (*websocket.Conn, bool) {
	t.Helper()
	hdr := map[string][]string{"Authorization": {"Bearer " + makeRelayJWT(id, relayRoleChild)}}
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/ws/relay", hdr)
	if err != nil {
		return nil, false
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, true
}

func snapshotAttempt(t *testing.T, base, id string) attempt {
	t.Helper()
	c, ok := specDial(t, base, id)
	if !ok {
		return attempt{dialFailed: true}
	}
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: id, Version: "3.0"}); err != nil {
		return attempt{closeCode: -1}
	}
	sent := false
	for {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var m RelayMessage
		if err := c.ReadJSON(&m); err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				return attempt{closeCode: ce.Code}
			}
			return attempt{closeCode: -1}
		}
		switch m.Type {
		case "relay_ack":
			if !sent {
				sent = true
				if err := c.WriteJSON(RelayMessage{Type: "topology_snapshot"}); err != nil {
					return attempt{closeCode: -1}
				}
			}
		case "topology_ack":
			return attempt{accepted: m.Status == "ok"}
		}
	}
}

func (a attempt) refused() bool {
	return !a.accepted && (a.dialFailed || a.closeCode == WSRelayCloseRetry)
}

// exhaust opens a link as id and sends n snapshots, all acknowledged.
func exhaust(t *testing.T, base, id string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if a := snapshotAttempt(t, base, id); !a.accepted {
			// each attempt is a NEW link: with a quota by identity the (n+1)th is refused, never the first n
			t.Fatalf("snapshot %d/%d of %s refused too early: %+v", i+1, n, id, a)
		}
	}
}

func quotaServer(t *testing.T) (base string) {
	t.Helper()
	newFakeRouting(t)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	t.Cleanup(srv.Close)
	return srv.URL
}

// 1. The quota survives the reconnection.
func TestSnapshotQuota_AReconnectionDoesNotResetTheCounter(t *testing.T) {
	requireQuotaByIdentity(t)
	setQuota(t, 3, time.Minute)
	base := quotaServer(t)
	exhaust(t, base, "relay1", 3) // three links, one snapshot each: the whole quota of the identity
	// the child ignores its backoff and reconnects at once
	for i := 0; i < 3; i++ {
		if a := snapshotAttempt(t, base, "relay1"); !a.refused() {
			t.Fatalf("reconnection %d: %+v — an exhausted identity must be refused (4012 / handshake) until the window is over", i+1, a)
		}
	}
}

// 1b. The first snapshot of a new link counts too (otherwise every reconnection offers a free one).
func TestSnapshotQuota_TheFirstSnapshotOfANewLinkCounts(t *testing.T) {
	requireQuotaByIdentity(t)
	setQuota(t, 3, time.Minute)
	base := quotaServer(t)

	c, ok := specDial(t, base, "relay1") // ONE link: first snapshot + 2 replacements = 3
	if !ok {
		t.Fatal("dial")
	}
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: "relay1", Version: "3.0"}); err != nil {
		t.Fatal(err)
	}
	readMsg(t, c) // relay_ack
	for i := 0; i < 3; i++ {
		sendSnapshot(t, c, nil, nil)
		expectAck(t, readMsg(t, c))
	}
	_ = c.Close()
	if a := snapshotAttempt(t, base, "relay1"); !a.refused() {
		t.Fatalf("the quota is spent (first snapshot included): a new link must be refused, got %+v", a)
	}
}

// 2. No permanent block.
func TestSnapshotQuota_TheChildIsAcceptedAgainWhenTheWindowIsOver(t *testing.T) {
	requireQuotaByIdentity(t)
	const window = 500 * time.Millisecond
	setQuota(t, 2, window)
	base := quotaServer(t)
	start := time.Now()
	exhaust(t, base, "relay1", 2)
	if a := snapshotAttempt(t, base, "relay1"); !a.refused() && time.Since(start) < window {
		t.Fatalf("inside the window an exhausted identity must be refused, got %+v", a)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if snapshotAttempt(t, base, "relay1").accepted {
			if time.Since(start) < window {
				t.Fatalf("accepted again after %s, before the window (%s) was over", time.Since(start), window)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("still refused long after the window: a permanent block")
}

// 3. Quotas are per identity.
func TestSnapshotQuota_DistinctIdentitiesHaveIndependentQuotas(t *testing.T) {
	requireQuotaByIdentity(t)
	setQuota(t, 2, time.Minute)
	base := quotaServer(t)
	exhaust(t, base, "relay1", 2)
	if a := snapshotAttempt(t, base, "relay1"); !a.refused() {
		t.Fatalf("relay1 must be refused: %+v", a)
	}
	for _, id := range []string{"relay2", "relay3"} {
		exhaust(t, base, id, 2) // untouched by relay1's abuse
	}
}

// 4. The table does not grow without bound.
func TestSnapshotQuota_TheTableIsPurgedAfterInactivity(t *testing.T) {
	requireQuotaByIdentity(t)
	if specSnapshotQuotaEntries == nil {
		t.Skip("PENDING #156: specSnapshotQuotaEntries is not wired (snapshot_quota_spec_wire_test.go)")
	}
	const window = 300 * time.Millisecond
	setQuota(t, 5, window)
	base := quotaServer(t)
	for i := 0; i < 30; i++ {
		id := "relay-" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if a := snapshotAttempt(t, base, id); !a.accepted {
			t.Fatalf("%s: %+v", id, a)
		}
	}
	if n := specSnapshotQuotaEntries(); n == 0 || n > 30 {
		t.Fatalf("entries = %d, want 1..30 (one per identity seen)", n)
	}
	time.Sleep(2 * window)
	// the purge runs on activity: one more identity triggers it, then the table must be bounded
	if a := snapshotAttempt(t, base, "relay-late"); !a.accepted {
		t.Fatalf("relay-late: %+v", a)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if specSnapshotQuotaEntries() <= 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("entries = %d after inactivity longer than the window: not purged", specSnapshotQuotaEntries())
}

// lockedBuf is a goroutine-safe log sink (the handlers log from their own goroutines).
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// 6. Logs: the warning names the relay and nothing else.
func TestSnapshotQuota_TheWarningNamesTheRelayAndLeaksNoToken(t *testing.T) {
	requireQuotaByIdentity(t)
	setQuota(t, 2, time.Minute)
	out := &lockedBuf{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	base := quotaServer(t)
	exhaust(t, base, "relay1", 2)
	_ = snapshotAttempt(t, base, "relay1") // refused
	awaitCondition(2*time.Second, func() bool { return strings.Contains(out.String(), "[SECURITY WARNING]") })
	logs := out.String()
	if !strings.Contains(logs, "[SECURITY WARNING]") || !strings.Contains(logs, `relay_id="relay1"`) {
		t.Errorf("a [SECURITY WARNING] naming relay_id=\"relay1\" is expected:\n%s", logs)
	}
	for _, leak := range []string{"Bearer", makeRelayJWT("relay1", relayRoleChild)} {
		if strings.Contains(logs, leak) {
			t.Errorf("the log leaks %q", leak)
		}
	}
}
