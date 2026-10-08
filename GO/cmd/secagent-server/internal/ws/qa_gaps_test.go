package ws

// QA v3.0.4 reserves R2 — tests that kill the mutants which survived the QA mutation campaign
// (_work/reports/qa-20261008-v304.md, lot 2): #179 reserved-stdout refund and global cap, #156 handshake
// refusal / window reset on an injected clock / bound of the table, #180 guard "connected locally AND routed".
// Every test states the mutant it kills.

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ── #179 ─────────────────────────────────────────────────────────────────────

// Mutant: refundStdout removed. A chunk cut on a rune boundary keeps less than what was reserved; the
// difference must be given back, else the global budget is over-counted until the task ends.
func TestQAGaps_ACutOnARuneBoundaryGivesBackWhatWasReserved(t *testing.T) {
	setLimits(t, 10, 10, 0)
	mustFuture(RegisterFuture("u1", "host-a"))
	t.Cleanup(func() { UnregisterFuture("u1") })
	HandleMessage(Message{TaskID: "u1", Type: "stdout", Chunk: strings.Repeat("x", stdoutMaxBytes-1)}, "host-a")
	// one byte of room: a two-byte rune does not fit and must not be split
	HandleMessage(Message{TaskID: "u1", Type: "stdout", Chunk: "éé"}, "host-a")

	got := stdoutString("u1")
	if !utf8.ValidString(got) || len(got) != stdoutMaxBytes-1 {
		t.Fatalf("kept %d bytes (valid UTF-8: %v), want %d: the rune must be dropped whole", len(got), utf8.ValidString(got), stdoutMaxBytes-1)
	}
	if held := stdoutHeldBytes(); held != int64(stdoutMaxBytes-1) {
		t.Errorf("held = %d, want %d: the byte reserved for the dropped rune was not given back", held, stdoutMaxBytes-1)
	}
	UnregisterFuture("u1")
	if held := stdoutHeldBytes(); held != 0 {
		t.Errorf("held = %d after the task ended, want 0", held)
	}
}

// Mutant: the global cap removed from reserveStdout. Admission makes it redundant, except when the budget
// is lowered while tasks are in flight (SetTaskLimits keeps the admitted ones): the bytes held must then
// still obey the new budget.
func TestQAGaps_LoweringTheBudgetCapsTheStdoutOfTasksAlreadyAdmitted(t *testing.T) {
	setLimits(t, 10, 10, 0)
	mustFuture(RegisterFuture("g1", "host-a"))
	t.Cleanup(func() { UnregisterFuture("g1") }) // also drops its stdout buffer (the test may run twice: -count)
	const mib = 1 << 20
	SetTaskLimits(0, 0, 1*mib) // lowered AFTER the admission of g1
	HandleMessage(Message{TaskID: "g1", Type: "stdout", Chunk: strings.Repeat("x", 2*mib)}, "host-a")
	if held := stdoutHeldBytes(); held > 1*mib {
		t.Errorf("held = %d bytes, above the lowered budget of %d", held, 1*mib)
	}
	if got := len(stdoutString("g1")); got > 1*mib {
		t.Errorf("buffered %d bytes, above the lowered budget", got)
	}
}

// ── #156 ─────────────────────────────────────────────────────────────────────

func resetQuotaTable(t *testing.T) {
	t.Helper()
	snapQuotaMu.Lock()
	snapQuotas = map[string]*snapQuota{}
	snapPurged = time.Time{}
	snapQuotaMu.Unlock()
	t.Cleanup(func() {
		snapQuotaMu.Lock()
		snapQuotas = map[string]*snapQuota{}
		snapPurged = time.Time{}
		snapQuotaMu.Unlock()
	})
}

// Mutant: the window of an EXISTING entry never restarts (`now.Sub(q.start) >= window` removed from
// allowSnapshot). The periodic purge hides it, so the scenario places the end of the window of A between
// two purges, on an injected clock (no sleep).
func TestQAGaps_TheWindowOfAnExistingEntryRestartsBetweenTwoPurges(t *testing.T) {
	setQuota(t, 3, time.Minute)
	resetQuotaTable(t)
	t0 := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)

	allowSnapshot("first", t0) // purge runs at t0 (first call)
	for i := 0; i < 3; i++ {
		if !allowSnapshot("A", t0.Add(30*time.Second)) {
			t.Fatalf("snapshot %d of A is within the quota", i+1)
		}
	}
	if allowSnapshot("A", t0.Add(31*time.Second)) {
		t.Fatal("the 4th snapshot of A in the window must be refused")
	}
	allowSnapshot("trigger", t0.Add(60*time.Second)) // the purge runs again: drops "first", keeps A (30 s old)
	if snapshotQuotaEntries() != 2 {                 // A and trigger
		t.Fatalf("entries = %d, want 2 (A kept by the purge)", snapshotQuotaEntries())
	}
	// t0+90 s: A's window (started at t0+30 s) is over; the next purge is not due (last one at t0+60 s)
	if snapshotQuotaExhausted("A", t0.Add(90*time.Second)) {
		t.Error("handshake: an expired window must not keep A refused")
	}
	if !allowSnapshot("A", t0.Add(90*time.Second)) {
		t.Fatal("A must be accepted again once its window is over, purge or not")
	}
}

// Mutant: eviction at maxQuotaEntries removed. The table is bounded in memory; the entry that is evicted
// is the OLDEST window, never the newest.
func TestQAGaps_TheQuotaTableIsBoundedAndEvictsTheOldestWindow(t *testing.T) {
	setQuota(t, 40, time.Hour) // nothing expires: only the bound can keep the table small
	resetQuotaTable(t)
	t0 := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	total := maxQuotaEntries + 500
	for i := 0; i < total; i++ {
		allowSnapshot(fmt.Sprintf("relay-%05d", i), t0.Add(time.Duration(i)*time.Millisecond))
		if n := snapshotQuotaEntries(); n > maxQuotaEntries {
			t.Fatalf("after %d identities the table holds %d entries, bound is %d", i+1, n, maxQuotaEntries)
		}
	}
	snapQuotaMu.Lock()
	_, oldest := snapQuotas["relay-00000"]
	_, newest := snapQuotas[fmt.Sprintf("relay-%05d", total-1)]
	snapQuotaMu.Unlock()
	if oldest {
		t.Error("the oldest window must be the one evicted")
	}
	if !newest {
		t.Error("the newest identity must be kept")
	}
}

// Mutant: the check at relay_hello removed (the refusal then comes with the first snapshot instead of the
// handshake). The spec: an exhausted identity is refused BEFORE any snapshot — it never gets a relay_ack.
func TestQAGaps_AnExhaustedIdentityIsRefusedAtTheHelloBeforeAnyAck(t *testing.T) {
	setQuota(t, 2, time.Minute)
	base := quotaServer(t)
	exhaust(t, base, "relay1", 2)

	c, ok := specDial(t, base, "relay1")
	if !ok {
		return // refused at the HTTP upgrade: also before any snapshot
	}
	if err := c.WriteJSON(RelayMessage{Type: "relay_hello", NodeType: "relay", RelayID: "relay1", Version: "3.0"}); err != nil {
		return
	}
	if code := expectClose(t, c); code != WSRelayCloseRetry {
		t.Errorf("close code %d, want %d (correctable) and no relay_ack in between", code, WSRelayCloseRetry)
	}
}

// ── #180 ─────────────────────────────────────────────────────────────────────

// Mutant: the guard "connected locally" of host.suspended / host.resumed removed. The host IS routed
// through the sender, which alone would let the event through: a live local agent still wins.
func TestQAGaps_ASuspensionEventForAHostConnectedHereAndAlsoRoutedIsRefused(t *testing.T) {
	sink := recordSuspensions(t)
	r := newEventRig(t, map[string]string{"host-A": "dmz1"})
	RegisterConnection("host-A", &AgentConnection{Hostname: "host-A"})
	t.Cleanup(func() { UnregisterConnection("host-A") })

	r.send(RelayMessage{Event: "host.suspended", Hostname: "host-A", RelayChain: []string{"dmz1"}})
	r.send(RelayMessage{Event: "host.resumed", Hostname: "host-A", RelayChain: []string{"dmz1"}})
	r.ready()
	if got := sink.snapshot(); len(got) != 0 {
		t.Errorf("an event about a local agent changed the state: %v", got)
	}
	if got := r.local.list(); len(got) != 0 || r.upstreamCount() != 0 {
		t.Errorf("the event was dispatched (%d) or forwarded (%d)", len(got), r.upstreamCount())
	}
}
