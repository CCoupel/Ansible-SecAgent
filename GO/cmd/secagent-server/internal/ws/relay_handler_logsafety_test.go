package ws

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── peer-controlled text must not forge log lines (#154) ─────────────────────

type safeSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func captureWSLogs(t *testing.T) *safeSink {
	t.Helper()
	sink := &safeSink{}
	prev := log.Writer()
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(prev) })
	return sink
}

const wsForged = "evil\nFAKE [SECURITY WARNING] forged"

func forgedLines(logs string) (fake []string) {
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, "FAKE") {
			fake = append(fake, l)
		}
	}
	return fake
}

func TestLogSafety_PeerTextStaysOnItsOwnLogLine(t *testing.T) {
	sink := captureWSLogs(t)
	recordRoutes(t)
	recordConflicts(t)
	events := make(chan RelayMessage, 4)
	setTreeHooks(t, "central", nil, nil, func(m RelayMessage) { events <- m })
	setHostRoutes(t, map[string]string{wsForged: "relay-other"}) // the forged hostname conflicts with another owner
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")

	// 1. unknown message type, 2. forged task_id, 3. forged hostname in a conflicting host.up,
	// 4. forged relay_chain element refused by validation
	_ = c.WriteJSON(RelayMessage{Type: wsForged})
	_ = c.WriteJSON(RelayMessage{Type: "task_result", TaskID: wsForged})
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: wsForged, Hostname: "h", Status: "connected", RelayChain: []string{"dmz1"}}) // forged event kind: refused, logged escaped
	_ = c.WriteJSON(RelayMessage{Type: "event_forward", Event: "host.up", Status: "connected", Hostname: "h", RelayChain: []string{wsForged, "dmz1"}})
	_ = c.WriteJSON(RelayMessage{Type: "heartbeat"}) // barrier: all previous messages are processed
	readMsg(t, c)
	time.Sleep(20 * time.Millisecond)

	logs := sink.String()
	fake := forgedLines(logs)
	if len(fake) < 3 {
		t.Fatalf("expected the forged text in at least 3 genuine log lines, got %d:\n%s", len(fake), logs)
	}
	for _, l := range fake {
		if strings.HasPrefix(strings.TrimSpace(l), "FAKE") {
			t.Errorf("forged log line injected: %q", l)
		}
		// the text is quoted: the newline is shown escaped inside the genuine line
		if !strings.Contains(l, `\n`) {
			t.Errorf("the peer text must be escaped (%%q) in the log line: %q", l)
		}
	}
}

func TestLogSafety_SnapshotValidationErrorIsEscaped(t *testing.T) {
	sink := captureWSLogs(t)
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, c, "dmz1")
	sendSnapshot(t, c, nil, []RelayAgentInfo{{Hostname: "h", RelayID: "dmz1", RelayChain: []string{"dmz1", wsForged}}})
	expectClose(t, c)
	fake := forgedLines(sink.String())
	if len(fake) == 0 {
		t.Fatalf("vacuous test:\n%s", sink.String())
	}
	for _, l := range fake {
		if strings.HasPrefix(strings.TrimSpace(l), "FAKE") || !strings.Contains(l, `\n`) {
			t.Errorf("unescaped or injected peer text: %q", l)
		}
	}
}
