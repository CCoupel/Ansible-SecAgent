package ws

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/auth"
)

// A link_state is stored and relayed upward: its current_kid must have the exact shape of a LinkKID,
// whatever the peer sends (QA: 100 x 1 MiB kids made the root's memory grow by 900 MiB).
func TestHandleLinkState_BoundsAndShapeOfTheKID(t *testing.T) {
	good := auth.LinkKID(make([]byte, 32))
	conn := &RelayConnection{RelayID: "relay1", descendants: map[string]struct{}{}}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	var relayed [][]byte
	SetLinkStateUpstreamFunc(func(f []byte) { relayed = append(relayed, f) })
	defer SetLinkStateUpstreamFunc(nil)

	handleLinkState(conn, RelayMessage{Type: MsgLinkState, RelayID: "relay1", Seq: 1, CurrentKID: good})
	if st, ok := LinkStates()["relay1"]; !ok || st.KID != good || len(relayed) != 1 {
		t.Fatalf("a valid link_state must be recorded and relayed: %v %d", LinkStates()["relay1"], len(relayed))
	}

	for name, kid := range map[string]string{
		"1 MiB": strings.Repeat("A", 1<<20), "too long": strings.Repeat("A", 23), "empty": "",
		"bad alphabet": "AAAAAAAAAAAAAAAAAAAA+/", "newline": "AAAAAAAAAAAAAAAAAAAAA\n",
	} {
		before := len(relayed)
		handleLinkState(conn, RelayMessage{Type: MsgLinkState, RelayID: "relay1", Seq: 99, CurrentKID: kid})
		if st := LinkStates()["relay1"]; st.Seq != 1 || st.KID != good {
			t.Errorf("%s: the stored state changed: %+v", name, st)
		}
		if len(relayed) != before {
			t.Errorf("%s: a malformed link_state was relayed", name)
		}
	}
	if !strings.Contains(buf.String(), "SECURITY WARNING") {
		t.Error("a refusal must be logged")
	}
	if strings.Contains(buf.String(), strings.Repeat("A", 100)) {
		t.Error("the log must not echo the value")
	}
}

func TestLinkStates_DoNotGrowWithRepeatedReportsOfTheSameRelay(t *testing.T) {
	good := auth.LinkKID(make([]byte, 32))
	conn := &RelayConnection{RelayID: "relay-grow", descendants: map[string]struct{}{}}
	for i := 0; i < 1000; i++ {
		handleLinkState(conn, RelayMessage{Type: MsgLinkState, RelayID: "relay-grow", Seq: uint64(i), CurrentKID: good})
	}
	n := 0
	for id := range LinkStates() {
		if id == "relay-grow" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one entry per relay_id expected, got %d", n)
	}
}
