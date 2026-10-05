package ws

import (
	"strings"
	"testing"
)

// Identifiers supplied by an agent are logged with %q: they cannot forge a log line, and the whole
// message of an agent is never dumped (it may carry command output).
func TestHandleMessageQuotesAgentIdentifiersAndNeverDumpsTheMessage(t *testing.T) {
	sink := captureWSLogs(t)
	evil := "t1\nFAKE [SECURITY WARNING] forged"
	for _, msg := range []Message{
		{TaskID: evil, Type: "ack"},
		{TaskID: evil, Type: "nonsense\nFAKE type"},
		{TaskID: evil, Type: "", Stdout: "SECRET-COMMAND-OUTPUT"},
		{TaskID: evil, Type: "stdout", Stdout: "SECRET-COMMAND-OUTPUT"},
		{TaskID: evil, Type: "result"},
	} {
		HandleMessage(msg, "h\nFAKE host")
	}
	out := sink.String()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "FAKE") {
			t.Errorf("forged log line: %q\nfull log:\n%s", l, out)
		}
	}
	if strings.Contains(out, "SECRET-COMMAND-OUTPUT") {
		t.Errorf("a message of an agent must never be dumped in the log:\n%s", out)
	}
}
