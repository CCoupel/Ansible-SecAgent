package repeater

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// ── log injection through peer-controlled text (#154, security-reviewer MOYEN) ───────────

func TestSanitizeText(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"newlines", "ok\nFAKE [SECURITY WARNING] x\r\nmore", "ok FAKE [SECURITY WARNING] x  more"},
		{"tabs and ESC", "a\tb\x1b[31mred", "a b [31mred"},
		{"NUL", "a\x00b", "a b"},
		{"unicode line separators", "a b c\u0085d", "a b c d"},
		{"trimmed", "  \n hi \r\n ", "hi"},
		{"plain unchanged", "peer closed with code 4010 (token revoked)", "peer closed with code 4010 (token revoked)"},
	}
	for _, tt := range tests {
		if got := sanitizeText(tt.in); got != tt.want {
			t.Errorf("%s: sanitizeText(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
	// bounded, rune-aligned, no control characters left whatever the input
	long := strings.Repeat("é\n", 500)
	got := sanitizeText(long)
	if len(got) > maxReasonLen+len("…") || !utf8.ValidString(got) {
		t.Errorf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	for _, r := range got {
		if unicode.IsControl(r) {
			t.Fatalf("control character %U left in %q", r, got)
		}
	}
}

// closeWithText returns a TLS server that, after relay_hello, closes with the given code/text.
func closeWithText(t *testing.T, code int, text string) string {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		var hello map[string]any
		if err := c.ReadJSON(&hello); err != nil {
			return
		}
		// control characters are legal in a close reason as long as it is valid UTF-8 and <= 123 bytes
		_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(time.Second))
	}))
	t.Cleanup(srv.Close)
	return "wss" + strings.TrimPrefix(srv.URL, "https")
}

// captureRawLogs redirects the standard logger to a plain sink. captureLogs (logs_test.go) also
// routes log through slog's text handler, which QUOTES messages and would hide a raw newline
// injection: production writes through the plain logger, so this is what must be tested.
func captureRawLogs(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return sink
}

const forged = "x\nFAKE [SECURITY WARNING] forged line\r\n[REPEATER] ERROR fake"

// linesWith returns the log lines that contain sub.
func linesWith(logs, sub string) []string {
	var out []string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

func TestLogSafety_CloseFrameTextCannotForgeLogLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want string // marker of the genuine line the text must stay inside
	}{
		{"permanent 4010", CloseCodePermanent, "operator action required"},
		{"correctable 4012", CloseCodeRetry, "refused link (correctable)"},
		{"other close code (generic path)", websocket.CloseGoingAway, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := captureRawLogs(t)
			url := closeWithText(t, tc.code, forged)
			c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: url, UpstreamToken: "tok"}, Options{
				TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
				MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for len(linesWith(sink.String(), "FAKE")) == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			logs := sink.String()
			fake := linesWith(logs, "FAKE")
			if len(fake) == 0 {
				t.Fatalf("the peer text never reached the logs: the test would be vacuous:\n%s", logs)
			}
			for _, l := range fake {
				if !strings.Contains(l, tc.want) {
					t.Errorf("the forged text must stay inside the genuine log line (%q):\n%q", tc.want, l)
				}
				if strings.HasPrefix(strings.TrimSpace(l), "FAKE") || strings.HasPrefix(l, "[SECURITY WARNING]") {
					t.Errorf("forged line injected: %q", l)
				}
			}
			// a forged "[REPEATER] ERROR fake" must not start its own line either
			for _, l := range strings.Split(logs, "\n") {
				if strings.Contains(l, "ERROR fake") && !strings.Contains(l, "FAKE") {
					t.Errorf("injected log line: %q", l)
				}
			}
			if c.Status().State != LinkRefusedPermanent && tc.code == CloseCodePermanent {
				t.Errorf("status = %+v", c.Status())
			}
			for _, r := range c.Status().Reason {
				if unicode.IsControl(r) {
					t.Fatalf("control character %U in the status reason %q", r, c.Status().Reason)
				}
			}
		})
	}
}

// relay_ack.relay_id is unvalidated peer text: it must not forge lines either.
func TestLogSafety_UnvalidatedRelayIDInAckIsEscaped(t *testing.T) {
	sink := captureRawLogs(t)
	p := newRefusalPeer(t, 0, "central\nFAKE [SECURITY WARNING] forged id")
	c, _ := refusalClient(t, p)
	waitStatus(t, c.Status, LinkConnected)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(sink.String(), "linked to parent") && time.Now().Before(deadline) { // logged just after the status flips
		time.Sleep(5 * time.Millisecond)
	}
	logs := sink.String()
	fake := linesWith(logs, "FAKE")
	if len(fake) == 0 {
		t.Fatalf("vacuous test, no log with the id:\n%s", logs)
	}
	for _, l := range fake {
		if strings.HasPrefix(strings.TrimSpace(l), "FAKE") || !strings.Contains(l, "parent") {
			t.Errorf("forged line: %q", l)
		}
	}
	if !strings.Contains(logs, "linked to parent") {
		t.Error("the 'linked to parent' log line was never emitted: vacuous test")
	}
}

func TestLogSafety_DialerIdentityMismatchIsEscaped(t *testing.T) {
	sink := captureRawLogs(t)
	p := newRefusalPeer(t, 0, "evil\nFAKE [SECURITY WARNING] forged")
	d, _ := refusalDialer(t, p, "child1", func(string) bool { return false })
	waitStatus(t, d.Status, LinkRefusedPermanent)
	for _, l := range linesWith(sink.String(), "FAKE") {
		if strings.HasPrefix(strings.TrimSpace(l), "FAKE") || !strings.Contains(l, "identity") && !strings.Contains(l, "refused") {
			t.Errorf("forged line: %q", l)
		}
	}
	st := d.Status()
	for _, r := range st.Reason {
		if unicode.IsControl(r) {
			t.Fatalf("control char in the status reason: %q", st.Reason)
		}
	}
}
