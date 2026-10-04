package repeater

import (
	"strings"
	"testing"
)

// Every refusal path must (1) be logged with its own marker — so the test proves the path was
// really exercised and the causes stay distinguishable — and (2) never leak the token, its
// fragments, its encodings nor the Authorization header (same needles as TestLogs_*, #149).
func TestRefusalLogs_NeverLeakToken(t *testing.T) {
	cases := []struct {
		name    string
		markers []string
		run     func(t *testing.T)
	}{
		{
			name:    "client close 4010",
			markers: []string{"[REPEATER] ERROR parent refused link (permanent)", "operator action required", "peer closed with code 4010"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, CloseCodePermanent, "central")
				c, _ := refusalClient(t, p)
				awaitDone(t, c.Done(), "client gives up after 4010")
			},
		},
		{
			name:    "client parent identity changed",
			markers: []string{"[REPEATER] ERROR parent refused link (permanent)", "operator action required", "parent identity changed"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, 0, "central")
				c, _ := refusalClient(t, p)
				waitFor(t, waitTimeout, "first link", func() bool { return c.ParentID() != "" })
				p.ackID.Store("impostor")
				p.dropLinks()
				awaitDone(t, c.Done(), "identity mismatch is terminal")
			},
		},
		{
			name:    "client correctable 4012",
			markers: []string{"parent refused link (correctable), retrying", "peer closed with code 4012"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, CloseCodeRetry, "central")
				refusalClient(t, p)
				waitAttempts(t, p, 3)
			},
		},
		{
			name:    "dialer close 4010",
			markers: []string{"[REPEATER] ERROR child child1 refused link (permanent)", "operator action required", "peer closed with code 4010"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, CloseCodePermanent, "child1")
				d, _ := refusalDialer(t, p, "child1", func(string) bool { return false })
				awaitTerminal(t, d)
			},
		},
		{
			name: "dialer child identity mismatch (impersonation)",
			markers: []string{"[SECURITY WARNING] dial-out refused: expected child", "relay_ack announced",
				"[REPEATER] ERROR child child1 refused link (permanent)", "child identity mismatch"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, 0, "impostor")
				d, _ := refusalDialer(t, p, "child1", func(string) bool { return false })
				awaitTerminal(t, d)
			},
		},
		{
			name: "dialer loop",
			markers: []string{"[SECURITY WARNING] dial-out refused: child root is this node or one of its ancestors (loop)",
				"[REPEATER] ERROR child root refused link (permanent)", "loop: child is this node or one of its ancestors"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, 0, "root")
				d, _ := refusalDialer(t, p, "root", func(id string) bool { return id == "root" })
				awaitTerminal(t, d)
			},
		},
		{
			name:    "dialer correctable 4012",
			markers: []string{"child child1 refused link (correctable), retrying", "peer closed with code 4012"},
			run: func(t *testing.T) {
				p := newRefusalPeer(t, CloseCodeRetry, "child1")
				refusalDialer(t, p, "child1", func(string) bool { return false })
				waitAttempts(t, p, 3)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := captureLogs(t)
			tc.run(t)
			logs := sink.String()
			for _, m := range tc.markers {
				if !strings.Contains(logs, m) {
					t.Errorf("missing log marker %q (path not exercised or message changed):\n%s", m, logs)
				}
			}
			assertNoLeak(t, logs, leakToken)
		})
	}
}
