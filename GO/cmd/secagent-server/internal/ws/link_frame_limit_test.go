package ws

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The size of a link_* frame is checked on the raw bytes of the generic /ws/relay read, before the
// decoding: link_state <= 512 bytes, link_keys / link_revocations <= 1 MiB; the 10 MiB read limit stays
// the rule of every other type.
func TestLinkFrameLimits_ByType(t *testing.T) {
	big := func(typ string, n int) []byte {
		b, _ := json.Marshal(map[string]any{"type": typ, "pad": strings.Repeat("x", n)})
		return b
	}
	tests := []struct {
		name  string
		raw   []byte
		limit int
	}{
		{"link_state", big(MsgLinkState, 10), maxLinkStateFrame},
		{"link_keys", big(MsgLinkKeys, 10), maxLinkKeysFrame},
		{"link_revocations", big(MsgLinkRevocations, 10), maxLinkKeysFrame},
		{"another type", big("agent_list", 10), 0},
		{"not json, link type among the first bytes", []byte(`{"type":"link_state","pad":"` + strings.Repeat("x", 600)), maxLinkStateFrame},
	}
	for _, tt := range tests {
		if got := linkFrameLimit(tt.raw); got != tt.limit {
			t.Errorf("%s: limit %d, want %d", tt.name, got, tt.limit)
		}
	}
}

func TestLinkFrameLimits_AnOversizedLinkFrameClosesTheLinkWith4012(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  string
		size int
	}{
		{"link_state above 512 bytes", MsgLinkState, 600},
		{"link_revocations above 1 MiB", MsgLinkRevocations, 1<<20 + 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTreeHooks(t, "dmz1", nil, nil, nil)
			srv := setupRelayTestServer(t)
			defer srv.Close()
			c := dialRelay(t, srv, makeRelayJWT("child1", "relay"))
			handshake(t, c, "child1")
			if err := c.WriteJSON(map[string]any{"type": tc.typ, "pad": strings.Repeat("x", tc.size)}); err != nil {
				t.Fatal(err)
			}
			if code := expectClose(t, c); code != WSRelayCloseRetry {
				t.Errorf("close code = %d, want 4012", code)
			}
			if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("child1") }) {
				t.Error("the link must be gone")
			}
		})
	}
}

func TestLinkFrameLimits_AWellSizedLinkStateKeepsTheLink(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("child1", "relay"))
	handshake(t, c, "child1")
	if err := c.WriteJSON(RelayMessage{Type: MsgLinkState, RelayID: "child1", Seq: 1, CurrentKID: "AAAAAAAAAAAAAAAAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if !IsRelayConnected("child1") {
		t.Error("a normal link_state must not close the link")
	}
}
