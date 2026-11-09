// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

func TestParseConnSeq(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int{
		"": 1, "0": 1, "-3": 1, "abc": 1, "1.5": 1, "1": 1, "2": 2, " 7 ": 7, "2147483648": 2147483648,
		"2147483649": 1, "99999999999999999999": 1, "0x10": 1,
	} {
		if got := ParseConnSeq(in); got != want {
			t.Errorf("ParseConnSeq(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestEventShape_RelayKinds(t *testing.T) {
	t.Parallel()
	ok := func(m RelayMessage) {
		t.Helper()
		if r := eventShapeError(m); r != "" {
			t.Errorf("%s %+v refused: %s", m.Event, m.Detail, r)
		}
	}
	bad := func(m RelayMessage, why string) {
		t.Helper()
		if r := eventShapeError(m); !strings.Contains(r, why) {
			t.Errorf("%s %+v: got %q, want a refusal mentioning %q", m.Event, m.Detail, r, why)
		}
	}
	chain := []string{"x", "p"}
	ok(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Mode: "pull",
		Detail: hooks.Detail{ConnSeq: 1, HostsRouted: 3000, RelaysBelow: 2, RelaysBelowIDs: []string{"a", "b"}}})
	ok(RelayMessage{Event: "relay.reconnect", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{ConnSeq: 5}})
	ok(RelayMessage{Event: "relay.failover", RelayID: "x", RelayChain: chain,
		Detail: hooks.Detail{Cause: "takeover", InstanceID: "abc123", PreviousInstanceID: "def456"}})
	ok(RelayMessage{Event: "relay.failover", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "start", InstanceID: "abc123"}})
	for _, reason := range []string{"revoked", "read_error", "idle_timeout", "peer_closed:1006", "rejected:4012"} {
		ok(RelayMessage{Event: "relay.down", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Reason: reason}})
	}

	bad(RelayMessage{Event: "relay.up", RelayID: "x", Hostname: "h", RelayChain: chain}, "no hostname")
	bad(RelayMessage{Event: "relay.up", RelayID: "bad id", RelayChain: chain}, "invalid relay id")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: []string{"y", "p"}}, "chain must start")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Mode: "evil"}, "invalid mode")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{ConnSeq: 1 << 32}}, "conn_seq")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{HostsRouted: -1}}, "counter")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{RelaysBelowIDs: make([]string, 257)}}, "too long")
	bad(RelayMessage{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{RelaysBelowIDs: []string{"a b"}}}, "relays_below_ids")
	bad(RelayMessage{Event: "relay.down", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Reason: "boom\nFAKE"}}, "reason")
	bad(RelayMessage{Event: "relay.down", RelayID: "x", RelayChain: chain}, "reason")
	bad(RelayMessage{Event: "relay.failover", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "x", InstanceID: "a"}}, "cause")
	bad(RelayMessage{Event: "relay.failover", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "start", InstanceID: "a b"}}, "instance_id")
	bad(RelayMessage{Event: "relay.nonsense", RelayID: "x", RelayChain: chain}, "unsupported")
}

func TestEventShape_HostReconnectAndConnSeq(t *testing.T) {
	t.Parallel()
	good := RelayMessage{Event: "host.reconnect", Hostname: "h1", Status: "connected", RelayChain: []string{"p"}, Detail: hooks.Detail{ConnSeq: 4}}
	if r := eventShapeError(good); r != "" {
		t.Fatalf("host.reconnect refused: %s", r)
	}
	good.Detail.ConnSeq = -1
	if r := eventShapeError(good); !strings.Contains(r, "conn_seq") {
		t.Errorf("a negative conn_seq must be refused, got %q", r)
	}
	good.Detail.ConnSeq = 1
	good.Status = "weird"
	if r := eventShapeError(good); r == "" {
		t.Error("an invalid status must be refused")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

var _ net.Error = timeoutErr{}

func TestDownReason(t *testing.T) {
	t.Parallel()
	cause := "revoked"
	revoked := &RelayConnection{}
	revoked.closeCause.Store(&cause)
	rejected := &RelayConnection{reject: &relayRejection{code: WSRelayCloseRetry}}
	for name, c := range map[string]struct {
		rc   *RelayConnection
		err  error
		want string
	}{
		"revoked":      {revoked, errors.New("closed"), "revoked"},
		"rejected":     {rejected, nil, "rejected:4012"},
		"frame":        {&RelayConnection{}, errLinkFrameTooLarge, "rejected:4012"},
		"peer close":   {&RelayConnection{}, &websocket.CloseError{Code: 1001}, "peer_closed:1001"},
		"abnormal":     {&RelayConnection{}, &websocket.CloseError{Code: 1006}, "peer_closed:1006"},
		"idle timeout": {&RelayConnection{}, timeoutErr{}, "idle_timeout"},
		"other":        {&RelayConnection{}, errors.New("boom"), "read_error"},
	} {
		if got := downReason(c.rc, c.err); got != c.want {
			t.Errorf("%s: downReason = %q, want %q", name, got, c.want)
		}
		if !downReasonShape.MatchString(c.want) {
			t.Errorf("%s: %q does not match the wire shape", name, c.want)
		}
	}
}

func TestEventShape_FieldWhitelistPerKind(t *testing.T) {
	t.Parallel()
	chain := []string{"x", "p"}
	free := "-rf ../../etc\nFAKE"
	// a free string on a kind that does not carry it is refused, whatever the kind
	cases := []RelayMessage{
		{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Reason: free}},
		{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "takeover"}},
		{Event: "relay.up", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{InstanceID: "abc"}},
		{Event: "relay.down", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Reason: "revoked", Cause: free}},
		{Event: "relay.down", RelayID: "x", RelayChain: chain, Mode: "pull", Detail: hooks.Detail{Reason: "revoked"}},
		{Event: "relay.failover", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "start", InstanceID: "a", Reason: free}},
		{Event: "relay.failover", RelayID: "x", RelayChain: chain, Detail: hooks.Detail{Cause: "start", InstanceID: "a", ConnSeq: 2}},
		{Event: "host.up", Hostname: "h", Status: "connected", RelayChain: chain, Detail: hooks.Detail{Reason: free}},
		{Event: "host.up", Hostname: "h", Status: "connected", RelayChain: chain, Detail: hooks.Detail{InstanceID: "a"}},
		{Event: "host.down", Hostname: "h", Status: "disconnected", RelayChain: chain, Detail: hooks.Detail{ConnSeq: 3}},
		{Event: "host.reconnect", Hostname: "h", Status: "connected", RelayChain: chain, Mode: free},
		{Event: "host.reconnect", Hostname: "h", Status: "connected", RelayChain: chain, Detail: hooks.Detail{Cause: free}},
		{Event: "host.new", Hostname: "h", Status: "disconnected", RelayChain: chain, Detail: hooks.Detail{PreviousInstanceID: "a"}},
	}
	for i, m := range cases {
		if r := eventShapeError(m); r == "" {
			t.Errorf("case %d (%s): must be refused", i, m.Event)
		}
	}
	// invalid values on the kinds that do carry the field
	if r := eventShapeError(RelayMessage{Event: "host.rerouted", Hostname: "h", OldRelay: "a", NewRelay: "b", RelayChain: chain, Detail: hooks.Detail{Cause: free}}); r == "" {
		t.Error("host.rerouted cause must be moved|direct|indirect")
	}
	if r := eventShapeError(RelayMessage{Event: "host.removed", Hostname: "h", RelayChain: chain, Detail: hooks.Detail{Cause: "other"}}); r == "" {
		t.Error("host.removed cause must be deleted")
	}
	if r := eventShapeError(RelayMessage{Event: "relay.removed", RelayID: "x", RelayChain: chain, Mode: free}); r == "" {
		t.Error("relay.removed mode must be pull|push")
	}
}

// relay.down after a REPLACING snapshot carries the hosts_routed of the last accepted snapshot.
func TestRelayDown_CarriesTheHostsRoutedOfTheLastSnapshot(t *testing.T) {
	var mu sync.Mutex
	var got []hooks.Event
	SetEventFunc(func(ev hooks.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	t.Cleanup(func() { SetEventFunc(nil) })
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	t.Cleanup(srv.Close)
	conn := dialRelay(t, srv, makeRelayJWT("dmz1", "relay"))
	handshake(t, conn, "dmz1")
	agents := func(n int) []RelayAgentInfo {
		out := make([]RelayAgentInfo, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, RelayAgentInfo{Hostname: "h" + strconv.Itoa(i), RelayID: "dmz1", RelayChain: []string{"dmz1"}})
		}
		return out
	}
	sendSnapshot(t, conn, nil, agents(2))
	readMsg(t, conn)
	sendSnapshot(t, conn, nil, agents(5)) // replacing snapshot
	readMsg(t, conn)
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"), time.Now().Add(time.Second))
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		var up, down *hooks.Event
		for i := range got {
			switch got[i].Name {
			case "relay.up":
				up = &got[i]
			case "relay.down":
				down = &got[i]
			}
		}
		mu.Unlock()
		if down != nil {
			if up == nil || up.Detail.HostsRouted != 2 {
				t.Errorf("relay.up = %+v, want hosts_routed 2 (one relay.up only, from the first snapshot)", up)
			}
			if down.Detail.HostsRouted != 5 || down.RelayID != "dmz1" || down.Detail.Reason != "peer_closed:1000" {
				t.Errorf("relay.down = %+v, want hosts_routed 5, reason peer_closed:1000", down)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no relay.down")
}

func TestConnSeqDecodingIsFailSafe(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int{`3`: 3, `"3"`: 0, `1.5`: 0, `null`: 0, `true`: 0, `99999999999999999999`: 0, `-2`: -2} {
		var m RelayMessage
		if err := json.Unmarshal([]byte(`{"type":"relay_hello","conn_seq":`+in+`}`), &m); err != nil {
			t.Errorf("conn_seq %s must not fail the frame: %v", in, err)
			continue
		}
		if int(m.ConnSeq) != want {
			t.Errorf("conn_seq %s decoded to %d, want %d", in, m.ConnSeq, want)
		}
	}
}
