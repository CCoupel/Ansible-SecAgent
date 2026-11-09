// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"errors"
	"net"
	"strings"
	"testing"

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
