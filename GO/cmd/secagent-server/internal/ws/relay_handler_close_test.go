package ws

import (
	"errors"
	"github.com/gorilla/websocket"
	"net/http"
	"testing"
	"time"
)

// ── CloseRelay and the revoked check (#153) ──────────────────────────────────

func TestCloseRelay_ClosesActiveLinkWithGivenCode(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	a := dialRelay(t, srv, makeRelayJWT("relay-a", "relay"))
	b := dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	if !awaitRelayConnected(t, "relay-a", 2*time.Second) || !awaitRelayConnected(t, "relay-b", 2*time.Second) {
		t.Fatal("relays not connected")
	}
	if CloseRelay("ghost", WSRelayCloseRevoked, "x") {
		t.Error("an unknown relay must return false")
	}
	if !CloseRelay("relay-a", WSRelayCloseRevoked, "token revoked") {
		t.Fatal("relay-a must be closed")
	}
	if code := expectClose(t, a); code != WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", code)
	}
	if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("relay-a") }) {
		t.Error("relay-a must be unregistered after the close")
	}
	// the other link is untouched and still answers
	if err := b.WriteJSON(RelayMessage{Type: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	if m := readMsg(t, b); m.Type != "heartbeat_ack" {
		t.Errorf("relay-b affected: %+v", m)
	}
}

func TestRevokedCheck_RefusesRevokedErrorAndUnconfigured(t *testing.T) {
	t.Cleanup(func() { SetRelayRevokedFunc(func(string) (bool, error) { return false, nil }) })
	srv := setupRelayTestServer(t)
	defer srv.Close()
	tok := makeRelayJWT("relay-a", "relay")

	for name, fn := range map[string]func(string) (bool, error){
		"revoked":      func(id string) (bool, error) { return id == "relay-a", nil },
		"check errors": func(string) (bool, error) { return false, errors.New("db down") },
		"unconfigured": nil,
	} {
		SetRelayRevokedFunc(fn)
		if code := dialRelayExpectFail(t, srv, tok); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401 (fail closed)", name, code)
		}
	}
	// a different, non-revoked relay still connects
	SetRelayRevokedFunc(func(id string) (bool, error) { return id == "relay-a", nil })
	dialRelay(t, srv, makeRelayJWT("relay-b", "relay"))
	if !awaitRelayConnected(t, "relay-b", 2*time.Second) {
		t.Error("relay-b must connect")
	}
}

// The revoked flag concerns CHILD links only: a parent (relay-parent token) is never a relay_nodes row.
func TestRevokedCheck_NotAppliedToParentLinks(t *testing.T) {
	setTreeHooks(t, "dmz1", nil, nil, nil)
	t.Cleanup(func() { SetRelayRevokedFunc(func(string) (bool, error) { return false, nil }) })
	SetRelayRevokedFunc(func(string) (bool, error) { return true, nil }) // would refuse every child
	setParentLink(t, func(conn *websocket.Conn, _ []string) error { return nil }, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()
	c := dialRelay(t, srv, makeRelayJWT("central", "relay-parent"))
	parentHello(t, c, "central", nil)
	if m := readMsg(t, c); m.Type != "relay_ack" {
		t.Errorf("parent link must not be subject to the child revoked flag: %+v", m)
	}
}
