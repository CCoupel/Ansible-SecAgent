package ws

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// serverConn opens a WebSocket pair: the server side conn (to register) and the client side.
func serverConn(t *testing.T) (server, client *websocket.Conn) {
	t.Helper()
	up := websocket.Upgrader{}
	ch := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ch <- c
		select {} // keep the handler (and the hijacked conn) alive until the test ends
	}))
	t.Cleanup(srv.Close)
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return <-ch, cl
}

func closeCodeOf(t *testing.T, c *websocket.Conn) int {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err := c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a close frame, got %v", err)
	}
	return ce.Code
}

func TestCloseAllLinks_AgentsRelaysAndParentLinksGetTheCodeAndNever4001(t *testing.T) {
	agentSrv, agentCl := serverConn(t)
	relaySrv, relayCl := serverConn(t)
	parentSrv, parentCl := serverConn(t)

	connectionsMu.Lock()
	wsConnections["agent-x"] = &AgentConnection{Hostname: "agent-x", Conn: agentSrv}
	connectionsMu.Unlock()
	relayConnsMu.Lock()
	relayConnections["relay-x"] = &RelayConnection{RelayID: "relay-x", wsConn: relaySrv}
	relayConnsMu.Unlock()
	registerParentLink("jti-x", parentSrv)
	t.Cleanup(func() {
		connectionsMu.Lock()
		delete(wsConnections, "agent-x")
		connectionsMu.Unlock()
		relayConnsMu.Lock()
		delete(relayConnections, "relay-x")
		relayConnsMu.Unlock()
		unregisterParentLink("jti-x", parentSrv)
	})

	if n := CloseAllLinks(1001, "master lock lost"); n < 3 {
		t.Fatalf("closed %d links, want at least 3", n)
	}
	for name, c := range map[string]*websocket.Conn{"agent": agentCl, "relay": relayCl, "parent": parentCl} {
		if code := closeCodeOf(t, c); code != 1001 {
			t.Errorf("%s link closed with %d, want 1001", name, code)
		}
	}
}

func TestCloseAllLinks_RefusesTheCodesThatForbidReconnecting(t *testing.T) {
	for _, code := range []int{WSCloseRevoked, WSRelayCloseRevoked} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("close code %d must be refused: it forbids reconnecting to the next master", code)
				}
			}()
			CloseAllLinks(code, "x")
		}()
	}
}
