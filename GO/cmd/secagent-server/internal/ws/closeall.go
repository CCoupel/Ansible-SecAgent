package ws

import (
	"log"
	"time"

	"github.com/gorilla/websocket"
)

// CloseAllLinks closes EVERY live WebSocket this node serves or holds (agents, child relays, parent
// links accepted from a push parent) with the given close code, and returns how many were closed.
// It is used when the node stops: a clean shutdown and above all the loss of the master lock (#163).
//
// The code must be one the peers reconnect on: 1001 (Going Away) or 4000. Never WSCloseRevoked
// (4001, "agent must not reconnect") nor the permanent relay refusal 4010: a minion or a relay that
// received them would stop trying to join the new master. Such a code is replaced by 1001.
//
// Frames are written with WriteControl (safe next to a concurrent writer, bounded by a short
// deadline: a stuck peer must not delay the exit); the connection is then closed whatever happened.
func CloseAllLinks(code int, reason string) int {
	if code == WSCloseRevoked || code == WSRelayCloseRevoked {
		// a permanent code would forbid reconnecting to the next master: never send it from here
		log.Printf("[WARN] CloseAllLinks: close code %d forbids reconnection, using 1001 instead", code)
		code = websocket.CloseGoingAway
	}
	var conns []*websocket.Conn

	connectionsMu.RLock()
	for _, c := range wsConnections {
		if c != nil && c.Conn != nil {
			conns = append(conns, c.Conn)
		}
	}
	connectionsMu.RUnlock()

	relayConnsMu.RLock()
	for _, rc := range relayConnections {
		if rc != nil && rc.wsConn != nil {
			conns = append(conns, rc.wsConn)
		}
	}
	relayConnsMu.RUnlock()

	parentLinksMu.Lock()
	for _, c := range parentLinks {
		if c != nil {
			conns = append(conns, c)
		}
	}
	parentLinksMu.Unlock()

	frame := websocket.FormatCloseMessage(code, reason)
	for _, c := range conns {
		_ = c.WriteControl(websocket.CloseMessage, frame, time.Now().Add(250*time.Millisecond))
		_ = c.Close()
	}
	return len(conns)
}
