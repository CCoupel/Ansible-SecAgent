package repeater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Uplink publishes this node's state to its single parent over an ESTABLISHED
// (post relay_hello / relay_ack) WebSocket: topology_snapshot, agent_list,
// event_forward, and receives task_forward. It is shared by the pull client
// (this node dialed the parent) and by the accepted-parent path (the parent
// dialed this node, #140): only one parent link may be served at a time.
type Uplink struct {
	id   string
	opts Options

	mu        sync.Mutex
	serving   bool
	ancestors []string   // ancestors of this node, parent first
	wmu       sync.Mutex // serialises writes on the current conn
}

// ErrUplinkBusy is returned by Serve when a parent link is already active (single parent).
var ErrUplinkBusy = errors.New("a parent link is already active")

// NewUplink builds an Uplink for the node id.
func NewUplink(id string, opts Options) *Uplink {
	return &Uplink{id: id, opts: normalizeOptions(opts)}
}

// Ancestors returns this node's ancestors (parent first, root last); nil when unlinked.
func (u *Uplink) Ancestors() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.ancestors...)
}

// SetAncestors records this node's ancestors, as learned from its parent.
func (u *Uplink) SetAncestors(a []string) {
	u.mu.Lock()
	u.ancestors = append([]string(nil), a...)
	u.mu.Unlock()
}

// Serve sends the topology_snapshot and agent_list then serves the link until it
// ends. It returns ErrUplinkBusy if another parent link is active. The ancestors
// are cleared when the link ends.
func (u *Uplink) Serve(ctx context.Context, conn *websocket.Conn) error {
	_, err := u.serve(ctx, conn)
	if !errors.Is(err, ErrUplinkBusy) {
		u.SetAncestors(nil)
	}
	return err
}

func (u *Uplink) serve(ctx context.Context, conn *websocket.Conn) (established bool, err error) {
	u.mu.Lock()
	if u.serving {
		u.mu.Unlock()
		return false, ErrUplinkBusy
	}
	u.serving = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.serving = false
		u.mu.Unlock()
	}()

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-sessCtx.Done(); _ = conn.Close() }()
	snap := Snapshot{}
	if u.opts.Snapshot != nil {
		snap = u.opts.Snapshot()
	}
	if snap.Relays == nil {
		snap.Relays = []TopoRelay{}
	}
	if snap.Agents == nil {
		snap.Agents = []TopoAgent{}
	}
	if err := u.write(conn, snapshotMessage{Type: "topology_snapshot", Relays: snap.Relays, Agents: snap.Agents}); err != nil {
		return false, fmt.Errorf("send topology_snapshot: %w", err)
	}
	established = true

	// 4. steady state
	if err := u.sendAgentList(conn); err != nil {
		return true, err
	}

	readDeadline := u.opts.PingInterval * readTimeoutFactor
	extend := func() error { return conn.SetReadDeadline(time.Now().Add(readDeadline)) }
	if err := extend(); err != nil {
		return true, err
	}
	conn.SetPongHandler(func(string) error { return extend() })

	readErr := make(chan error, 1)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			if err := extend(); err != nil {
				readErr <- err
				return
			}
			u.handleIncoming(sessCtx, conn, raw)
		}
	}()

	ping := time.NewTicker(u.opts.PingInterval)
	defer ping.Stop()
	list := time.NewTicker(u.opts.AgentListInterval)
	defer list.Stop()

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case err := <-readErr:
			return true, wrapRead("read", err)
		case <-ping.C:
			u.wmu.Lock()
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(u.opts.HandshakeTimeout))
			u.wmu.Unlock()
			if err != nil {
				return true, fmt.Errorf("ping: %w", err)
			}
		case <-list.C:
			if err := u.sendAgentList(conn); err != nil {
				return true, err
			}
		case <-u.changed():
			if err := u.sendAgentList(conn); err != nil {
				return true, err
			}
		case ev, ok := <-u.events():
			if !ok {
				continue
			}
			if err := u.forwardEvent(conn, ev); err != nil {
				return true, err
			}
		}
	}
}

// changed/events return nil channels (block forever) when unset.
func (u *Uplink) changed() <-chan struct{} { return u.opts.Changed }
func (u *Uplink) events() <-chan Event {
	if u.opts.Events == nil {
		return nil
	}
	return u.opts.Events
}

func (u *Uplink) closeWithCode(conn *websocket.Conn, code int, reason string) {
	u.wmu.Lock()
	defer u.wmu.Unlock()
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
}

func (u *Uplink) sendAgentList(conn *websocket.Conn) error {
	agents := []AgentInfo{}
	if u.opts.DirectAgents != nil {
		if a := u.opts.DirectAgents(); a != nil {
			agents = a
		}
	}
	msg := struct {
		Type   string      `json:"type"`
		Agents []AgentInfo `json:"agents"`
	}{"agent_list", agents}
	if err := u.write(conn, msg); err != nil {
		return fmt.Errorf("send agent_list: %w", err)
	}
	return nil
}

// ForwardChain returns relay_chain with REPEATER_ID appended, or an error if
// REPEATER_ID is already in it (anti-loop).
func ForwardChain(chain []string, id string) ([]string, error) {
	for _, r := range chain {
		if r == id {
			return nil, fmt.Errorf("loop detected: %q already in relay_chain", id)
		}
	}
	out := make([]string, 0, len(chain)+1)
	out = append(out, chain...)
	return append(out, id), nil
}

func (u *Uplink) forwardEvent(conn *websocket.Conn, ev Event) error {
	chain, err := ForwardChain(ev.RelayChain, u.id)
	if err != nil {
		log.Printf("[REPEATER] event %s dropped: %v", ev.Event, err)
		return nil
	}
	ev.RelayChain = chain
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if err := u.write(conn, eventMessage{Type: "event_forward", Event: ev}); err != nil {
		return fmt.Errorf("send event_forward: %w", err)
	}
	return nil
}

// handleIncoming processes a message from the parent. An event_forward coming
// from the parent is NEVER re-forwarded to it.
func (u *Uplink) handleIncoming(ctx context.Context, conn *websocket.Conn, raw []byte) {
	var m message
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("[REPEATER] invalid message from parent: %v", err)
		return
	}
	switch m.Type {
	case "task_forward":
		if u.opts.OnTask == nil {
			log.Printf("[REPEATER] task_forward task_id=%s dropped: no handler", m.TaskID)
			return
		}
		reply := func(v any) error { return u.write(conn, v) }
		go u.opts.OnTask(ctx, json.RawMessage(raw), reply)
	case "event_forward":
		log.Printf("[REPEATER] event_forward from parent ignored (never re-forwarded upstream)")
	case "agent_list_ack", "heartbeat_ack", "topology_ack":
		// nothing to do
	case "heartbeat":
		_ = u.write(conn, message{Type: "heartbeat_ack", Timestamp: time.Now().UTC().Format(time.RFC3339)})
	default:
		log.Printf("[REPEATER] unknown message type from parent: %q", m.Type)
	}
}

func (u *Uplink) write(conn *websocket.Conn, v any) error {
	u.wmu.Lock()
	defer u.wmu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(u.opts.HandshakeTimeout)); err != nil {
		return err
	}
	return conn.WriteJSON(v)
}
