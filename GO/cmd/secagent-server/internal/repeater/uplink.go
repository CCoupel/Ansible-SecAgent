// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package repeater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
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
	cur       *websocket.Conn
	states    map[string]json.RawMessage // last link_state frame per relay_id (own and relayed), re-sent after each snapshot
	revoked   atomic.Bool                // the token of THIS link was revoked by the root (link_revocations)
	declared  map[string]struct{}        // relay ids of the last topology_snapshot SENT on the current link
}

// ErrUplinkBusy is returned by Serve when a parent link is already active (single parent).
var ErrUplinkBusy = errors.New("a parent link is already active")

// NewUplink builds an Uplink for the node id.
func NewUplink(id string, opts Options) *Uplink {
	return &Uplink{id: id, opts: normalizeOptions(opts)}
}

// Active reports whether a parent link is currently being served.
func (u *Uplink) Active() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.serving
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

func (u *Uplink) acquire() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.serving {
		return ErrUplinkBusy
	}
	u.serving = true
	return nil
}

func (u *Uplink) release() {
	u.mu.Lock()
	u.serving = false
	u.mu.Unlock()
}

// ServeAccepted serves a link opened by our PARENT (push mode, #140). The single-parent
// slot is acquired first; beforeServe (typically: send relay_ack) runs only if it was free,
// then the ancestors are recorded and the link is served. Ancestors are cleared on exit.
func (u *Uplink) ServeAccepted(ctx context.Context, conn *websocket.Conn, ancestors []string, beforeServe func() error) error {
	if err := u.acquire(); err != nil {
		return err
	}
	defer u.release()
	if beforeServe != nil {
		if err := beforeServe(); err != nil {
			return err
		}
	}
	u.SetAncestors(ancestors)
	defer u.SetAncestors(nil)
	_, err := u.run(ctx, conn)
	return err
}

func (u *Uplink) serve(ctx context.Context, conn *websocket.Conn) (established bool, err error) {
	if err := u.acquire(); err != nil {
		return false, err
	}
	defer u.release()
	return u.run(ctx, conn)
}

func (u *Uplink) run(ctx context.Context, conn *websocket.Conn) (established bool, err error) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	u.revoked.Store(false)
	u.mu.Lock()
	u.cur = conn
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		if u.cur == conn {
			u.cur = nil
		}
		u.mu.Unlock()
	}()
	if u.opts.LinkTrust != nil {
		u.opts.LinkTrust.ResetFrames() // the parent re-sends its full state on this link
	}
	go func() {
		<-sessCtx.Done()
		if ctx.Err() != nil {
			u.goingAway(conn) // orderly stop: the parent reads 1001, not a cut socket (1006)
		}
		_ = conn.Close()
	}()
	if err := u.sendSnapshot(conn); err != nil {
		return false, u.earlyClose(conn, err)
	}
	u.resendLinkStates(conn)
	lastSnap := time.Now()
	established = true

	// 4. steady state
	if err := u.sendAgentList(conn); err != nil {
		return true, u.earlyClose(conn, err)
	}

	readDeadline := u.opts.PingInterval * readTimeoutFactor
	extend := func() error { return conn.SetReadDeadline(time.Now().Add(readDeadline)) }
	if err := extend(); err != nil {
		return true, u.earlyClose(conn, err)
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

	var topoTimer *time.Timer
	var topoC <-chan time.Time
	defer func() {
		if topoTimer != nil {
			topoTimer.Stop()
		}
	}()
	ping := time.NewTicker(u.opts.PingInterval)
	defer ping.Stop()
	list := time.NewTicker(u.opts.AgentListInterval)
	defer list.Stop()

	// Replay cadence (#246): after each event the channel is left alone for one interval, so a
	// backlog goes out at EventRate per second and the loop keeps answering pings and snapshots.
	var evInterval time.Duration
	if u.opts.EventRate > 0 {
		evInterval = time.Second / time.Duration(u.opts.EventRate)
	}
	evCh := u.events()
	var evTimer *time.Timer
	var evTick <-chan time.Time
	// An event about a relay the parent has not been told about yet is HELD (not taken further) until the
	// snapshot that declares it has been sent, at most HoldEventsForSnapshotAfter.
	var held *Event
	var holdTimer *time.Timer
	var holdC <-chan time.Time
	defer func() {
		if evTimer != nil {
			evTimer.Stop()
		}
		if holdTimer != nil {
			holdTimer.Stop()
		}
	}()
	// sendEvent forwards one event and applies the replay cadence.
	sendEvent := func(ev Event) error {
		if err := u.forwardEvent(conn, ev); err != nil {
			return err
		}
		if evInterval > 0 {
			if evTimer == nil {
				evTimer = time.NewTimer(evInterval)
			} else {
				evTimer.Reset(evInterval)
			}
			evTick, evCh = evTimer.C, nil
		}
		return nil
	}
	// releaseHeld sends the held event when its relays are now declared (or when force is set).
	releaseHeld := func(force bool) error {
		if held == nil || (!force && !u.releasable(*held)) {
			return nil
		}
		ev := *held
		held = nil
		if holdTimer != nil {
			holdTimer.Stop()
			holdTimer, holdC = nil, nil
		}
		if err := sendEvent(ev); err != nil {
			return err
		}
		if evInterval <= 0 {
			evCh = u.events()
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-evTick:
			evTick = nil
			if held == nil {
				evCh = u.events()
			}
		case <-holdC:
			holdTimer, holdC = nil, nil
			if err := releaseHeld(true); err != nil {
				return true, u.preferRead(err, readErr)
			}
		case err := <-readErr:
			if u.revoked.Load() { // the root revoked our own link token: never reconnect with it
				return true, &refusedError{reason: "link token revoked by the root (operator action required)", permanent: true}
			}
			return true, wrapRead("read", err)
		case <-ping.C:
			u.wmu.Lock()
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(u.opts.HandshakeTimeout))
			u.wmu.Unlock()
			if err != nil {
				return true, u.preferRead(fmt.Errorf("ping: %w", err), readErr)
			}
		case <-list.C:
			if err := u.sendAgentList(conn); err != nil {
				return true, u.preferRead(err, readErr)
			}
		case <-u.topologyChanged():
			// coalesce a burst of changes into ONE full snapshot, never closer than TopologyMinGap
			// to the previous one (the parent rate limits replacement snapshots)
			if topoTimer == nil {
				delay := u.opts.TopologyDebounce
				if wait := u.opts.TopologyMinGap - time.Since(lastSnap); wait > delay {
					delay = wait
				}
				topoTimer = time.NewTimer(delay)
				topoC = topoTimer.C
			}
		case <-topoC:
			topoTimer, topoC = nil, nil
			if err := u.sendSnapshot(conn); err != nil {
				return true, u.preferRead(err, readErr)
			}
			u.resendLinkStates(conn)
			lastSnap = time.Now()
			if err := releaseHeld(false); err != nil {
				return true, u.preferRead(err, readErr)
			}
		case <-u.changed():
			if err := u.sendAgentList(conn); err != nil {
				return true, u.preferRead(err, readErr)
			}
		case ev, ok := <-evCh:
			if !ok {
				evCh = nil
				continue
			}
			if !u.releasable(ev) {
				// hold it and make sure a snapshot that declares the relay goes out soon (debounced like any change)
				held, evCh = &ev, nil
				holdTimer = time.NewTimer(holdEventsFor)
				holdC = holdTimer.C
				if topoTimer == nil {
					delay := u.opts.TopologyDebounce
					if wait := u.opts.TopologyMinGap - time.Since(lastSnap); wait > delay {
						delay = wait
					}
					topoTimer = time.NewTimer(delay)
					topoC = topoTimer.C
				}
				continue
			}
			if err := sendEvent(ev); err != nil {
				return true, u.preferRead(err, readErr)
			}
		}
	}
}

// preferRead is called when a WRITE failed: the parent that closes a link writes its close frame first
// (4010 permanent refusal, 4012 retry), but a write of ours racing with that close fails before the
// reader goroutine has delivered the frame, and the node would retry as if the link had merely broken
// (a revoked child coming back). The close frame, when it arrives within a short delay, wins.
func (u *Uplink) preferRead(werr error, readErr <-chan error) error {
	if u.revoked.Load() { // already known: no wait, no retry
		return &refusedError{reason: "link token revoked by the root (operator action required)", permanent: true}
	}
	select {
	case rerr := <-readErr:
		if u.revoked.Load() {
			return &refusedError{reason: "link token revoked by the root (operator action required)", permanent: true}
		}
		return wrapRead("read", rerr)
	case <-time.After(writeFailReadGrace):
		return werr
	}
}

// earlyClose is preferRead for the failures BEFORE the reader goroutine exists (the first writes of a
// session, the handshake): it reads, for at most writeFailReadGrace, the close frame the parent may have
// sent, and gives it priority over the write error (fail closed: a 4010 is never retried).
func (u *Uplink) earlyClose(conn *websocket.Conn, werr error) error {
	if u.revoked.Load() {
		return &refusedError{reason: "link token revoked by the root (operator action required)", permanent: true}
	}
	_ = conn.SetReadDeadline(time.Now().Add(writeFailReadGrace))
	for i := 0; i < 16; i++ { // data frames before the close frame are skipped
		if _, _, err := conn.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return wrapRead("read", err)
			}
			return werr
		}
	}
	return werr
}

// writeFailReadGrace is how long a failed write waits for the close frame of the parent.
const writeFailReadGrace = 500 * time.Millisecond

func (u *Uplink) topologyChanged() <-chan struct{} { return u.opts.TopologyChanged }

// sendSnapshot sends the full topology_snapshot (the truth about the subtree below this node).
func (u *Uplink) sendSnapshot(conn *websocket.Conn) error {
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
	if err := u.write(conn, snapshotMessage{Type: "topology_snapshot", Relays: snap.Relays, Agents: snap.Agents, GroupVars: u.opts.GroupVars}); err != nil {
		return fmt.Errorf("send topology_snapshot: %w", err)
	}
	declared := make(map[string]struct{}, len(snap.Relays))
	for _, r := range snap.Relays {
		declared[r.RelayID] = struct{}{}
	}
	u.mu.Lock()
	u.declared = declared
	u.mu.Unlock()
	return nil
}

// HoldEventsForSnapshotAfter bounds how long an event about a relay the parent has not been told about yet
// waits for the snapshot that declares it (after that it is sent anyway: the parent will log and refuse it).
const HoldEventsForSnapshotAfter = 5 * time.Second

// holdEventsFor is HoldEventsForSnapshotAfter, a variable so that a test can shorten it.
var holdEventsFor = HoldEventsForSnapshotAfter

// releasable reports whether the parent already knows every relay of the event's chain: it validates each
// element of relay_chain (but the sender, appended last) against the descendants of the last snapshot it got.
// An event for a relay declared only by a snapshot still to come (a grandchild that has just linked) would be
// refused as "unknown descendant" and its lifecycle event lost.
func (u *Uplink) releasable(ev Event) bool {
	if len(ev.RelayChain) == 0 || u.opts.Snapshot == nil { // no snapshot source: nothing to wait for (tests)
		return true
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, id := range ev.RelayChain {
		if id == u.id {
			continue
		}
		if _, ok := u.declared[id]; !ok {
			return false
		}
	}
	return true
}

// changed/events return nil channels (block forever) when unset.
func (u *Uplink) changed() <-chan struct{} { return u.opts.Changed }
func (u *Uplink) events() <-chan Event {
	if u.opts.Events == nil {
		return nil
	}
	return u.opts.Events
}

// goingAway sends the close frame 1001 of an orderly stop (best effort, 1 s at most): the parent then
// reports relay.down reason=peer_closed:1001 and can tell a stop from a cut (peer_closed:1006).
func (u *Uplink) goingAway(conn *websocket.Conn) {
	u.closeWithCode(conn, websocket.CloseGoingAway, "going away")
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
		u.eventLost(1)
		return nil
	}
	ev.RelayChain = chain
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	} else if at, perr := time.Parse(time.RFC3339, ev.Timestamp); perr == nil && time.Since(at) > LateEventAfter {
		ev.Late = true
	}
	if err := u.write(conn, eventMessage{Type: "event_forward", Event: ev}); err != nil {
		u.eventLost(1) // the event left the queue but not the node
		return fmt.Errorf("send event_forward: %w", err)
	}
	return nil
}

// LateEventAfter is the age from which a forwarded event is marked Late (it waited in the queue).
const LateEventAfter = 10 * time.Second

// eventLost reports events removed from the queue and never delivered.
func (u *Uplink) eventLost(n int64) {
	if u.opts.OnEventLost != nil {
		u.opts.OnEventLost(n)
	}
}

// handleIncoming processes a message from the parent. An event_forward coming
// from the parent is NEVER re-forwarded to it.
func (u *Uplink) handleIncoming(ctx context.Context, conn *websocket.Conn, raw []byte) {
	var m message
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("[REPEATER] invalid message from parent: %s", sanitizeText(err.Error()))
		return
	}
	switch m.Type {
	case "task_forward", "task_dispatch", "file_upload", "file_fetch":
		// task_dispatch / file_* are what a parent's ProxyRouter sends; task_forward is the spec name.
		if u.opts.OnTask == nil {
			log.Printf("[REPEATER] task_forward task_id=%q dropped: no handler", m.TaskID)
			return
		}
		reply := func(v any) error { return u.write(conn, v) }
		go u.opts.OnTask(ctx, json.RawMessage(raw), reply)
	case "link_keys", "link_revocations":
		u.handleLinkFrame(conn, raw)
	case "link_state":
		// informative ack, only meaningful child -> parent: never used as a decision
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

// handleLinkFrame applies a link_keys / link_revocations frame from the parent (the format and the
// signatures are checked by auth, through LinkTrust). The link stays open on an invalid frame.
func (u *Uplink) handleLinkFrame(conn *websocket.Conn, raw []byte) {
	if len(raw) > maxLinkFrameLen {
		log.Printf("[SECURITY WARNING] link frame from parent refused: %d bytes exceed the limit", len(raw))
		return
	}
	lt := u.opts.LinkTrust
	if lt == nil {
		log.Printf("[SECURITY WARNING] link frame from parent ignored: no link trust configured")
		return
	}
	res, err := lt.HandleFrame(raw)
	if err != nil || (!res.Applied && !res.Confirm) {
		return
	}
	for _, jti := range res.Revoked {
		if u.opts.OwnLinkJTI != "" && jti == u.opts.OwnLinkJTI {
			log.Printf("[SECURITY WARNING] the token of the link to the parent was revoked by the root: closing the link")
			u.revoked.Store(true)
			u.closeWithCode(conn, CloseCodePermanent, "link token revoked")
			_ = conn.Close()
			return
		}
	}
	// informative acknowledgement towards the parent (unsigned, never a decision)
	frame, merr := json.Marshal(struct {
		Type       string `json:"type"`
		RelayID    string `json:"relay_id"`
		Seq        uint64 `json:"seq"`
		CurrentKID string `json:"current_kid"`
	}{"link_state", u.id, res.Seq, res.KID})
	if merr != nil {
		return
	}
	u.rememberLinkState(u.id, frame)
	_ = u.write(conn, json.RawMessage(frame))
}

const (
	maxRememberedLinkStates = 1024
	maxLinkStateFrameLen    = 512 // a link_state is ~120 bytes: total memory kept <= 1024 x 512 B
)

// validLinkStateFrame accepts only a well formed, small link_state (relay_id and kid shapes checked).
func validLinkStateFrame(frame []byte) (relayID string, ok bool) {
	if len(frame) > maxLinkStateFrameLen {
		return "", false
	}
	var m struct {
		Type       string `json:"type"`
		RelayID    string `json:"relay_id"`
		CurrentKID string `json:"current_kid"`
	}
	if json.Unmarshal(frame, &m) != nil || m.Type != "link_state" || !relayIDPattern.MatchString(m.RelayID) || !auth.ValidLinkKID(m.CurrentKID) {
		return "", false
	}
	return m.RelayID, true
}

// rememberLinkState keeps the last link_state of a relay so that it can be re-sent once the parent
// knows the topology (the parent ignores a link_state of a relay it has not seen declared yet).
func (u *Uplink) rememberLinkState(relayID string, frame []byte) {
	if id, ok := validLinkStateFrame(frame); !ok || id != relayID {
		return // never kept: bounded size, strict shape, one entry per relay_id
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.states == nil {
		u.states = map[string]json.RawMessage{}
	}
	if _, known := u.states[relayID]; !known && len(u.states) >= maxRememberedLinkStates {
		return
	}
	u.states[relayID] = append(json.RawMessage(nil), frame...)
}

// resendLinkStates re-sends the remembered link_state frames: called right after a topology_snapshot,
// which is what makes the sender (and the relays below it) known to the parent.
func (u *Uplink) resendLinkStates(conn *websocket.Conn) {
	// Our own state, as WE authenticated it (never read from a frame): the kid we trust as current and
	// the last seq we verified. A relay deployed after a rotation never receives a verifiable link_keys;
	// this is how it tells the root it trusts the current key.
	if lt := u.opts.LinkTrust; lt != nil && lt.Anchored() {
		seq, kid := lt.State()
		if frame, err := json.Marshal(struct {
			Type       string `json:"type"`
			RelayID    string `json:"relay_id"`
			Seq        uint64 `json:"seq"`
			CurrentKID string `json:"current_kid"`
		}{"link_state", u.id, seq, kid}); err == nil {
			u.rememberLinkState(u.id, frame)
		}
	}
	u.mu.Lock()
	frames := make([]json.RawMessage, 0, len(u.states))
	for _, f := range u.states {
		frames = append(frames, f)
	}
	u.mu.Unlock()
	for _, f := range frames {
		if err := u.write(conn, f); err != nil {
			return
		}
	}
}

// SendUpstream writes a message on the current parent link (used to retransmit a child's
// link_state towards the root). It fails when no parent link is active.
func (u *Uplink) SendUpstream(v any) error {
	u.mu.Lock()
	conn := u.cur
	u.mu.Unlock()
	if raw, ok := v.(json.RawMessage); ok {
		if id, ok := validLinkStateFrame(raw); ok {
			u.rememberLinkState(id, raw)
		}
	}
	if conn == nil {
		return errors.New("no parent link")
	}
	return u.write(conn, v)
}
