package ws

// Inter-relay link tokens and messages on /ws/relay (v3.0.4, #141/#146): the verification of the
// EdDSA tokens (auth.VerifyLinkToken only, never the HS256 path), the frames link_keys /
// link_revocations sent DOWN to the children (and relayed from relay to relay) and link_state sent UP.
//
// Contract: DOC/server/SERVER_SPEC.md §9.2.1. The frames are the signed messages of auth/linkjwt.go
// plus a "type" field; they are forwarded byte for byte.

import (
	"encoding/json"
	"errors"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
)

// Types of the link messages.
const (
	MsgLinkKeys        = "link_keys"
	MsgLinkRevocations = "link_revocations"
	MsgLinkState       = "link_state"
)

// ErrLinkNoTrust: this node cannot verify link tokens (a non-root relay without trust anchor, or a
// root without signing key). The link is closed with 4010 (S21).
var ErrLinkNoTrust = errors.New(auth.LinkErrNoTrust)

var (
	linkMu sync.RWMutex
	// linkTrustFn returns what this node trusts: the trust, the root relay_id ("iss"). A non-nil error
	// is a refusal (ErrLinkNoTrust when there is nothing to verify with).
	linkTrustFn func() (auth.LinkTrust, string, error)
	// linkSyncFn (root) builds the frames sent to a child when its link is established.
	linkSyncFn func() [][]byte
	// linkStateUpFn sends a link_state frame to our parent.
	linkStateUpFn func(frame []byte)
	// confirmations reported by the relays below us (and by us when we are the root).
	linkStates = map[string]LinkStateInfo{}
)

// LinkStateInfo is the last link_state reported by a relay.
type LinkStateInfo struct {
	Seq uint64
	KID string
	At  time.Time
}

// SetLinkTrustFunc sets the provider of the verification trust of /ws/relay (fail closed without it).
func SetLinkTrustFunc(fn func() (auth.LinkTrust, string, error)) {
	linkMu.Lock()
	linkTrustFn = fn
	linkMu.Unlock()
}

// SetLinkSyncFunc sets the provider of the frames sent when a child link is established.
func SetLinkSyncFunc(fn func() [][]byte) {
	linkMu.Lock()
	linkSyncFn = fn
	linkMu.Unlock()
}

// SetLinkStateUpstreamFunc sets how a link_state frame reaches our parent (the uplink).
func SetLinkStateUpstreamFunc(fn func(frame []byte)) {
	linkMu.Lock()
	linkStateUpFn = fn
	linkMu.Unlock()
}

// LinkFrameType returns the "type" of a link frame ("" if it is not one).
func LinkFrameType(frame []byte) string {
	var t struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(frame, &t) != nil {
		return ""
	}
	if t.Type == MsgLinkKeys || t.Type == MsgLinkRevocations {
		return t.Type
	}
	return ""
}

// WithLinkType adds the "type" field to a signed message of auth/linkjwt.go.
func WithLinkType(msg []byte, typ string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(msg, &m); err != nil {
		return nil, err
	}
	t, _ := json.Marshal(typ)
	m["type"] = t
	return json.Marshal(m)
}

// linkFramesForNewLink returns the frames to send right after relay_ack: the root's own state, or
// (non-root) what was received from the parent and verified (repeater.LinkTrust.Replay).
func linkFramesForNewLink() [][]byte {
	linkMu.RLock()
	fn := linkSyncFn
	linkMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// writeRaw sends one text frame on the link (nil wsConn: unit tests, nothing to send).
func (c *RelayConnection) writeRaw(frame []byte) error {
	if c.wsConn == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.wsConn.SetWriteDeadline(time.Time{}) }()
	return c.wsConn.WriteMessage(websocket.TextMessage, frame)
}

// sendLinkSync sends the link frames of a freshly established child link.
func sendLinkSync(c *RelayConnection) {
	for _, f := range linkFramesForNewLink() {
		if err := c.writeRaw(f); err != nil {
			log.Printf("link sync write error: relay_id=%q err=%v", c.RelayID, err)
			return
		}
	}
}

// BroadcastLinkFrame sends a link frame to every connected child link.
func BroadcastLinkFrame(frame []byte) {
	relayConnsMu.RLock()
	conns := make([]*RelayConnection, 0, len(relayConnections))
	for _, rc := range relayConnections {
		conns = append(conns, rc)
	}
	relayConnsMu.RUnlock()
	for _, rc := range conns {
		if err := rc.writeRaw(frame); err != nil {
			log.Printf("link frame write error: relay_id=%q err=%v", rc.RelayID, err)
		}
	}
}

// CloseLinksByJTI closes (4010) every live link authenticated with the token jti: a child link we
// accepted (pull) and a parent link accepted from our parent (push). Returns how many were closed.
func CloseLinksByJTI(jti string) int {
	if jti == "" {
		return 0
	}
	n := 0
	relayConnsMu.RLock()
	var ids []string
	for id, rc := range relayConnections {
		if rc.JTI == jti {
			ids = append(ids, id)
		}
	}
	relayConnsMu.RUnlock()
	for _, id := range ids {
		if CloseRelay(id, WSRelayCloseRevoked, "link token revoked") {
			n++
		}
	}
	if RevokeRelayParentLink(jti) {
		n++
	}
	if n > 0 {
		log.Printf("[SECURITY WARNING] link closed: token revoked (links=%d)", n)
	}
	return n
}

// ReportLinkState tells our parent which link message we applied last (informative, unsigned).
func ReportLinkState(seq uint64, kid string) {
	frame, err := json.Marshal(RelayMessage{Type: MsgLinkState, RelayID: localRelayID(), Seq: seq, CurrentKID: kid})
	if err != nil {
		return
	}
	linkMu.RLock()
	fn := linkStateUpFn
	linkMu.RUnlock()
	if fn != nil {
		fn(frame)
	}
}

// RecordLinkState stores the confirmation of a relay (root side, or while relaying upward).
func RecordLinkState(relayID string, seq uint64, kid string) {
	linkMu.Lock()
	linkStates[relayID] = LinkStateInfo{Seq: seq, KID: kid, At: time.Now()}
	linkMu.Unlock()
}

// LinkStates returns the confirmations received, by relay_id.
func LinkStates() map[string]LinkStateInfo {
	linkMu.RLock()
	defer linkMu.RUnlock()
	out := make(map[string]LinkStateInfo, len(linkStates))
	for k, v := range linkStates {
		out[k] = v
	}
	return out
}

// KnownRelayIDs lists the relays below this node known from the live topology (direct children and
// the descendants they declared), sorted.
func KnownRelayIDs() []string {
	set := map[string]struct{}{}
	for _, id := range GetConnectedRelayIDs() {
		set[id] = struct{}{}
	}
	descOwnerMu.Lock()
	for id := range descendantOwner {
		set[id] = struct{}{}
	}
	descOwnerMu.Unlock()
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// handleLinkState records the confirmation of a relay below us and relays it upward.
func handleLinkState(conn *RelayConnection, msg RelayMessage) {
	id := msg.RelayID
	if !relayIDShape.MatchString(id) {
		log.Printf("[SECURITY WARNING] link_state ignored: malformed relay_id from %q", conn.RelayID)
		return
	}
	if id != conn.RelayID {
		if _, below := conn.descendants[id]; !below {
			log.Printf("[SECURITY WARNING] link_state ignored: %q is not %q nor one of its declared descendants", id, conn.RelayID)
			return
		}
	}
	if !auth.ValidLinkKID(msg.CurrentKID) { // bounded and sanitised before being stored or relayed
		log.Printf("[SECURITY WARNING] link_state ignored: malformed current_kid from %q", conn.RelayID)
		return
	}
	RecordLinkState(id, msg.Seq, msg.CurrentKID)
	frame, err := json.Marshal(RelayMessage{Type: MsgLinkState, RelayID: id, Seq: msg.Seq, CurrentKID: msg.CurrentKID})
	if err != nil {
		return
	}
	linkMu.RLock()
	fn := linkStateUpFn
	linkMu.RUnlock()
	if fn != nil {
		fn(frame)
	}
}

// verifyLinkBearer verifies the bearer token of a /ws/relay upgrade with auth.VerifyLinkToken only.
// The role the verifier expects follows the token (relay-child: the peer is our child; relay-parent:
// the peer is our parent): it is part of the signed claims and cannot be swapped (the audience binds
// the token to ONE verifier); anything else (legacy "relay", unknown) is refused by the verifier.
func verifyLinkBearer(authHeader string) (*auth.LinkClaims, error) {
	linkMu.RLock()
	fn := linkTrustFn
	linkMu.RUnlock()
	if fn == nil {
		log.Printf("[SECURITY WARNING] relay connection refused: no link verifier configured (fail closed)")
		return nil, ErrLinkNoTrust
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		return nil, errors.New("missing_relay_credentials")
	}
	want := auth.RoleRelayChild
	if p, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{}); err == nil {
		if mc, ok := p.Claims.(jwt.MapClaims); ok {
			if r, _ := mc["role"].(string); r == auth.RoleRelayParent {
				want = auth.RoleRelayParent
			}
		}
	}
	trust, rootID, err := fn()
	if err != nil {
		return nil, err
	}
	trust.Blacklisted = func(jti string) bool {
		bad, berr := relayJTIRevoked(jti)
		return bad || berr != nil // fail closed
	}
	claims, err := auth.VerifyLinkToken(trust, token, auth.LinkWant{LocalID: localRelayID(), RootID: rootID, Role: want}, time.Now())
	if err != nil {
		var le *auth.LinkError
		if errors.As(err, &le) && le.Code == auth.LinkErrNoTrust {
			return nil, ErrLinkNoTrust
		}
		return nil, err
	}
	return claims, nil
}

func relayJTIRevoked(jti string) (bool, error) {
	treeHooksMu.RLock()
	fn := relayJTIBlacklistFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return true, errors.New("blacklist_not_configured")
	}
	return fn(jti)
}
