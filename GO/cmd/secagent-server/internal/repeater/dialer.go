package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/internal/endpoints"
)

// ModePush is relay_hello.mode when the PARENT opened the link (#140).
const ModePush = "push"

var relayIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// DialTarget is a child relay registered with mode=push.
type DialTarget struct {
	RelayID string   // expected identity of the child (relay_nodes.relay_id)
	URLs    []string // wss://host:port of the child's instances (the /ws/relay path is appended); tried in order
	URL     string   // single address (kept for callers of the pre-v3.0.3 shape): used when URLs is empty
	Token   string   // relay-parent JWT signed by the child; secret, never logged
}

// DialerOptions configures a Dialer / DialerManager.
type DialerOptions struct {
	// Identity returns this node's relay id and its ancestors (parent first), sent in relay_hello.
	Identity func() (id string, ancestors []string)
	// WouldLoop reports whether childID ∈ {this node} ∪ ancestors(this node): such a child is never dialed.
	WouldLoop func(childID string) bool
	// Serve takes over the link once the handshake succeeded and blocks until it ends
	// (bound to ws.ServeDialedRelay). It must close conn.
	Serve func(ctx context.Context, conn *websocket.Conn, peerID string) error

	TLSConfig        *tls.Config // nil = default (see tlsOrDefault)
	MinBackoff       time.Duration
	MaxBackoff       time.Duration
	HandshakeTimeout time.Duration
}

// Dialer keeps ONE outgoing WSS link to ONE child (one goroutine), reconnecting with backoff.
type Dialer struct {
	target DialTarget
	opts   DialerOptions

	mu       sync.Mutex
	started  bool
	terminal error // permanent refusal that stopped this dialer
	tr       *linkTracker
	rotor    *endpoints.Rotor
}

// setTerminal records the permanent refusal; runLoop calls it before the status flips.
func (d *Dialer) setTerminal(err error) {
	d.mu.Lock()
	d.terminal = err
	d.mu.Unlock()
}

// Status returns the observable state of the link to this child (#154).
func (d *Dialer) Status() LinkStatus { return d.tr.get() }

// Terminal returns the permanent refusal that stopped the dialer (nil while it runs or retries).
func (d *Dialer) Terminal() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.terminal
}

// addresses returns the target's address list (URLs, or the single URL).
func (t DialTarget) addresses() []string {
	if len(t.URLs) > 0 {
		return t.URLs
	}
	if t.URL != "" {
		return []string{t.URL}
	}
	return nil
}

// ValidateDialTarget checks a push target: valid id, a list of wss:// addresses, each with a host,
// no userinfo and NOT an internal destination (loopback, link-local, cloud metadata, non routable;
// RFC 1918 stays allowed), token set. One forbidden address refuses the whole list.
// Errors never contain the token or a URL.
func ValidateDialTarget(t DialTarget) error {
	if !relayIDPattern.MatchString(t.RelayID) {
		return fmt.Errorf("invalid relay_id %q", t.RelayID)
	}
	if _, err := ParseTargetURLs(t.addresses()); err != nil {
		return err
	}
	if strings.TrimSpace(t.Token) == "" {
		return errors.New("token is required")
	}
	return nil
}

// NewDialer validates the target and builds a Dialer.
func NewDialer(target DialTarget, opts DialerOptions) (*Dialer, error) {
	if err := ValidateDialTarget(target); err != nil {
		return nil, fmt.Errorf("dial target %q: %w", target.RelayID, err)
	}
	if opts.Identity == nil || opts.Serve == nil {
		return nil, errors.New("dialer: Identity and Serve are required")
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = DefaultMinBackoff
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = DefaultMaxBackoff
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = DefaultHandshakeTimeout
	}
	return &Dialer{target: target, opts: opts, tr: newLinkTracker()}, nil
}

// String never exposes the token.
func (d *Dialer) String() string { return "Dialer{relay_id=" + d.target.RelayID + "}" }

// Start launches the reconnect loop in one goroutine and returns immediately.
func (d *Dialer) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return errors.New("dialer already started")
	}
	d.started = true
	urls, err := ParseTargetURLs(d.target.addresses())
	if err != nil {
		d.started = false
		return err
	}
	rotor, err := endpoints.NewRotor(urls, endpoints.Backoff{Min: d.opts.MinBackoff, Max: d.opts.MaxBackoff})
	if err != nil {
		d.started = false
		return err
	}
	d.rotor = rotor
	go func() {
		// terminal is assigned (by the callback) BEFORE the status becomes refused_permanent
		_ = runLoop(ctx, "child "+d.target.RelayID, d.opts.MinBackoff, d.opts.MaxBackoff, d.tr, d.setTerminal, d.session)
	}()
	return nil
}

func (d *Dialer) session(ctx context.Context) (established bool, err error) {
	// Structural loop refusal BEFORE dialing: C ∈ {P} ∪ ancestors(P).
	if d.opts.WouldLoop != nil && d.opts.WouldLoop(d.target.RelayID) {
		log.Printf("[SECURITY WARNING] dial-out refused: child %s is this node or one of its ancestors (loop)", d.target.RelayID)
		return false, &refusedError{reason: "loop: child is this node or one of its ancestors", permanent: true}
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+d.target.Token)
	conn, used, derr := endpoints.DialFirst(ctx, d.rotor, d.opts.HandshakeTimeout,
		func(actx context.Context, u *url.URL) (*websocket.Conn, error) {
			return dialWS(actx, u, "/ws/relay", d.opts.TLSConfig, hdr, d.opts.HandshakeTimeout)
		})
	if derr != nil {
		if i, after := endpoints.AfterSendIndex(derr); after {
			d.rotor.Rotate(i) // it accepted the connection and then froze: start elsewhere next time
		}
		return false, fmt.Errorf("dial child: %w", derr)
	}
	log.Printf("[REPEATER] child %s: connected through %s", d.target.RelayID, used.Host)
	closeConn := func() { _ = conn.Close() }

	// Unblock the handshake reads if the dialer is stopped meanwhile.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	self, ancestors := d.opts.Identity()
	if ancestors == nil {
		ancestors = []string{}
	}
	if err := conn.SetWriteDeadline(time.Now().Add(d.opts.HandshakeTimeout)); err != nil {
		closeConn()
		return false, err
	}
	hello := message{Type: "relay_hello", NodeType: NodeTypeRelay, Mode: ModePush,
		RelayID: self, Ancestors: ancestors, Version: ProtocolVersion}
	if err := conn.WriteJSON(hello); err != nil {
		closeConn()
		return false, fmt.Errorf("send relay_hello: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(d.opts.HandshakeTimeout)); err != nil {
		closeConn()
		return false, err
	}
	var ack message
	if err := conn.ReadJSON(&ack); err != nil {
		closeConn()
		return false, wrapRead("read relay_ack", err)
	}
	if ack.Type != "relay_ack" || ack.Status != "ok" {
		closeConn()
		return false, &refusedError{reason: fmt.Sprintf("unexpected handshake reply type=%q status=%q", ack.Type, ack.Status)}
	}
	// The child must be who relay_nodes says it is.
	if ack.RelayID != d.target.RelayID {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(CloseCodePermanent, "child identity mismatch"), time.Now().Add(time.Second))
		closeConn()
		log.Printf("[SECURITY WARNING] dial-out refused: expected child %q, relay_ack announced %q", d.target.RelayID, ack.RelayID)
		return false, &refusedError{reason: fmt.Sprintf("child identity mismatch: expected %q, got %q", d.target.RelayID, ack.RelayID), permanent: true}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		closeConn()
		return false, err
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		closeConn()
		return false, err
	}
	d.tr.set(LinkConnected, "")
	log.Printf("[REPEATER] linked to child relay_id=%s (push)", d.target.RelayID)
	if err := d.opts.Serve(ctx, conn, d.target.RelayID); err != nil {
		// A close frame received on the served link carries the peer's decision: 4010 is a
		// permanent refusal (revoked token, identity...), 4012 a correctable one (#148, #153).
		return true, wrapRead("served link", err)
	}
	return true, nil
}

// DialerManager owns one Dialer per push relay and supports hot start/stop.
type DialerManager struct {
	ctx  context.Context
	opts DialerOptions

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	dialers map[string]*Dialer
}

// NewDialerManager creates a manager whose dialers stop when ctx is cancelled.
func NewDialerManager(ctx context.Context, opts DialerOptions) *DialerManager {
	return &DialerManager{ctx: ctx, opts: opts, cancels: make(map[string]context.CancelFunc), dialers: make(map[string]*Dialer)}
}

// Start (re)starts the dialer for target; an existing dialer for the same relay is replaced.
func (m *DialerManager) Start(target DialTarget) error {
	d, err := NewDialer(target, m.opts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.cancels[target.RelayID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	if err := d.Start(ctx); err != nil {
		cancel()
		return err
	}
	m.cancels[target.RelayID] = cancel
	m.dialers[target.RelayID] = d
	return nil
}

// Stop stops the dialer of relayID (no-op if none).
func (m *DialerManager) Stop(relayID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.cancels[relayID]; ok {
		cancel()
		delete(m.cancels, relayID)
		delete(m.dialers, relayID)
	}
}

// Statuses returns the link status of every push child (one per relay_id), sorted by relay_id.
func (m *DialerManager) Statuses() []NamedStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]NamedStatus, 0, len(m.dialers))
	for id, d := range m.dialers {
		out = append(out, NamedStatus{RelayID: id, LinkStatus: d.Status()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayID < out[j].RelayID })
	return out
}

// Running returns the number of active dialers.
func (m *DialerManager) Running() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cancels)
}
