// Package repeater implements the child-relay side of the relay tree (#125):
// a single goroutine keeps one persistent WSS link to the unique parent,
// performs the relay_hello / relay_ack / topology_snapshot handshake, then
// publishes agent_list and event_forward and receives task_forward.
package repeater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// Protocol constants.
const (
	ProtocolVersion = "3.0"
	NodeTypeRelay   = "relay"
	ModePull        = "pull"

	// CloseCodePermanent (4010): permanent refusal (revoked/unauthorized identity, loop, identity
	// mismatch): the peer must never reconnect. CloseCodeRetry (4012): correctable refusal
	// (invalid snapshot, protocol error, conflict): reconnect with backoff. See ARCHITECTURE.md.
	CloseCodePermanent = 4010
	CloseCodeRetry     = 4012
	// CloseCodeRefused is the former name of CloseCodePermanent.
	CloseCodeRefused = CloseCodePermanent

	DefaultMinBackoff        = 5 * time.Second
	DefaultMaxBackoff        = 60 * time.Second
	DefaultAgentListInterval = 30 * time.Second
	DefaultPingInterval      = 30 * time.Second
	DefaultHandshakeTimeout  = 15 * time.Second
	readTimeoutFactor        = 3
)

// ── Wire types ───────────────────────────────────────────────────────────────

// AgentInfo is a direct agent (agent_list entry).
type AgentInfo struct {
	Hostname string `json:"hostname"`
	Status   string `json:"status,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

// TopoRelay is a descendant relay in a topology_snapshot.
type TopoRelay struct {
	RelayID    string         `json:"relay_id"`
	RelayChain []string       `json:"relay_chain"`
	GroupVars  map[string]any `json:"group_vars,omitempty"` // that relay's Ansible group vars (#139)
}

// TopoAgent is an agent of the subtree in a topology_snapshot.
type TopoAgent struct {
	Hostname   string   `json:"hostname"`
	RelayID    string   `json:"relay_id"`
	RelayChain []string `json:"relay_chain"`
}

// Snapshot is the full subtree of this relay (descendants only).
type Snapshot struct {
	Relays []TopoRelay
	Agents []TopoAgent
}

// Event is a locally generated subtree event (host.* / relay.*), before
// REPEATER_ID is added to relay_chain.
type Event struct {
	Event      string         `json:"event"`
	Hostname   string         `json:"hostname,omitempty"`
	RelayID    string         `json:"relay_id,omitempty"`
	Status     string         `json:"status,omitempty"`
	RelayChain []string       `json:"relay_chain"`
	GroupVars  map[string]any `json:"group_vars,omitempty"`
	Timestamp  string         `json:"timestamp,omitempty"`
	EnrolledAt string         `json:"enrolled_at,omitempty"` // host.new only
	// host.conflict only
	OldRelay string `json:"old_relay,omitempty"`
	NewRelay string `json:"new_relay,omitempty"`
}

// message is the generic envelope; only the fields of the given type are set.
type message struct {
	GroupVars  map[string]any `json:"group_vars,omitempty"`
	Type       string         `json:"type"`
	NodeType   string         `json:"node_type,omitempty"`
	Mode       string         `json:"mode,omitempty"`
	RelayID    string         `json:"relay_id,omitempty"`
	Ancestors  []string       `json:"ancestors,omitempty"`
	Version    string         `json:"version,omitempty"`
	Status     string         `json:"status,omitempty"`
	Error      string         `json:"error,omitempty"`
	Timestamp  string         `json:"timestamp,omitempty"`
	Agents     []AgentInfo    `json:"agents,omitempty"`
	TaskID     string         `json:"task_id,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	RelayChain []string       `json:"relay_chain,omitempty"`
}

type snapshotMessage struct {
	Type      string         `json:"type"`
	Relays    []TopoRelay    `json:"relays"`
	Agents    []TopoAgent    `json:"agents"`
	GroupVars map[string]any `json:"group_vars,omitempty"` // this relay's own Ansible group vars (#139)
}

type eventMessage struct {
	Type string `json:"type"`
	Event
}

// ── Client ───────────────────────────────────────────────────────────────────

// TaskHandler is invoked for every task_forward received from the parent.
// raw is the full JSON message; reply sends a message back upstream.
// Next-hop resolution (relay_routing lookup) is the handler's job.
type TaskHandler func(ctx context.Context, raw json.RawMessage, reply func(v any) error)

// Options configures a Client. Zero values get production defaults.
type Options struct {
	// DirectAgents returns the direct agents (1 level, not recursive).
	DirectAgents func() []AgentInfo
	// Snapshot returns the descendant subtree for topology_snapshot.
	Snapshot func() Snapshot
	// Events carries local subtree events to forward upstream (optional).
	Events <-chan Event
	// Changed signals a downstream state change → agent_list is re-sent (optional).
	Changed <-chan struct{}
	// GroupVars are this relay's Ansible group variables (RELAY_GROUP_VARS, already validated):
	// sent in relay_hello (pull) and in every topology_snapshot (pull and push).
	GroupVars map[string]any
	// OnTask handles task_forward (optional; tasks are dropped with a log if nil).
	OnTask TaskHandler

	TLSConfig         *tls.Config // nil = system roots
	MinBackoff        time.Duration
	MaxBackoff        time.Duration
	AgentListInterval time.Duration
	PingInterval      time.Duration
	HandshakeTimeout  time.Duration
}

// Client is the repeater-client. Start launches exactly one goroutine.
type Client struct {
	cfg  config.RepeaterConfig
	opts Options

	up *Uplink
	tr *linkTracker

	mu       sync.Mutex
	started  bool
	parentID string // identity learned at first successful handshake
	terminal error  // set when a permanent refusal stopped the client
	done     chan struct{}
	conn     *websocket.Conn
}

// New builds a Client from the validated repeater config.
func New(cfg config.RepeaterConfig, opts Options) *Client {
	up := NewUplink(cfg.ID, opts)
	return &Client{cfg: cfg, opts: up.opts, up: up, tr: newLinkTracker(), done: make(chan struct{})}
}

// Uplink returns the shared uplink publisher (used to also accept a parent that dials us, #140).
func (c *Client) Uplink() *Uplink { return c.up }

// normalizeOptions applies production defaults.
func normalizeOptions(opts Options) Options {
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = DefaultMinBackoff
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = DefaultMaxBackoff
	}
	if opts.AgentListInterval <= 0 {
		opts.AgentListInterval = DefaultAgentListInterval
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = DefaultPingInterval
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = DefaultHandshakeTimeout
	}
	return opts
}

// ParentID returns the parent identity learned from relay_ack ("" before the first handshake).
func (c *Client) ParentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.parentID
}

// Ancestors returns this node's ancestors (parent first, root last) as announced
// by the parent in relay_ack; nil before the first handshake.
func (c *Client) Ancestors() []string { return c.up.Ancestors() }

// Start runs the single reconnect loop in one goroutine; it returns
// immediately and the goroutine stops when ctx is cancelled. A second call is
// an error (one connection to one parent).
func (c *Client) Start(ctx context.Context) error {
	// Defense in depth: config already enforces wss://, never dial anything else.
	if u, err := url.Parse(c.cfg.UpstreamURL); err != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil {
		return errors.New("repeater client: upstream URL must be a wss:// URL without userinfo")
	}
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("repeater client already started")
	}
	c.started = true
	c.mu.Unlock()
	go c.run(ctx)
	return nil
}

func (c *Client) run(ctx context.Context) {
	err := runLoop(ctx, "parent", c.opts.MinBackoff, c.opts.MaxBackoff, c.tr, c.setTerminal, c.session)
	if err != nil {
		close(c.done)
	}
}

// setTerminal records the permanent refusal; runLoop calls it before the status flips.
func (c *Client) setTerminal(err error) {
	c.mu.Lock()
	c.terminal = err
	c.mu.Unlock()
}

// Status returns the observable state of the link to the parent (#154).
func (c *Client) Status() LinkStatus { return c.tr.get() }

// Terminal returns the permanent refusal that stopped the client (nil while it runs or retries).
func (c *Client) Terminal() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminal
}

// Done is closed when the client gave up after a permanent refusal (never closed on ctx cancel).
func (c *Client) Done() <-chan struct{} { return c.done }

// refusedError: the peer refused the link. permanent=true (close 4010) means never retry.
type refusedError struct {
	reason    string
	permanent bool
}

func (e *refusedError) Error() string { return e.reason }

// endpoint builds <upstream>/ws/relay (never logs the token).
func (c *Client) endpoint() string {
	return strings.TrimRight(c.cfg.UpstreamURL, "/") + "/ws/relay"
}

func (c *Client) write(conn *websocket.Conn, v any) error { return c.up.write(conn, v) }

// session runs one connection until it ends. established=true once the
// handshake (hello, ack, snapshot) completed.
func (c *Client) session(ctx context.Context) (established bool, err error) {
	dialer := websocket.Dialer{TLSClientConfig: tlsOrDefault(c.opts.TLSConfig), HandshakeTimeout: c.opts.HandshakeTimeout}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+c.cfg.UpstreamToken)
	conn, _, derr := dialer.DialContext(ctx, c.endpoint(), hdr)
	if derr != nil {
		// DialContext errors do not include request headers; still, only url host is shown.
		return false, fmt.Errorf("dial parent: %w", derr)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		_ = conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	// Closing on ctx cancel unblocks the read loop.
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-sessCtx.Done(); _ = conn.Close() }()

	// 1. relay_hello
	hello := message{Type: "relay_hello", NodeType: NodeTypeRelay, Mode: ModePull,
		RelayID: c.cfg.ID, Ancestors: []string{}, Version: ProtocolVersion, GroupVars: c.opts.GroupVars}
	if err := c.write(conn, hello); err != nil {
		return false, fmt.Errorf("send relay_hello: %w", err)
	}

	// 2. relay_ack
	if err := conn.SetReadDeadline(time.Now().Add(c.opts.HandshakeTimeout)); err != nil {
		return false, err
	}
	var ack message
	if err := conn.ReadJSON(&ack); err != nil {
		return false, wrapRead("read relay_ack", err)
	}
	if ack.Type != "relay_ack" || ack.Status != "ok" || ack.RelayID == "" {
		return false, &refusedError{reason: fmt.Sprintf("unexpected handshake reply type=%q status=%q", ack.Type, ack.Status)}
	}
	if err := c.checkParentIdentity(ack.RelayID); err != nil {
		c.up.closeWithCode(conn, CloseCodePermanent, "parent identity mismatch")
		return false, &refusedError{reason: err.Error(), permanent: true}
	}

	c.up.SetAncestors(ack.Ancestors)
	c.tr.set(LinkConnected, "")
	log.Printf("[REPEATER] linked to parent relay_id=%q as %s", ack.RelayID, c.cfg.ID)

	// 3+4. topology_snapshot (always sent by the child) then steady state.
	done, err := c.up.serve(ctx, conn)
	return done, err
}

func wrapRead(what string, err error) error {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case CloseCodePermanent:
			return &refusedError{reason: fmt.Sprintf("%s: peer closed with code %d (%s)", what, ce.Code, sanitizeText(ce.Text)), permanent: true}
		case CloseCodeRetry:
			return &refusedError{reason: fmt.Sprintf("%s: peer closed with code %d (%s)", what, ce.Code, sanitizeText(ce.Text))}
		}
	}
	return fmt.Errorf("%s: %s", what, sanitizeText(err.Error()))
}

// checkParentIdentity pins the parent identity on first connection, then
// requires it to be stable across reconnections.
func (c *Client) checkParentIdentity(got string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parentID == "" {
		c.parentID = got
		log.Printf("[REPEATER] first connection: parent identity relay_id=%q", got)
		return nil
	}
	if c.parentID != got {
		return fmt.Errorf("parent identity changed: expected %q, got %q", c.parentID, got)
	}
	return nil
}
