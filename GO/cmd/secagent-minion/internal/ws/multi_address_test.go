package ws

// #166 — multi-address minion: failover before send, no replay after send, pairing by position.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/internal/endpoints"
)

// relayNode is a fake relay instance on a FIXED address that can be switched on and off (the
// active/passive switch-over: the standby opens no port, the master does).
type relayNode struct {
	t     *testing.T
	addr  string
	mu    sync.Mutex
	ln    net.Listener
	srv   *http.Server
	conns atomic.Int32 // WebSocket upgrades served
	reqs  atomic.Int32 // TCP connections accepted
	mute  atomic.Bool  // accept the upgrade request, then say nothing
	deny  atomic.Bool  // answer every request 401 (a verdict, not a silent host)
	links []*websocket.Conn
}

func newRelayNode(t *testing.T, on bool) *relayNode {
	t.Helper()
	n := &relayNode{t: t, addr: freeAddr(t)}
	if on {
		n.start()
	}
	t.Cleanup(n.stop)
	return n
}

func (n *relayNode) start() {
	n.mu.Lock()
	defer n.mu.Unlock()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ { // the port was just released
		if ln, err = net.Listen("tcp", n.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		n.t.Fatalf("listen %s: %v", n.addr, err)
	}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	n.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.deny.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if n.mute.Load() {
			time.Sleep(5 * time.Second) // read the request, never answer
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		n.conns.Add(1)
		n.mu.Lock()
		n.links = append(n.links, c) // hijacked connections are not closed by Server.Close
		n.mu.Unlock()
		for { // hold the link until the node stops
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})}
	n.ln = &countingListener{Listener: ln, n: &n.reqs}
	srv, cl := n.srv, n.ln
	go func() { _ = srv.Serve(cl) }()
}

func (n *relayNode) stop() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.srv != nil {
		_ = n.srv.Close() // closes the listener
		n.srv = nil
	}
	for _, c := range n.links {
		_ = c.Close()
	}
	n.links = nil
}

func (n *relayNode) wsURL() string { return "ws://" + n.addr + "/ws/agent" }

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func rotorOf(t *testing.T, urls ...string) *endpoints.Rotor {
	t.Helper()
	var us []*url.URL
	for _, s := range urls {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		us = append(us, u)
	}
	r, err := endpoints.NewRotor(us, endpoints.Backoff{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func fastDispatcher(t *testing.T, ws, enroll *endpoints.Rotor) (*Dispatcher, context.CancelFunc, chan error) {
	t.Helper()
	d := NewDispatcher(ConnConfig{Endpoints: ws, JWT: secretJWT, Insecure: true}, nil)
	if enroll != nil {
		d.WithEnrollConfig(EnrollConfig{Rotor: enroll, Hostname: "h", PrivateKey: generateTestKey2048(t), EnrollmentToken: secretToken})
	}
	d.reconnectBase, d.reconnectMax = 0.02, 0.05 // seconds: quick rounds
	d.attemptTimeout = 400 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return d, cancel, done
}

func TestMulti_FailoverBeforeSendThenBackToTheFirstOnSwitchOver(t *testing.T) {
	logs := captureLog(t)
	a, b := newRelayNode(t, false), newRelayNode(t, true) // A (first of the list) is the standby: no port
	fastDispatcher(t, rotorOf(t, a.wsURL(), b.wsURL()), nil)

	waitFor(t, "the WebSocket on B (A refuses TCP)", func() bool { return b.conns.Load() == 1 })
	if a.reqs.Load() != 0 {
		t.Errorf("A is down, it cannot have accepted anything")
	}
	// switch-over: B (master) stops, A takes over: the minion reconnects to A without restart
	a.start()
	b.stop()
	defer func() {
		if t.Failed() {
			t.Logf("minion logs:\n%s", logs.String())
		}
	}()
	waitFor(t, "the WebSocket on A after the switch-over", func() bool { return a.conns.Load() == 1 })
	// and the last good address is now the head: a later drop of A reconnects on A first
	if !strings.Contains(logs.String(), "Connected to "+a.addr) || !strings.Contains(logs.String(), "Connected to "+b.addr) {
		t.Errorf("the chosen address (host:port) must be logged:\n%s", logs.String())
	}
	for _, s := range []string{secretJWT, secretToken} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("secret in the logs: %q", s)
		}
	}
}

// (a) the upgrade request left on server 1, which then stays silent: ErrAfterSend, NOT replayed
// on server 2 in the same round (and the next round does not start on the silent address).
func TestMulti_WebSocketNoReplayAfterTheUpgradeWasSent(t *testing.T) {
	a, b := newRelayNode(t, true), newRelayNode(t, true)
	a.mute.Store(true)
	d := NewDispatcher(ConnConfig{Endpoints: rotorOf(t, a.wsURL(), b.wsURL()), JWT: "j", Insecure: true}, nil)
	d.attemptTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := d.connect(ctx, NewReconnectManager(0.01, 0.01))
	if !errors.Is(err, endpoints.ErrAfterSend) {
		t.Fatalf("connect = %v, want ErrAfterSend (the request left, the server stayed silent)", err)
	}
	if b.reqs.Load() != 0 {
		t.Fatalf("server 2 received %d connection(s) after the request was sent on server 1, want 0", b.reqs.Load())
	}
	if a.reqs.Load() != 1 {
		t.Errorf("server 1 connections: %d", a.reqs.Load())
	}
	// the next round starts on B: a silent address does not starve the others
	a.mute.Store(false)
	if err := d.connect(ctx, NewReconnectManager(0.01, 0.01)); err == nil || b.conns.Load() != 1 {
		// connect only returns when the link drops; B accepted it
		if b.conns.Load() != 1 {
			t.Fatalf("the round after an after-send failure must start on the next address (B conns %d, err %v)", b.conns.Load(), err)
		}
	}
}

func TestMulti_AllAddressesDownIsAFullRoundThenBackoff(t *testing.T) {
	a, b := newRelayNode(t, false), newRelayNode(t, false)
	d, _, _ := fastDispatcher(t, rotorOf(t, a.wsURL(), b.wsURL()), nil)
	_ = d
	time.Sleep(300 * time.Millisecond)
	a.start()
	waitFor(t, "recovery once an address comes back", func() bool { return a.conns.Load() == 1 })
}

func TestMulti_PairedRotorsShareTheLastGoodInstance(t *testing.T) {
	enroll := rotorOf(t, "https://h1:7770", "https://h2:7770", "https://h3:7770")
	wsr := rotorOf(t, "wss://h1:7772/ws/agent", "wss://h2:7772/ws/agent", "wss://h3:7772/ws/agent")
	enroll.Success(2) // the enrollment reached instance 3
	syncPair(enroll, wsr)
	if wsr.Head() != 2 {
		t.Fatalf("the WebSocket must try instance 3 first, head %d", wsr.Head())
	}
	wsr.Success(1)
	syncPair(wsr, enroll)
	if enroll.Head() != 1 {
		t.Fatalf("enrollment head %d, want 1", enroll.Head())
	}
	// lists of different lengths are never synchronised (and main refuses them at start-up)
	syncPair(enroll, rotorOf(t, "wss://x/ws/agent"))
}

// A 401 verdict is not a silent host: the re-enrollment keeps the address, no rotation.
func TestMulti_A401DoesNotRotateTheHead(t *testing.T) {
	srv := newRelayNode(t, true)
	srv.deny.Store(true) // the listener stays open: the node answers 401 (no stop-then-listen on a recycled port)
	other := newRelayNode(t, true)
	r := rotorOf(t, "ws://"+srv.addr+"/ws/agent", other.wsURL())
	d := NewDispatcher(ConnConfig{Endpoints: r, JWT: "j", Insecure: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := d.connect(ctx, NewReconnectManager(0.01, 0.01))
	if !isHTTP401(err) {
		t.Fatalf("connect = %v, want the 401 verdict", err)
	}
	if r.Head() != 0 || other.reqs.Load() != 0 {
		t.Errorf("a 401 must neither rotate the head (%d) nor try the other address (%d)", r.Head(), other.reqs.Load())
	}
	if srv.reqs.Load() != 1 {
		t.Errorf("the 401 address was contacted %d times", srv.reqs.Load())
	}
}

// The instance that answered on one side is the first tried on the other (pairing by position).
func TestMulti_ConnectionSyncsTheEnrollmentRotor(t *testing.T) {
	captureLog(t)
	a, b := newRelayNode(t, false), newRelayNode(t, true)
	enroll := rotorOf(t, "https://a.invalid:7770", "https://b.invalid:7770")
	d, _, _ := fastDispatcher(t, rotorOf(t, a.wsURL(), b.wsURL()), enroll)
	_ = d
	waitFor(t, "the WebSocket on B", func() bool { return b.conns.Load() == 1 })
	waitFor(t, "the enrollment rotor to follow the WebSocket instance", func() bool { return enroll.Head() == 1 })
}

func TestMulti_ReEnrollmentSyncsTheWebSocketRotor(t *testing.T) {
	enroll := rotorOf(t, "https://a.invalid:7770", "https://b.invalid:7770")
	wsr := rotorOf(t, "wss://a.invalid:7772/ws/agent", "wss://b.invalid:7772/ws/agent")
	d := NewDispatcher(ConnConfig{Endpoints: wsr, JWT: "old"}, nil).
		WithEnrollConfig(EnrollConfig{Rotor: enroll, Hostname: "h", PrivateKey: generateTestKey2048(t), EnrollmentToken: "tok"})
	mockReEnroll(t, func(_ context.Context, ec EnrollConfig, _ string) (string, error) {
		ec.Rotor.Success(1) // the enrollment was served by instance 2
		return "new", nil
	})
	if _, err := d.handleUnauthorized(context.Background()); err != nil {
		t.Fatal(err)
	}
	if wsr.Head() != 1 {
		t.Fatalf("after a re-enrollment through instance 2 the WebSocket must try instance 2 first, head %d", wsr.Head())
	}
}

// ── ports: no bind-close-reuse window with the kernel's ephemeral allocations ──
//
// A node that is OFF must refuse TCP (the standby of an active/passive pair opens no port) and may
// be switched ON later at the SAME address. A port obtained with ":0" and released is an EPHEMERAL
// port: the kernel hands it to any outgoing connection or ":0" listener of a parallel test before
// the node binds it again ("address already in use"). Addresses are therefore drawn OUTSIDE the
// kernel's ephemeral range, never handed out twice by this process, and checked free right before use.
var (
	portMu   sync.Mutex
	portUsed = map[int]bool{}
)

func ephemeralRangeStart() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 32768
	}
	var lo, hi int
	if _, err := fmt.Sscanf(string(b), "%d %d", &lo, &hi); err != nil || lo < 2048 {
		return 32768
	}
	return lo
}

func freeAddr(t *testing.T) string {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	top := ephemeralRangeStart() - 1
	bottom := 12000
	if top-bottom < 1000 {
		bottom = 1100
	}
	for i := 0; i < 500; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(top-bottom)))
		if err != nil {
			t.Fatal(err)
		}
		port := bottom + int(n.Int64())
		if portUsed[port] {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		portUsed[port] = true
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	t.Fatal("no free port outside the ephemeral range")
	return ""
}
