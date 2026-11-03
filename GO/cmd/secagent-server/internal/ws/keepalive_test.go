package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// keepaliveServer runs the relevant part of AgentHandler: register the connection, arm the keepalive,
// read until the connection ends. closed receives the host when its read loop ended.
func keepaliveServer(t *testing.T, host string) (url string, closed chan struct{}) {
	t.Helper()
	closed = make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ac := &AgentConnection{Hostname: host, Conn: conn}
		RegisterConnection(host, ac)
		stop := startKeepalive(ac)
		defer func() { stop(); unregisterIfCurrent(host, ac); _ = conn.Close(); close(closed) }()
		for {
			var m Message
			if err := conn.ReadJSON(&m); err != nil {
				return
			}
			ac.extendReadDeadline()
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), closed
}

func dialKA(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func withKeepalive(t *testing.T, interval time.Duration) {
	t.Helper()
	SetAgentKeepalive(interval)
	t.Cleanup(func() { SetAgentKeepalive(0) })
}

// A client that reads (so answers pings) stays connected well past the 2 x interval read deadline.
func TestKeepalive_AResponsiveAgentStaysConnected(t *testing.T) {
	withKeepalive(t, 100*time.Millisecond)
	url, closed := keepaliveServer(t, "ka-live")
	c := dialKA(t, url)
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	select {
	case <-closed:
		t.Fatal("a responsive connection was closed")
	case <-time.After(800 * time.Millisecond):
	}
}

// A client that never reads sends no pong: the relay closes the connection after 2 x interval and unregisters it.
func TestKeepalive_ASilentAgentIsClosedAndUnregistered(t *testing.T) {
	withKeepalive(t, 100*time.Millisecond)
	url, closed := keepaliveServer(t, "ka-silent")
	_ = dialKA(t, url)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("a silent connection was not closed")
	}
	if _, err := GetConnection("ka-silent"); err == nil {
		t.Error("the closed connection must be unregistered")
	}
}

func TestProbeConnection(t *testing.T) {
	withKeepalive(t, 200*time.Millisecond)
	if ProbeConnection("ka-nobody", 100*time.Millisecond) {
		t.Fatal("no connection: not alive")
	}
	url, closed := keepaliveServer(t, "ka-probe-live")
	c := dialKA(t, url)
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	time.Sleep(250 * time.Millisecond)
	if !ProbeConnection("ka-probe-live", time.Second) {
		t.Fatal("a reading client answers the ping")
	}
	select {
	case <-closed:
		t.Fatal("a live connection must not be closed by the probe")
	default:
	}

	url2, closed2 := keepaliveServer(t, "ka-probe-dead")
	_ = dialKA(t, url2)                // never reads: no pong
	time.Sleep(210 * time.Millisecond) // one ping interval without a sign of life
	// single-flight: concurrent probes share one answer and take about one delay, not N
	var wg sync.WaitGroup
	res := make([]bool, 4)
	start := time.Now()
	for i := range res {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i] = ProbeConnection("ka-probe-dead", 150*time.Millisecond) }(i)
	}
	wg.Wait()
	for i, r := range res {
		if r {
			t.Errorf("probe %d: a silent connection must be dead", i)
		}
	}
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Errorf("4 concurrent probes took %s: not single-flight", d)
	}
	select {
	case <-closed2:
	case <-time.After(2 * time.Second):
		t.Fatal("a dead connection must be closed by the probe")
	}
}

// N2: a recent sign of life keeps the connection even when it does not answer the probe; only a sign of
// life older than one ping interval AND no answer makes it dead.
func TestProbeConnection_ARecentSignOfLifeKeepsTheConnection(t *testing.T) {
	withKeepalive(t, time.Hour) // no automatic ping during the test
	url, closed := keepaliveServer(t, "ka-n2")
	_ = dialKA(t, url) // never reads: would never answer
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if !ProbeConnection("ka-n2", time.Second) {
		t.Fatal("a connection with a recent sign of life must be kept")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("no probe must be sent when the sign of life is recent")
	}
	select {
	case <-closed:
		t.Fatal("the connection must not be closed")
	default:
	}
	ac, _ := GetConnection("ka-n2")
	ac.lastAlive.Store(time.Now().Add(-2 * time.Hour).UnixNano()) // now a full interval without any sign
	if ProbeConnection("ka-n2", 150*time.Millisecond) {
		t.Fatal("old sign of life and no answer: dead")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the dead connection must be closed")
	}
}

// B11: past MaxConcurrentProbes probes in flight, the host is kept without probing.
func TestProbeConnection_GlobalCapKeepsTheConnection(t *testing.T) {
	withKeepalive(t, time.Hour)
	url, closed := keepaliveServer(t, "ka-cap")
	_ = dialKA(t, url)
	time.Sleep(50 * time.Millisecond)
	ac, _ := GetConnection("ka-cap")
	ac.lastAlive.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	for i := 0; i < MaxConcurrentProbes; i++ {
		probeSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < MaxConcurrentProbes; i++ {
			<-probeSlots
		}
	}()
	if !ProbeConnection("ka-cap", 100*time.Millisecond) {
		t.Fatal("past the cap the connection is kept (401 without probing)")
	}
	select {
	case <-closed:
		t.Fatal("the connection must not be closed when the cap is reached")
	case <-time.After(150 * time.Millisecond):
	}
}

// B55: a revocation that lands between the handshake check and the registration is caught by the check
// replayed after RegisterConnection: the link is closed with 4001 and unregistered.
func TestAgentHandler_ReplaysTheRevocationCheckAfterRegistering(t *testing.T) {
	SetAgentRevokedCheckFunc(func(host, jti string) error { return errTest("token_revoked") })
	t.Cleanup(func() { SetAgentRevokedCheckFunc(nil) })
	closeCodeSeen := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ac := &AgentConnection{Hostname: "b55", Conn: conn}
		RegisterConnection("b55", ac)
		if rerr := replayRevokedCheck("b55", "jti"); rerr != nil {
			ac.mu.Lock()
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(WSCloseRevoked, "token_revoked"), time.Now().Add(time.Second))
			ac.mu.Unlock()
			unregisterIfCurrent("b55", ac)
			_ = conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		_, _, rerr := c.ReadMessage()
		if ce, ok := rerr.(*websocket.CloseError); ok {
			closeCodeSeen <- ce.Code
		} else {
			closeCodeSeen <- -1
		}
	}()
	select {
	case code := <-closeCodeSeen:
		if code != WSCloseRevoked {
			t.Fatalf("close code = %d, want 4001", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no close frame")
	}
	if _, err := GetConnection("b55"); err == nil {
		t.Error("the revoked connection must be unregistered")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
