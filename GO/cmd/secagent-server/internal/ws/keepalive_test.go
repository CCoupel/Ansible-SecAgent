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
	withKeepalive(t, time.Hour) // keepalive on (deadline set) but no automatic ping during the test
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
	time.Sleep(50 * time.Millisecond)
	if !ProbeConnection("ka-probe-live", time.Second) {
		t.Fatal("a reading client answers the ping")
	}
	select {
	case <-closed:
		t.Fatal("a live connection must not be closed by the probe")
	default:
	}

	url2, closed2 := keepaliveServer(t, "ka-probe-dead")
	_ = dialKA(t, url2) // never reads: no pong
	time.Sleep(50 * time.Millisecond)
	// single-flight: concurrent probes share one answer and take about one delay, not N
	var wg sync.WaitGroup
	res := make([]bool, 4)
	start := time.Now()
	for i := range res {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i] = ProbeConnection("ka-probe-dead", 400*time.Millisecond) }(i)
	}
	wg.Wait()
	for i, r := range res {
		if r {
			t.Errorf("probe %d: a silent connection must be dead", i)
		}
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("4 concurrent probes took %s: not single-flight", d)
	}
	select {
	case <-closed2:
	case <-time.After(2 * time.Second):
		t.Fatal("a dead connection must be closed by the probe")
	}
}
