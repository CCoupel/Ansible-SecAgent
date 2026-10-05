package integration

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// #183: 3 000 agents reconnect at once after a start (failover): every host.up hook runs and is
// journaled, nothing is dropped (the queue and the counters of GET /api/admin/status say so).
func TestHooksBurst_3000AgentsReconnectingAllRunTheirHook(t *testing.T) {
	if testing.Short() {
		t.Skip("burst test")
	}
	parallel(t)
	const agents = 3000
	n := startNode(t, nodeSpec{ID: "burst", Hooks: func(out string) string {
		return `{"hooks":[{"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"up {{hostname}}\n"}]}]}`
	}})

	// enroll all agents through the real flow, concurrently (the state engine groups the writes)
	tokens := make([]string, agents)
	var ewg sync.WaitGroup
	eq := make(chan int)
	eerrs := make(chan error, agents)
	for w := 0; w < 64; w++ {
		ewg.Add(1)
		go func() {
			defer ewg.Done()
			for i := range eq {
				tok, err := n.enrollAgentErr(fmt.Sprintf("burst-%04d", i))
				if err != nil {
					eerrs <- err
					continue
				}
				tokens[i] = tok
			}
		}()
	}
	for i := 0; i < agents; i++ {
		eq <- i
	}
	close(eq)
	ewg.Wait()
	close(eerrs)
	if err := <-eerrs; err != nil {
		t.Fatalf("an agent could not enroll: %v", err)
	}

	// the failover burst: all of them (re)connect at once
	dial := func(i int) error {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens[i])
		d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 20 * time.Second}
		conn, _, err := d.Dial(n.wssURL()+"/ws/agent", h)
		if err != nil {
			return err
		}
		return conn.Close() // the host.up event fired at registration
	}
	var wg sync.WaitGroup
	next := make(chan int)
	errs := make(chan error, agents)
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := dial(i); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 0; i < agents; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatalf("an agent could not connect: %v", err)
	}

	waitFor(t, "3000 host.up hooks executed", func() bool { return n.hookCount("up burst-") >= agents })
	lines := n.hookLines()
	seen := map[string]bool{}
	for _, l := range lines {
		seen[l] = true
	}
	if len(seen) != agents {
		t.Errorf("%d distinct hooks executed, want %d", len(seen), agents)
	}
	journal := ""
	for _, e := range n.env {
		if strings.HasPrefix(e, "RELAY_ACTION_LOG=") {
			journal = strings.TrimPrefix(e, "RELAY_ACTION_LOG=")
		}
	}
	waitFor(t, "3000 lines in the action journal", func() bool {
		b, _ := os.ReadFile(journal)
		return strings.Count(string(b), `"event":"host.up"`) >= agents
	})
	code, status := n.admin("GET", "/api/admin/status", nil)
	if code != http.StatusOK || status["hooks_dropped_events"] != float64(0) || status["hooks_dropped_actions"] != float64(0) {
		t.Errorf("status %d: %v", code, status)
	}
	if n.logs.has("queue full") {
		t.Error("an event was rejected: the queue must absorb 3 000 hosts")
	}
}
