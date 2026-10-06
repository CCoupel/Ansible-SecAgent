package integration

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// forEachAgent runs fn for every index with a bounded pool; the first error is returned.
func forEachAgent(n, workers int, fn func(i int) error) error {
	var wg sync.WaitGroup
	next := make(chan int)
	errs := make(chan error, n)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(i); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	close(errs)
	return <-errs
}

// connectAndClose opens /ws/agent of the node with the agent's token and closes it: the host.up event
// fires at registration.
func connectAndClose(n *node, tok string) error {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 20 * time.Second}
	conn, _, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		return err
	}
	return conn.Close()
}

// #171 hooks through a REAL fail-over with two instances: N agents connect to the master A (N host.up
// hooks), A is killed, the standby B takes over, the same N agents reconnect to B: B executes exactly N
// more host.up hooks (one per agent) and drops nothing (queue counters of GET /api/admin/status).
func TestFailover_HooksRunOnTheNewMasterAfterTheSwitchOver(t *testing.T) {
	parallel(t)
	const agents = 100
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: func(out string) string {
		return `{"hooks":[{"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"up {{hostname}}\n"}]}]}`
	}})
	b := a.sibling() // same state, same hooks configuration and output file
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)

	tokens := make([]string, agents)
	if err := forEachAgent(agents, 16, func(i int) (err error) {
		tokens[i], err = a.enrollAgentErr(fmt.Sprintf("wh-%03d", i))
		return err
	}); err != nil {
		t.Fatalf("an agent could not enroll: %v", err)
	}

	if err := forEachAgent(agents, 16, func(i int) error { return connectAndClose(a, tokens[i]) }); err != nil {
		t.Fatalf("an agent could not connect to the master: %v", err)
	}
	waitFor(t, "the master ran one host.up hook per agent", func() bool { return a.hookCount("up wh-") >= agents })
	if got := a.hookCount("up wh-"); got != agents {
		t.Fatalf("the master ran %d host.up hooks, want %d", got, agents)
	}

	a.killNow()
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over; logs:\n%s", b.logs.String())
	}
	if err := forEachAgent(agents, 16, func(i int) error { return connectAndClose(b, tokens[i]) }); err != nil {
		t.Fatalf("an agent could not connect to the new master: %v", err)
	}
	waitFor(t, "the new master ran its host.up hooks", func() bool { return b.hookCount("up wh-") >= 2*agents })

	// one hook per agent and per master: every agent appears exactly twice (A's run, B's run)
	perHost := map[string]int{}
	for _, l := range b.hookLines() {
		if strings.HasPrefix(l, "up wh-") {
			perHost[l]++
		}
	}
	if len(perHost) != agents {
		t.Errorf("%d distinct agents in the hook output, want %d", len(perHost), agents)
	}
	for l, c := range perHost {
		if c != 2 {
			t.Errorf("%q ran %d times over the two masters, want 2 (one each)", l, c)
		}
	}
	code, status := b.admin("GET", "/api/admin/status", nil)
	if code != http.StatusOK || status["hooks_dropped_events"] != float64(0) || status["hooks_dropped_actions"] != float64(0) {
		t.Errorf("status %d: dropped events/actions must be 0: %v", code, status)
	}
	if b.logs.has("queue full") {
		t.Error("the new master rejected an event: its queue must absorb the reconnection burst")
	}
}
