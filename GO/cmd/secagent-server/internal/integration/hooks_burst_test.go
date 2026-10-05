package integration

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// enroll all agents in ONE transaction (the node is a separate process: through its database file)
	path := ""
	for _, e := range n.env {
		if strings.HasPrefix(e, "DATABASE_URL=sqlite:///") {
			path = strings.TrimPrefix(e, "DATABASE_URL=sqlite:///")
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=10000"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < agents; i++ {
		h := fmt.Sprintf("burst-%04d", i)
		if _, err := tx.Exec(`INSERT INTO agents (hostname, public_key_pem, token_jti, enrolled_at, last_seen, status)
			VALUES (?, 'pem', ?, ?, ?, 'disconnected')`, h, "agent-"+h, now, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	dial := func(host string) error {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": host, "role": "agent", "jti": "agent-" + host,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(n.jwtSecret))
		if err != nil {
			return err
		}
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tok)
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
				if err := dial(fmt.Sprintf("burst-%04d", i)); err != nil {
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
