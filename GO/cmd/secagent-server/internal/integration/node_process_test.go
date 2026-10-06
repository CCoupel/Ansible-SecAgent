package integration

// Child side of the harness: ONE real secagent-server node per OS process, started through the
// REAL entry point (internal/server: ConfigFromEnv → Build → Run), exactly as main() does.
//
// The ws / handlers packages keep their hooks in package-level variables, so a tree of nodes
// cannot live in a single process: the harness re-executes this test binary once per node. What
// differs from `secagent-server` is only the plumbing around it:
//   - the three listeners are bound by the child on ephemeral loopback ports and wrapped in TLS
//     (test certificate, trusted through SSL_CERT_FILE: the nodes really verify each other);
//   - a tiny plain-HTTP control server (ws.CloseRelay) lets a test cut a link with a close code;
//   - (no message broker: NATS was removed in v3.0.3).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/server"
	"secagent-server/cmd/secagent-server/internal/ws"
)

const (
	envNodeProcess = "NODE_PROCESS"
	envNodeCert    = "NODE_CERT"
	envNodeKey     = "NODE_KEY"
	readyMarker    = "NODE_READY "
	startedMarker  = "NODE_STARTED"
)

// nodeReady is the one line a child prints once its node serves.
type nodeReady struct {
	API     string `json:"api"`     // host:port of the public API listener (TLS)
	Admin   string `json:"admin"`   // host:port of the admin listener (TLS)
	WS      string `json:"ws"`      // host:port of the WebSocket listener (TLS)
	Control string `json:"control"` // http://host:port of the test control server
}

// lockProfileFast is the lock calibration of the harness' children (the production values are
// minutes: DefaultParams). It keeps every invariant of Params.Validate. NODE_LOCK_PROFILE=default
// selects the production values.
func lockProfileFast() lock.Params {
	return lock.Params{
		Beat: 400 * time.Millisecond, Check: 200 * time.Millisecond, SelfRetire: 5 * time.Second, MasterStale: 7 * time.Second,
		CandidateStale: 2500 * time.Millisecond, PauseMin: 350 * time.Millisecond, PauseMax: 600 * time.Millisecond,
		MaxWriteLatency: 250 * time.Millisecond,
	}
}

// TestNodeProcess runs ONE instance of a node (through the real active/passive entry point,
// server.RunInstance) until its stdin is closed (the parent test process exits) or the instance
// exits by itself (lock lost: code 75, start refused: 1).
func TestNodeProcess(t *testing.T) {
	if os.Getenv(envNodeProcess) != "1" {
		t.Skip("child process of the integration harness only")
	}
	// the harness' children all listen on 127.0.0.1: the SSRF guard on push targets would refuse them
	repeater.UnsafeAllowInternalDialTargets(true)
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		log.Fatalf("ConfigFromEnv: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv(envNodeCert), os.Getenv(envNodeKey))
	if err != nil {
		log.Fatalf("test certificate: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	// The listeners are bound when the instance is PROMOTED (cfg.Listen): a secondary has none.
	// Ephemeral loopback ports, unless the harness restarts the node on its previous addresses.
	cfg.Listen = func(name string) (net.Listener, error) {
		env := map[string]string{"api": "NODE_API_ADDR", "admin": "NODE_ADMIN_ADDR", "ws": "NODE_WS_ADDR"}[name]
		addr := os.Getenv(env)
		var ln net.Listener
		var err error
		if addr == "" {
			ln, err = listenOutsideEphemeralRange()
		} else {
			for i := 0; i < 300; i++ { // the previous process (or a loopback self-connect of a redialing peer) may still hold it
				if ln, err = net.Listen("tcp", addr); err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		if err != nil {
			return nil, err
		}
		return tls.NewListener(ln, tlsCfg), nil
	}
	applyTuning(&cfg)
	if os.Getenv("NODE_LOCK_PROFILE") != "default" {
		cfg.LockParams = lockProfileFast()
	}

	// NODE_LOCK_REMOVE_GATE: this instance waits between judging a lock stale and deleting it
	// (case 5 of #162: a process frozen at that exact point erases a lock someone else just took).
	// NODE_LOCK_REMOVE_GATE=<file>: the instance writes <file>.reached when it judged the lock stale, then
	// waits until <file> exists before deleting it (the test releases the gates in the order it needs:
	// deterministic whatever the machine load).
	if gate := os.Getenv("NODE_LOCK_REMOVE_GATE"); gate != "" {
		cfg.LockHooks.BeforeRemove = func() {
			_ = os.WriteFile(gate+".reached", []byte("x"), 0o600) // observable: this instance judged the lock stale
			for i := 0; i < 6000; i++ {
				if _, err := os.Stat(gate); err == nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	var ctlLn net.Listener
	cfg.OnReady = func(node *server.Node) {
		ctl := http.NewServeMux()
		ctl.HandleFunc("POST /close-relay", func(w http.ResponseWriter, r *http.Request) {
			code, _ := strconv.Atoi(r.URL.Query().Get("code"))
			ok := ws.CloseRelay(r.URL.Query().Get("id"), code, "test-induced")
			_ = json.NewEncoder(w).Encode(map[string]bool{"closed": ok})
		})
		// SIGHUP stand-in: main() calls the hooks reload on SIGHUP (covered by the real-process test
		// of internal/server); here the harness triggers the same method.
		ctl.HandleFunc("POST /reload-hooks", func(w http.ResponseWriter, r *http.Request) {
			node.ReloadHooks()
			_ = json.NewEncoder(w).Encode(map[string]bool{"reloaded": true})
		})
		var err error
		if ctlLn, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			log.Fatalf("control listen: %v", err)
		}
		go func() { _ = http.Serve(ctlLn, ctl) }()
		api, admin, wsAddr := node.Addrs()
		line, _ := json.Marshal(nodeReady{API: api, Admin: admin, WS: wsAddr, Control: "http://" + ctlLn.Addr().String()})
		fmt.Println(readyMarker + string(line))
		_ = os.Stdout.Sync()
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { // the parent closes our stdin to stop us
		buf := make([]byte, 1)
		for {
			if _, err := os.Stdin.Read(buf); err != nil {
				break
			}
		}
		cancel()
	}()
	fmt.Println(startedMarker)
	_ = os.Stdout.Sync()
	done := make(chan int, 1)
	go func() {
		code, err := server.RunInstance(ctx, cfg)
		if err != nil {
			log.Printf("RunInstance: %v", err)
		}
		done <- code
	}()
	select {
	case code := <-done:
		if ctlLn != nil {
			_ = ctlLn.Close()
		}
		os.Exit(code) // 0 clean stop, 75 lock lost, 1 refused: the harness reads it
	case <-time.After(10 * time.Minute):
		log.Fatal("node instance did not end")
	}
}

// applyTuning is the single place where the child adjusts the real configuration for tests: ONLY
// durations, through the Config.Tune seam (short backoff and agent_list interval so the suite runs
// in seconds; production defaults are 5-60 s and 30 s). TLS settings and every callback are the
// production ones.
func applyTuning(cfg *server.Config) {
	cfg.Tune = func(o *repeater.Options, d *repeater.DialerOptions) {
		o.MinBackoff, o.MaxBackoff = 50*time.Millisecond, 400*time.Millisecond
		o.AgentListInterval = 100 * time.Millisecond
		d.MinBackoff, d.MaxBackoff = 50*time.Millisecond, 400*time.Millisecond
	}
}

// listenOutsideEphemeralRange binds a loopback port that the kernel never hands out as an ephemeral
// port (source port of an outgoing connection, ":0" listener): the harness restarts a node on the
// SAME address, and an ephemeral port released by the stopped process could be taken by another
// connection of the test run before the new process binds it ("address already in use").
func listenOutsideEphemeralRange() (net.Listener, error) {
	top := 32768
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		var lo, hi int
		if _, err := fmt.Sscanf(string(b), "%d %d", &lo, &hi); err == nil && lo >= 2048 {
			top = lo
		}
	}
	const bottom = 12000
	if top-bottom < 1000 {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	for i := 0; i < 500; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(top-bottom)))
		if err != nil {
			return nil, err
		}
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bottom+int(n.Int64()))); err == nil {
			return ln, nil
		}
	}
	return net.Listen("tcp", "127.0.0.1:0")
}
