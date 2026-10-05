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
//   - the NATS URL is unreachable (degraded mode, like production without NATS).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/server"
	"secagent-server/cmd/secagent-server/internal/ws"
)

const (
	envNodeProcess = "NODE_PROCESS"
	envNodeCert    = "NODE_CERT"
	envNodeKey     = "NODE_KEY"
	readyMarker    = "NODE_READY "
)

// nodeReady is the one line a child prints once its node serves.
type nodeReady struct {
	API     string `json:"api"`     // host:port of the public API listener (TLS)
	Admin   string `json:"admin"`   // host:port of the admin listener (TLS)
	WS      string `json:"ws"`      // host:port of the WebSocket listener (TLS)
	Control string `json:"control"` // http://host:port of the test control server
}

// TestNodeProcess runs ONE node until its stdin is closed (the parent test process exits).
func TestNodeProcess(t *testing.T) {
	if os.Getenv(envNodeProcess) != "1" {
		t.Skip("child process of the integration harness only")
	}
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		log.Fatalf("ConfigFromEnv: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv(envNodeCert), os.Getenv(envNodeKey))
	if err != nil {
		log.Fatalf("test certificate: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	for _, p := range []*net.Listener{&cfg.APIListener, &cfg.AdminListener, &cfg.WSListener} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		*p = tls.NewListener(ln, tlsCfg)
	}
	applyTuning(&cfg)

	node, err := server.Build(cfg)
	if err != nil {
		log.Fatalf("Build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx) }()
	select {
	case <-node.Ready():
	case err := <-done:
		log.Fatalf("node stopped before being ready: %v", err)
	case <-time.After(60 * time.Second):
		log.Fatal("node not ready")
	}

	ctl := http.NewServeMux()
	ctl.HandleFunc("POST /close-relay", func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.URL.Query().Get("code"))
		ok := ws.CloseRelay(r.URL.Query().Get("id"), code, "test-induced")
		_ = json.NewEncoder(w).Encode(map[string]bool{"closed": ok})
	})
	// SIGHUP stand-in: main() calls node.ReloadHooks() on SIGHUP (covered by the real-process test of
	// internal/server); here the harness triggers the same method.
	ctl.HandleFunc("POST /reload-hooks", func(w http.ResponseWriter, r *http.Request) {
		node.ReloadHooks()
		_ = json.NewEncoder(w).Encode(map[string]bool{"reloaded": true})
	})
	ctlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("control listen: %v", err)
	}
	go func() { _ = http.Serve(ctlLn, ctl) }()

	api, admin, wsAddr := node.Addrs()
	line, _ := json.Marshal(nodeReady{API: api, Admin: admin, WS: wsAddr, Control: "http://" + ctlLn.Addr().String()})
	fmt.Println(readyMarker + string(line))
	_ = os.Stdout.Sync()

	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			break
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(35 * time.Second):
	}
	_ = ctlLn.Close()
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
