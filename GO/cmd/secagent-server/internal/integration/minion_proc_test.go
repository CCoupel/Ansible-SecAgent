package integration

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"secagent-server/cmd/secagent-server/internal/localstatus"
	"secagent-server/internal/testnet"
)

// The REAL minion (cmd/secagent-minion binary: loadOrEnroll + dispatcher with its address lists) against
// REAL nodes. The binary is built once; its RSA key is the harness' shared 4096-bit key (a minion would
// generate one on first start: minutes under -race), enrollment is the real token + challenge flow.

var (
	minBinOnce sync.Once
	minBinPath string
	minBinErr  error
)

func minionBinary(t *testing.T) string {
	t.Helper()
	minBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "secagent-minion-")
		if err != nil {
			minBinErr = err
			return
		}
		minBinPath = filepath.Join(dir, "secagent-minion")
		goBin, err := exec.LookPath("go")
		if err != nil {
			minBinErr = err
			return
		}
		cmd := exec.Command(goBin, "build", "-o", minBinPath, "./cmd/secagent-minion")
		cmd.Dir = "../../../.." // GO/
		if out, err := cmd.CombinedOutput(); err != nil {
			minBinErr = fmt.Errorf("go build secagent-minion: %v\n%s", err, out)
		}
	})
	if minBinErr != nil {
		t.Fatal(minBinErr)
	}
	return minBinPath
}

// nodeAddrs are the three fixed listening addresses of a node instance, outside the ephemeral range
// (a standby instance must be reachable at an address known BEFORE it is promoted).
type nodeAddrs struct{ api, admin, ws string }

func newNodeAddrs(t *testing.T) nodeAddrs {
	t.Helper()
	return nodeAddrs{api: testnet.ClosedAddr(t), admin: testnet.ClosedAddr(t), ws: testnet.ClosedAddr(t)}
}

func (a nodeAddrs) env() []string {
	return []string{"NODE_API_ADDR=" + a.api, "NODE_ADMIN_ADDR=" + a.admin, "NODE_WS_ADDR=" + a.ws}
}

// enrollmentToken mints a one-shot enrollment token (secagent_enr_…) bound to the hostname on node n.
func enrollmentToken(t *testing.T, n *node, host string) string {
	t.Helper()
	code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "hostname_pattern": regexp.QuoteMeta(host), "created_by": "harness"})
	if code != 201 {
		t.Fatalf("enrollment token for %s on %s: %d %v", host, n.id, code, m)
	}
	tok, _ := m["token"].(string)
	if !strings.HasPrefix(tok, "secagent_enr_") {
		t.Fatalf("unexpected enrollment token %q", tok)
	}
	return tok
}

type minionProc struct {
	t       *testing.T
	host    string
	cmd     *exec.Cmd
	logs    *syncBuf
	exited  chan struct{}
	jwtPath string
}

// startMinionProc starts the real minion for host with the address lists of the given node instances
// (same position = same instance). It enrolls with token on first start (no JWT file yet).
func startMinionProc(t *testing.T, host, token string, instances ...nodeAddrs) *minionProc {
	t.Helper()
	dir := t.TempDir()
	key, _, err := harnessAgentKeyErr()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	var apis, wss []string
	for _, in := range instances {
		apis = append(apis, "https://"+in.api)
		wss = append(wss, "wss://"+in.ws+"/ws/agent")
	}
	m := &minionProc{t: t, host: host, logs: &syncBuf{}, exited: make(chan struct{}), jwtPath: filepath.Join(dir, "token.jwt")}
	m.cmd = exec.Command(minionBinary(t))
	m.cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir,
		"RELAY_SERVER_URL=" + strings.Join(apis, ","), "RELAY_WS_URL=" + strings.Join(wss, ","),
		"RELAY_AGENT_HOSTNAME=" + host, "RELAY_PRIVATE_KEY=" + keyFile, "RELAY_JWT_PATH=" + m.jwtPath,
		"RELAY_ENROLLMENT_TOKEN=" + token, "RELAY_CA_BUNDLE=" + certPath, "RELAY_ASYNC_DIR=" + filepath.Join(dir, "async"),
	}
	m.cmd.Stdout, m.cmd.Stderr = m.logs, m.logs
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = m.cmd.Wait(); close(m.exited) }()
	t.Cleanup(func() {
		_ = m.cmd.Process.Kill() // our own child, by handle
		<-m.exited
		if t.Failed() {
			t.Logf("minion %s logs:\n%s", host, m.logs.String())
		}
	})
	return m
}

// connections is the number of times this minion logged an established WebSocket.
func (m *minionProc) connections() int { return m.logs.count("[WS] Connected to ") }

// waitConnections waits for the minion's n-th established WebSocket.
func (m *minionProc) waitConnections(n int, why string) {
	m.t.Helper()
	waitFor(m.t, why, func() bool {
		select {
		case <-m.exited:
			m.t.Fatalf("minion %s exited:\n%s", m.host, m.logs.String())
		default:
		}
		return m.connections() >= n
	})
}

// agentServed is true once the node's log says the agent registered on its /ws/agent.
func agentServed(n *node, host string, times int) bool {
	return n.logs.count(fmt.Sprintf("Agent connected: hostname=%s", host)) >= times
}

// localStatusPolled is true once this (secondary) instance wrote a lock-check to its local status file.
func (n *node) localStatusPolled() bool {
	f, err := localstatus.Read(n.statusPath)
	return err == nil && f.LastCheckAt > 0
}
