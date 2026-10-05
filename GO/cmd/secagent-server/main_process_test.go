package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ── main() exercised as a real process (#155, qa): the test binary re-executes itself ──

const runMainEnv = "SECAGENT_TEST_RUN_MAIN"

// TestMain lets the test binary act as the secagent-server binary when re-executed with
// SECAGENT_TEST_RUN_MAIN=1: main() then runs for real (env → Config → Build → Run → exit code).
func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Args = []string{"secagent-server"}
		main()
		os.Exit(0) // main returned normally (graceful shutdown)
	}
	os.Exit(m.Run())
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// serverProc is one running re-executed server process.
type serverProc struct {
	cmd  *exec.Cmd
	out  *lockedBuf
	done chan error
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// startMain starts main() in a subprocess with a minimal environment plus the given overrides.
func startMain(t *testing.T, env map[string]string) *serverProc {
	t.Helper()
	dir := t.TempDir()
	base := map[string]string{
		runMainEnv:           "1",
		"JWT_SECRET_KEY":     "proc-test-secret",
		"ADMIN_TOKEN":        "proc-test-admin",
		"RSA_MASTER_KEY":     "proc-test-master-key",
		"DATABASE_URL":       filepath.Join(dir, "relay.db"),
		"NATS_URL":           "nats://127.0.0.1:1",
		"RELAY_HOOKS_CONFIG": filepath.Join(dir, "absent-hooks.json"),
		"PATH":               os.Getenv("PATH"),
		"HOME":               dir,
	}
	for k, v := range env {
		base[k] = v
	}
	var environ []string
	for k, v := range base {
		environ = append(environ, k+"="+v) // an empty value in env overrides the base on purpose
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = environ
	out := &lockedBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &serverProc{cmd: cmd, out: out, done: make(chan error, 1)}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func (p *serverProc) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case err := <-p.done:
		return exitCode(err)
	case <-time.After(d):
		t.Fatalf("process did not exit within %v; output:\n%s", d, p.out.String())
		return -1
	}
}

func portOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ── start-up refused: fail closed, non-zero exit, nothing listening ──────────

func TestMainProcess_RefusesToStartWithoutSecrets(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no JWT secret":  {"JWT_SECRET_KEY": ""},
		"no admin token": {"ADMIN_TOKEN": ""},
	} {
		t.Run(name, func(t *testing.T) {
			api := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			env["API_ADDR"] = api
			env["ADMIN_ADDR"] = fmt.Sprintf("127.0.0.1:%d", freePort(t))
			env["WS_ADDR"] = fmt.Sprintf("127.0.0.1:%d", freePort(t))
			p := startMain(t, env)
			if code := p.wait(t, 20*time.Second); code == 0 {
				t.Errorf("exit code 0 without a required secret; output:\n%s", p.out.String())
			}
			if !strings.Contains(p.out.String(), "environment variable") {
				t.Errorf("the missing variable must be reported:\n%s", p.out.String())
			}
			if portOpen(api) {
				t.Error("nothing may listen when the start-up is refused")
			}
		})
	}
}

func TestMainProcess_RefusesInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"malformed API_ADDR", map[string]string{"API_ADDR": "7770"}, "API_ADDR"},
		{"malformed ADMIN_ADDR", map[string]string{"ADMIN_ADDR": "nonsense"}, "ADMIN_ADDR"},
		{"malformed WS_ADDR", map[string]string{"WS_ADDR": "x"}, "WS_ADDR"},
		{"incomplete repeater config", map[string]string{"REPEATER_UPSTREAM_URL": "wss://parent:7772"}, "invalid repeater configuration"},
		{"ws:// upstream refused", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "ws://parent:7772", "REPEATER_UPSTREAM_TOKEN": "t"}, "wss"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := startMain(t, tt.env)
			if code := p.wait(t, 20*time.Second); code == 0 {
				t.Errorf("exit code 0 for an invalid configuration; output:\n%s", p.out.String())
			}
			if !strings.Contains(p.out.String(), tt.want) {
				t.Errorf("output lacks %q:\n%s", tt.want, p.out.String())
			}
		})
	}
}

func TestMainProcess_PortAlreadyInUseExitsNonZero(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	p := startMain(t, map[string]string{
		"API_ADDR":   busy.Addr().String(),
		"ADMIN_ADDR": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"WS_ADDR":    fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	})
	if code := p.wait(t, 30*time.Second); code == 0 {
		t.Errorf("exit code 0 with a busy port; output:\n%s", p.out.String())
	}
	if !strings.Contains(p.out.String(), "failed to start all servers") {
		t.Errorf("output:\n%s", p.out.String())
	}
}

// ── a configured start: environment honoured, health answers, SIGTERM stops cleanly ──

func TestMainProcess_ServesOnConfiguredAddressesAndStopsCleanlyOnSIGTERM(t *testing.T) {
	api := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	admin := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	wsAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	p := startMain(t, map[string]string{"API_ADDR": api, "ADMIN_ADDR": admin, "WS_ADDR": wsAddr})

	deadline := time.Now().Add(30 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + api + "/health")
		if err == nil {
			_ = resp.Body.Close()
			healthy = resp.StatusCode == http.StatusOK
			break
		}
		select {
		case err := <-p.done:
			t.Fatalf("process exited early (%v):\n%s", err, p.out.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		t.Fatalf("/health did not answer 200 on %s:\n%s", api, p.out.String())
	}
	// the three configured addresses are the ones in use
	for name, addr := range map[string]string{"api": api, "admin": admin, "ws": wsAddr} {
		if !portOpen(addr) {
			t.Errorf("%s address %s is not listening", name, addr)
		}
	}
	// SIGHUP reloads the hooks configuration without stopping the server
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	reloadDeadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(p.out.String(), "SIGHUP received") && time.Now().Before(reloadDeadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(p.out.String(), "SIGHUP received") {
		t.Errorf("SIGHUP not handled:\n%s", p.out.String())
	}
	if !portOpen(api) {
		t.Error("the server must keep running after SIGHUP")
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 40*time.Second); code != 0 {
		t.Errorf("exit code = %d after SIGTERM, want 0; output:\n%s", code, p.out.String())
	}
	out := p.out.String()
	if !strings.Contains(out, "[SHUTDOWN]") || !strings.Contains(out, "Shutdown complete") {
		t.Errorf("graceful shutdown not logged:\n%s", out)
	}
	for name, addr := range map[string]string{"api": api, "admin": admin, "ws": wsAddr} {
		if portOpen(addr) {
			t.Errorf("%s address %s still listening after the shutdown", name, addr)
		}
	}
}

func TestMainProcess_SIGINTAlsoStopsCleanly(t *testing.T) {
	api := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	p := startMain(t, map[string]string{"API_ADDR": api,
		"ADMIN_ADDR": fmt.Sprintf("127.0.0.1:%d", freePort(t)), "WS_ADDR": fmt.Sprintf("127.0.0.1:%d", freePort(t))})
	deadline := time.Now().Add(30 * time.Second)
	for !portOpen(api) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !portOpen(api) {
		t.Fatalf("server not up:\n%s", p.out.String())
	}
	time.Sleep(300 * time.Millisecond) // let Run reach its wait loop
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 40*time.Second); code != 0 {
		t.Errorf("exit code = %d after SIGINT, want 0; output:\n%s", code, p.out.String())
	}
}
