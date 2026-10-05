package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
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

	"secagent-server/cmd/secagent-server/internal/state"
)

// ── main() exercised as a real process (#155, qa): the test binary re-executes itself ──

const runMainEnv = "SECAGENT_TEST_RUN_MAIN"

// TestMain lets the test binary act as the secagent-server binary when re-executed with
// SECAGENT_TEST_RUN_MAIN=1: main() then runs for real (env → Config → Build → Run → exit code).
func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Args = []string{"secagent-server"}
		if extra := os.Getenv("SECAGENT_TEST_ARGS"); extra != "" {
			os.Args = append(os.Args, strings.Fields(extra)...)
		}
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

// ── ports: no bind-close-reuse window with the kernel's ephemeral allocations ──
//
// A port obtained with ":0" and released is an EPHEMERAL port: the kernel hands it to the next
// ":0" listener or outgoing connection of any test running in parallel, before the server process
// binds it. Ports are therefore drawn OUTSIDE the kernel's ephemeral range, never handed out
// twice by this process, and checked free right before use.
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

func freePort(t *testing.T) int {
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
		return port
	}
	t.Fatal("no free port outside the ephemeral range")
	return 0
}

// ── pre-initialized state: no RSA-4096 generation (minutes under -race and load) ──

var (
	stateOnce sync.Once
	stateTpl  string
	stateErr  error
)

// seedState gives the process a state created like `secagent-server state init` does (RSA key and
// JWT secret encrypted with RSA_MASTER_KEY), with a small RSA key. The template is made once.
func seedState(t *testing.T, dir, masterKey string) {
	t.Helper()
	stateOnce.Do(func() {
		d, err := os.MkdirTemp("", "secagent-main-state-*")
		if err != nil {
			stateErr = err
			return
		}
		if err := state.Init(state.InitOptions{Dir: d, MasterKey: masterKey, RSABits: 2048}); err != nil {
			stateErr = err
			return
		}
		stateTpl = filepath.Join(d, state.StateFile)
	})
	if stateErr != nil {
		t.Fatal(stateErr)
	}
	data, err := os.ReadFile(stateTpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, state.StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startMain starts main() in a subprocess with a minimal environment plus the given overrides.
func startMain(t *testing.T, env map[string]string) *serverProc {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedState(t, stateDir, "proc-test-master-key")
	base := map[string]string{
		runMainEnv:           "1",
		"TLS_DISABLE":        "true",
		"JWT_SECRET_KEY":     "proc-test-secret",
		"ADMIN_TOKEN":        "proc-test-admin",
		"RSA_MASTER_KEY":     "proc-test-master-key",
		"STATE_DIR":          stateDir,
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
		{"template in RELAY_GROUP_VARS", map[string]string{"RELAY_GROUP_VARS": `{"x":"{{ lookup('pipe','id') }}"}`}, "RELAY_GROUP_VARS"},
		{"reserved key in RELAY_GROUP_VARS", map[string]string{"RELAY_GROUP_VARS": `{"ansible_connection":"local"}`}, "RELAY_GROUP_VARS"},
		{"RELAY_GROUP_VARS not JSON", map[string]string{"RELAY_GROUP_VARS": `env=staging`}, "RELAY_GROUP_VARS"},
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

// #160: the relay state is relay.state in STATE_DIR. DATABASE_URL (SQLite) is refused loudly, a missing
// state refuses to start with the exact FATAL message (never created implicitly), a tampered state too.
func TestMainProcess_StateStartupRefusals(t *testing.T) {
	t.Run("DATABASE_URL is an error", func(t *testing.T) {
		p := startMain(t, map[string]string{"DATABASE_URL": "sqlite:////data/relay.db"})
		if code := p.wait(t, 20*time.Second); code == 0 || !strings.Contains(p.out.String(), "DATABASE_URL is no longer supported") {
			t.Errorf("exit %d, output:\n%s", code, p.out.String())
		}
	})
	t.Run("missing state", func(t *testing.T) {
		empty := t.TempDir()
		p := startMain(t, map[string]string{"STATE_DIR": empty})
		if code := p.wait(t, 20*time.Second); code == 0 {
			t.Errorf("exit code 0 without a state; output:\n%s", p.out.String())
		}
		want := "FATAL: relay.state not found in STATE_DIR=" + empty + " — run 'secagent-server state init' to initialize"
		if !strings.Contains(p.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, p.out.String())
		}
		if names, _ := os.ReadDir(empty); len(names) != 0 {
			t.Errorf("the server must never create the state: %v", names)
		}
	})
	t.Run("tampered state", func(t *testing.T) {
		dir := t.TempDir()
		seedState(t, dir, "proc-test-master-key")
		path := filepath.Join(dir, state.StateFile)
		b, _ := os.ReadFile(path)
		if err := os.WriteFile(path, bytes.Replace(b, []byte(`"write_seq":1`), []byte(`"write_seq":9`), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		p := startMain(t, map[string]string{"STATE_DIR": dir})
		if code := p.wait(t, 20*time.Second); code == 0 {
			t.Errorf("exit code 0 with a tampered state; output:\n%s", p.out.String())
		}
	})
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

// startServing starts the server on three fresh ports and waits (by condition, generous timeout)
// until it answers /health. A port taken by another process between the check and the bind makes
// the server exit with "address already in use": the start is then retried on new ports.
func startServing(t *testing.T) (p *serverProc, api, admin, wsAddr string) {
	t.Helper()
	for attempt := 1; attempt <= 4; attempt++ {
		api = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		admin = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		wsAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		p = startMain(t, map[string]string{"API_ADDR": api, "ADMIN_ADDR": admin, "WS_ADDR": wsAddr})
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := http.Get("http://" + api + "/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return p, api, admin, wsAddr
				}
			}
			select {
			case <-p.done:
				if strings.Contains(p.out.String(), "address already in use") && attempt < 4 {
					goto retry
				}
				t.Fatalf("process exited early:\n%s", p.out.String())
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("/health did not answer 200 on %s:\n%s", api, p.out.String())
	retry:
	}
	t.Fatal("no start succeeded")
	return
}

func waitLog(t *testing.T, p *serverProc, sub string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !strings.Contains(p.out.String(), sub) {
		if time.Now().After(deadline) {
			t.Fatalf("log %q never appeared:\n%s", sub, p.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestMainProcess_ServesOnConfiguredAddressesAndStopsCleanlyOnSIGTERM(t *testing.T) {
	p, api, admin, wsAddr := startServing(t)
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
	waitLog(t, p, "SIGHUP received", 30*time.Second)
	if !portOpen(api) {
		t.Error("the server must keep running after SIGHUP")
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 60*time.Second); code != 0 {
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
	p, _, _, _ := startServing(t)
	// signals are handled once Run is waiting: the readiness line is logged right before
	waitLog(t, p, "Ansible-SecAgent GO Server ready", 30*time.Second)
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 60*time.Second); code != 0 {
		t.Errorf("exit code = %d after SIGINT, want 0; output:\n%s", code, p.out.String())
	}
}

// `state init` is a LOCAL command: it must run without ADMIN_TOKEN nor JWT_SECRET_KEY in the
// environment (#159b R2), creates the state, and refuses to run a second time.
func TestStateInitNeedsNoServerSecretsInTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	run := func() (string, error) {
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			runMainEnv + "=1",
			"SECAGENT_TEST_ARGS=state init --state-dir " + dir,
			"RSA_MASTER_KEY=process-test-master-key",
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "state initialized in "+dir) {
		t.Fatalf("state init without ADMIN_TOKEN/JWT_SECRET_KEY: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "relay.state")); err != nil {
		t.Fatalf("relay.state missing: %v", err)
	}
	if out, err := run(); err == nil || !strings.Contains(out, "refusing to initialize") {
		t.Fatalf("a second init must be refused: %v\n%s", err, out)
	}
}

// #175: without a certificate pair and without the explicit TLS_DISABLE=true, the process refuses
// to start (non-zero exit, explicit message, nothing listening): never a silent plain-HTTP server.
func TestMainProcess_RefusesToStartWithoutTLS(t *testing.T) {
	api := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	env := map[string]string{
		"TLS_DISABLE": "", // overrides the test default
		"API_ADDR":    api,
		"ADMIN_ADDR":  fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"WS_ADDR":     fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	}
	p := startMain(t, env)
	if code := p.wait(t, 20*time.Second); code == 0 {
		t.Errorf("exit code 0 without TLS configuration; output:\n%s", p.out.String())
	}
	if !strings.Contains(p.out.String(), "TLS is required") {
		t.Errorf("the refusal must explain TLS_CERT/TLS_KEY/TLS_DISABLE:\n%s", p.out.String())
	}
	if portOpen(api) {
		t.Error("nothing may listen when the start-up is refused")
	}
}

// #187: the real process exits with the documented status of `state verify` / `state restore`.
func TestStateVerifyProcessExitCodes(t *testing.T) {
	dir := t.TempDir()
	run := func(masterKey string, args ...string) (int, string) {
		cmd := exec.Command(os.Args[0])
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), runMainEnv + "=1", "SECAGENT_TEST_ARGS=" + strings.Join(args, " "), "RSA_MASTER_KEY=" + masterKey}
		out, err := cmd.CombinedOutput()
		return exitCode(err), string(out)
	}
	if code, out := run("process-key", "state", "init", "--state-dir", dir); code != 0 {
		t.Fatalf("init: %d\n%s", code, out)
	}
	state := filepath.Join(dir, "relay.state")
	if code, out := run("process-key", "state", "verify", state); code != 0 || !strings.Contains(out, "verdict: OK") {
		t.Fatalf("verify: %d\n%s", code, out)
	}
	if code, out := run("wrong-key", "state", "verify", state); code != 2 || !strings.Contains(out, "REFUSED") {
		t.Fatalf("wrong key: %d (want 2)\n%s", code, out)
	}
	if code, _ := run("", "state", "verify", state); code != 6 {
		t.Fatalf("no key: %d (want 6)", code)
	}
	if code, _ := run("process-key", "state", "verify", filepath.Join(dir, "absent")); code != 5 {
		t.Fatalf("absent: %d (want 5)", code)
	}
	// restore from itself into the same directory: no lock, authentic source
	if code, out := run("process-key", "state", "restore", "--from", state, "--state-dir", dir); code != 0 || !strings.Contains(out, "state restored") {
		t.Fatalf("restore: %d\n%s", code, out)
	}
}
