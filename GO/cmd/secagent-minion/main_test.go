package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-minion/internal/enrollment"
	"secagent-server/cmd/secagent-minion/internal/executor"
	"secagent-server/cmd/secagent-minion/internal/ws"
)

func TestBuildEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		srv, ws string
		want    int // addresses, 0 = error expected
		errHas  string
	}{
		"single values (compatibility)": {"https://h1:7770", "wss://h1:7772/ws/agent", 1, ""},
		"paired lists":                  {"https://h1:7770, https://h2:7770", "wss://h1:7772/ws/agent,wss://h2:7772/ws/agent", 2, ""},
		"different lengths refused":     {"https://h1:7770,https://h2:7770", "wss://h1:7772/ws/agent", 0, "same length"},
		"different lengths (other way)": {"https://h1:7770", "wss://h1:7772/ws/agent,wss://h2:7772/ws/agent", 0, "same length"},
		"duplicate address":             {"https://h1:7770,https://h1:7770", "wss://a/ws/agent,wss://b/ws/agent", 0, "RELAY_SERVER_URL"},
		"empty":                         {"", "wss://a/ws/agent", 0, "RELAY_SERVER_URL"},
		"wrong scheme for the WS list":  {"https://h1:7770", "https://h1:7772/ws/agent", 0, "RELAY_WS_URL"},
		"userinfo refused":              {"https://user:SECRETPW@h1:7770", "wss://h1:7772/ws/agent", 0, "userinfo"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, wsr, err := buildEndpoints(tc.srv, tc.ws)
			if tc.want == 0 {
				if err == nil || !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.errHas)
				}
				if strings.Contains(err.Error(), "SECRETPW") || strings.Contains(err.Error(), "h1:7770") {
					t.Errorf("the error echoes an address: %v", err)
				}
				return
			}
			if err != nil || srv.Len() != tc.want || wsr.Len() != tc.want {
				t.Fatalf("got %v %v err %v", srv, wsr, err)
			}
		})
	}
}

// ── #186: a real minion handler: the task `env` sees none of the minion's secrets ──

func TestHandleExec_RealHandlerHidesTheMinionSecrets(t *testing.T) {
	t.Setenv("RELAY_ENROLLMENT_TOKEN", "REAL-ENROLLMENT-TOKEN")
	t.Setenv("RELAY_JWT_PATH", "/etc/secagent-minion/token.jwt")
	t.Setenv("FOO_TOKEN", "REAL-FOO-SECRET")
	h := &agentHandler{exec: executor.New()}
	var out strings.Builder
	send := func(payload any) error {
		if m, ok := payload.(map[string]any); ok && m["type"] == "result" {
			out.WriteString(fmt.Sprint(m["stdout"]))
		}
		return nil
	}
	if err := h.HandleExec(context.Background(), ws.ExecMsg{BaseMsg: ws.BaseMsg{TaskID: "e1"}, Cmd: "env", Timeout: 10}, send); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Fatal("no result")
	}
	for _, leak := range []string{"REAL-ENROLLMENT-TOKEN", "RELAY_ENROLLMENT_TOKEN", "REAL-FOO-SECRET", "FOO_TOKEN", "RELAY_JWT_PATH"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("the task output contains %q", leak)
		}
	}
}

// ── exit status of the real process after a permanent refusal (#186) ──

const runMainEnv = "SECAGENT_MINION_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A 403 on the enrollment (token invalid, expired or consumed) stops the minion with exit status
// 78, so that systemd's RestartPreventExitStatus=78 does not restart-loop it.
func TestMinionProcess_EnrollmentRefusedExits78(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "id_rsa")
	if err := enrollment.StorePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), runMainEnv + "=1",
		"RELAY_SERVER_URL=" + srv.URL, "RELAY_WS_URL=ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/agent",
		"RELAY_PRIVATE_KEY=" + keyPath, "RELAY_JWT_PATH=" + filepath.Join(dir, "token.jwt"),
		"RELAY_ENROLLMENT_TOKEN=REFUSED-TOKEN", "RELAY_AGENT_HOSTNAME=exit-test", "RELAY_ASYNC_DIR=" + filepath.Join(dir, "async"),
		"RELAY_INSECURE_TLS=true",
	}
	done := make(chan []byte, 1)
	var runErr error
	go func() { out, e := cmd.CombinedOutput(); runErr = e; done <- out }()
	select {
	case out := <-done:
		ee, ok := runErr.(*exec.ExitError)
		if !ok || ee.ExitCode() != 78 {
			t.Fatalf("exit = %v, want status 78\n%s", runErr, out)
		}
		if strings.Contains(string(out), "REFUSED-TOKEN") {
			t.Error("the enrollment token leaked in the output")
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the minion did not stop after a 403")
	}
}
