package integration

// #167: the real secagent-inventory binary against a real node with RELAY_SERVER_URL as a list
// (a dead address first, then the live one), then driven by the real ansible-inventory when present.

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// deadAddress returns an https address nothing listens on.
func deadAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "https://" + addr
}

func runInventoryBinary(t *testing.T, bin string, env []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %s: %v", bin, err)
		}
		code = ee.ExitCode()
	}
	return code, so.String(), se.String()
}

func TestInventoryMultiAddress(t *testing.T) {
	bin := inventoryBinary(t)
	root := startNode(t, nodeSpec{ID: "root"})
	enroll(t, root, "a-multi")
	waitFor(t, "the host is listed", func() bool { return root.hasHost("a-multi") })
	dead := deadAddress(t)
	token := root.pluginToken()
	list := dead + "," + root.apiURL()

	t.Run("dead address then live one", func(t *testing.T) {
		code, out, errOut := runInventoryBinary(t, bin,
			[]string{"RELAY_SERVER_URL=" + list, "RELAY_TOKEN=" + token, "SSL_CERT_FILE=" + certPath}, "--list")
		if code != 0 || !strings.Contains(out, "a-multi") {
			t.Fatalf("exit=%d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
	})
	t.Run("a refusal by the live address is reported as is", func(t *testing.T) {
		code, _, errOut := runInventoryBinary(t, bin,
			[]string{"RELAY_SERVER_URL=" + list, "RELAY_TOKEN=wrong-token-value", "SSL_CERT_FILE=" + certPath}, "--list")
		if code == 0 || !strings.Contains(errOut, "server returned 403") || strings.Contains(errOut, "wrong-token-value") {
			t.Fatalf("exit=%d stderr=%q", code, errOut)
		}
	})
	t.Run("all addresses dead", func(t *testing.T) {
		code, _, errOut := runInventoryBinary(t, bin,
			[]string{"RELAY_SERVER_URL=" + dead + "," + deadAddress(t), "RELAY_TOKEN=" + token, "SSL_CERT_FILE=" + certPath}, "--list")
		if code == 0 || !strings.Contains(errOut, "2 address(es) tried") || strings.Contains(errOut, token) {
			t.Fatalf("exit=%d stderr=%q", code, errOut)
		}
	})
	t.Run("ansible-inventory", func(t *testing.T) {
		tool := ansibleInventoryTool(t)
		res := runAnsible(t, tool, bin, []string{"RELAY_SERVER_URL=" + list, "RELAY_TOKEN=" + token, "SSL_CERT_FILE=" + certPath}, "--list")
		if p := parseProblems(res); len(p) > 0 || !strings.Contains(res.Stdout, "a-multi") {
			t.Fatalf("ansible did not accept the inventory: %v\nstderr:\n%s\nstdout:\n%s", p, res.Stderr, res.Stdout)
		}
	})
}
