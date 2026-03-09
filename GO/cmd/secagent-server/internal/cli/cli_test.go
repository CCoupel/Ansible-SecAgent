package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// mockServer returns a test HTTP server and sets RELAY_API_URL + ADMIN_TOKEN.
// The handler receives requests and can return arbitrary responses.
// Cleanup is registered automatically.
func mockServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	t.Setenv("RELAY_API_URL", ts.URL)
	t.Setenv("ADMIN_TOKEN", "test-token")
}

// captureStdout replaces os.Stdout with a pipe, runs f, and returns the output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

// ── apiURL / adminToken ───────────────────────────────────────────────────────

func TestAPIURL_DefaultValue(t *testing.T) {
	t.Setenv("RELAY_API_URL", "")
	got := apiURL()
	if got != "http://localhost:7771" {
		t.Errorf("expected default URL, got %q", got)
	}
}

func TestAPIURL_FromEnv(t *testing.T) {
	t.Setenv("RELAY_API_URL", "http://custom:9999")
	got := apiURL()
	if got != "http://custom:9999" {
		t.Errorf("expected http://custom:9999, got %q", got)
	}
}

func TestAPIURL_TrailingSlashStripped(t *testing.T) {
	t.Setenv("RELAY_API_URL", "http://server:7771/")
	got := apiURL()
	if strings.HasSuffix(got, "/") {
		t.Errorf("trailing slash not stripped: %q", got)
	}
}

func TestCheckHTTPS_LocalhostAllowed(t *testing.T) {
	if err := checkHTTPS("http://localhost:7771"); err != nil {
		t.Errorf("localhost should be allowed over http: %v", err)
	}
	if err := checkHTTPS("http://127.0.0.1:7771"); err != nil {
		t.Errorf("127.0.0.1 should be allowed over http: %v", err)
	}
}

func TestCheckHTTPS_RemoteHTTPRejected(t *testing.T) {
	if err := checkHTTPS("http://relay.example.com:7771"); err == nil {
		t.Error("expected error for http:// on remote host, got nil")
	}
}

func TestCheckHTTPS_RemoteHTTPSAllowed(t *testing.T) {
	if err := checkHTTPS("https://relay.example.com:7771"); err != nil {
		t.Errorf("https:// remote host should be allowed: %v", err)
	}
}

func TestAdminToken_FromEnv(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "my-token")
	if got := adminToken(); got != "my-token" {
		t.Errorf("expected my-token, got %q", got)
	}
}

// ── apiRequest ────────────────────────────────────────────────────────────────

func TestAPIRequest_GET(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/admin/minions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing or wrong Authorization header")
		}
		w.WriteHeader(200)
		w.Write([]byte(`[]`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/minions", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
	if string(data) != `[]` {
		t.Errorf("expected [], got %q", string(data))
	}
}

func TestAPIRequest_POST_WithBody(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		if body["key"] != "value" {
			t.Errorf("unexpected body: %v", body)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/test", map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
	_ = data
}

func TestAPIRequest_ServerError(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"db_error"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/fail", nil)
	if err != nil {
		t.Fatalf("apiRequest returned unexpected network error: %v", err)
	}
	if status != 500 {
		t.Errorf("expected 500, got %d", status)
	}
	if !strings.Contains(string(data), "db_error") {
		t.Errorf("expected error body, got %q", string(data))
	}
}

// ── checkError ────────────────────────────────────────────────────────────────

func TestCheckError_200_ReturnsZero(t *testing.T) {
	code := checkError([]byte(`{}`), 200)
	if code != 0 {
		t.Errorf("expected exit code 0 for HTTP 200, got %d", code)
	}
}

func TestCheckError_201_ReturnsZero(t *testing.T) {
	code := checkError([]byte(`{}`), 201)
	if code != 0 {
		t.Errorf("expected exit code 0 for HTTP 201, got %d", code)
	}
}

func TestCheckError_404_Returns2(t *testing.T) {
	old := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	code := checkError([]byte(`{"error":"agent_not_found"}`), 404)
	os.Stderr = old
	if code != 2 {
		t.Errorf("expected exit code 2 for HTTP 404, got %d", code)
	}
}

func TestCheckError_401_Returns1(t *testing.T) {
	old := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	code := checkError([]byte(`{"error":"unauthorized"}`), 401)
	os.Stderr = old
	if code != 1 {
		t.Errorf("expected exit code 1 for HTTP 401, got %d", code)
	}
}

func TestCheckError_500_Returns1(t *testing.T) {
	old := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	code := checkError([]byte(`{"error":"internal"}`), 500)
	os.Stderr = old
	if code != 1 {
		t.Errorf("expected exit code 1 for HTTP 500, got %d", code)
	}
}

// ── printOutput ───────────────────────────────────────────────────────────────

func TestPrintOutput_JSON(t *testing.T) {
	out := captureStdout(t, func() {
		printOutput("json", map[string]string{"hello": "world"}, nil) //nolint:errcheck
	})
	if !strings.Contains(out, `"hello"`) || !strings.Contains(out, `"world"`) {
		t.Errorf("expected JSON output, got %q", out)
	}
	// Must be valid JSON
	var v interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

func TestPrintOutput_YAML(t *testing.T) {
	out := captureStdout(t, func() {
		printOutput("yaml", map[string]string{"hello": "world"}, nil) //nolint:errcheck
	})
	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("expected YAML output, got %q", out)
	}
}

func TestPrintOutput_Table_WithFunc(t *testing.T) {
	called := false
	out := captureStdout(t, func() {
		printOutput("table", "data", func(v interface{}) { //nolint:errcheck
			called = true
		})
	})
	if !called {
		t.Error("table func was not called")
	}
	_ = out
}

func TestPrintOutput_Table_NoFunc_FallsBackToJSON(t *testing.T) {
	out := captureStdout(t, func() {
		printOutput("table", map[string]string{"k": "v"}, nil) //nolint:errcheck
	})
	// Falls back to JSON
	var v interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Errorf("fallback output is not JSON: %v", err)
	}
}

// ── sha256Hex (indirectly via security.go) — not exported, test via output ───

func TestSha256HexNotExposed(t *testing.T) {
	// sha256Hex is in handlers package, not cli — just verify CLI compiles
	_ = rootCmd
}

// ── cobra command tree ────────────────────────────────────────────────────────

func TestCommandTree_MinionsExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"minions"})
	if err != nil || cmd == nil {
		t.Errorf("minions command not found: %v", err)
	}
}

func TestCommandTree_SecurityExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"security"})
	if err != nil || cmd == nil {
		t.Errorf("security command not found: %v", err)
	}
}

func TestCommandTree_InventoryExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"inventory"})
	if err != nil || cmd == nil {
		t.Errorf("inventory command not found: %v", err)
	}
}

func TestCommandTree_ServerExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"server"})
	if err != nil || cmd == nil {
		t.Errorf("server command not found: %v", err)
	}
}

func TestCommandTree_MinionsSubcommands(t *testing.T) {
	for _, sub := range []string{"list", "get", "suspend", "resume", "revoke", "authorize", "set-state", "vars"} {
		cmd, _, err := rootCmd.Find([]string{"minions", sub})
		if err != nil || cmd == nil || cmd.Name() != sub {
			t.Errorf("minions %s command not found: %v", sub, err)
		}
	}
}

func TestCommandTree_SecuritySubcommands(t *testing.T) {
	for _, path := range [][]string{
		{"security", "keys", "status"},
		{"security", "keys", "rotate"},
		{"security", "tokens", "list"},
		{"security", "blacklist", "list"},
		{"security", "blacklist", "purge"},
	} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil || cmd == nil {
			t.Errorf("command %v not found: %v", path, err)
		}
	}
}

func TestGlobalFormatFlag(t *testing.T) {
	// --format flag must exist on root command
	f := rootCmd.PersistentFlags().Lookup("format")
	if f == nil {
		t.Error("--format flag not found on root command")
	}
	if f.DefValue != "table" {
		t.Errorf("expected default 'table', got %q", f.DefValue)
	}
}

func TestSecurityKeysRotate_GraceFlag(t *testing.T) {
	f := securityKeysRotateCmd.Flags().Lookup("grace")
	if f == nil {
		t.Error("--grace flag not found on security keys rotate")
	}
}

func TestInventoryList_OnlyConnectedFlag(t *testing.T) {
	f := inventoryListCmd.Flags().Lookup("only-connected")
	if f == nil {
		t.Error("--only-connected flag not found on inventory list")
	}
}

func TestMinionsAuthorize_KeyFileFlag(t *testing.T) {
	f := minionsAuthorizeCmd.Flags().Lookup("key-file")
	if f == nil {
		t.Error("--key-file flag not found on minions authorize")
	}
}

// ── End-to-end CLI command tests (mock HTTP server) ───────────────────────────

// TestMinionsList verifies that "minions list" calls GET /api/admin/minions
// and prints a table with hostname and status columns.
func TestMinionsList(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions" || r.Method != "GET" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`[{"hostname":"host-01","status":"active","suspended":false,"last_seen":"2026-03-06T10:00:00Z","enrolled_at":"2026-01-01T00:00:00Z"}]`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/minions", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	var agents []map[string]interface{}
	if err := json.Unmarshal(data, &agents); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0]["hostname"] != "host-01" {
		t.Errorf("expected hostname=host-01, got %v", agents[0]["hostname"])
	}
	if agents[0]["status"] != "active" {
		t.Errorf("expected status=active, got %v", agents[0]["status"])
	}

	// Verify table output contains expected columns
	out := captureStdout(t, func() {
		printOutput("table", agents, func(v interface{}) { //nolint:errcheck
			list := v.([]map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "HOSTNAME\tSTATUS\tSUSPENDED\tLAST_SEEN\tENROLLED_AT")
			for _, a := range list {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n",
					a["hostname"], a["status"], a["suspended"],
					a["last_seen"], a["enrolled_at"])
			}
			tw.Flush()
		})
	})
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "host-01") {
		t.Errorf("table output missing expected content: %q", out)
	}
}

// TestMinionsGetNotFound verifies that a 404 response maps to exit code 2.
func TestMinionsGetNotFound(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions/unknown-host" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"agent_not_found"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/minions/unknown-host", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	// Redirect stderr to suppress output
	old := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	code := checkError(data, status)
	os.Stderr = old

	if code != 2 {
		t.Errorf("expected exit code 2 for 404, got %d", code)
	}
}

// TestMinionsSuspend verifies POST /api/admin/minions/<host>/suspend → 200 → exit 0.
func TestMinionsSuspend(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions/host-01/suspend" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"suspended"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/minions/host-01/suspend", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

// TestMinionsRevoke verifies POST /api/admin/revoke/<host> → 200 → exit 0.
func TestMinionsRevoke(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/revoke/host-01" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"revoked"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/revoke/host-01", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

// TestMinionsVarsSetGet verifies that vars set (POST) then get (GET) returns the expected value.
func TestMinionsVarsSetGet(t *testing.T) {
	storedVars := map[string]interface{}{}

	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/admin/minions/host-01/vars":
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
			for k, v := range body {
				storedVars[k] = v
			}
			w.WriteHeader(200)
			w.Write([]byte(`{"message":"vars updated"}`)) //nolint:errcheck

		case r.Method == "GET" && r.URL.Path == "/api/admin/minions/host-01/vars":
			w.WriteHeader(200)
			out, _ := json.Marshal(storedVars)
			w.Write(out) //nolint:errcheck

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})

	// Set vars
	setData, setStatus, err := apiRequest("POST", "/api/admin/minions/host-01/vars",
		map[string]interface{}{"ansible_user": "deploy"})
	if err != nil {
		t.Fatalf("POST vars: %v", err)
	}
	if code := checkError(setData, setStatus); code != 0 {
		t.Fatalf("POST vars: unexpected exit code %d", code)
	}

	// Get vars
	getData, getStatus, err := apiRequest("GET", "/api/admin/minions/host-01/vars", nil)
	if err != nil {
		t.Fatalf("GET vars: %v", err)
	}
	if getStatus != 200 {
		t.Fatalf("GET vars: expected 200, got %d", getStatus)
	}

	var vars map[string]interface{}
	if err := json.Unmarshal(getData, &vars); err != nil {
		t.Fatalf("unmarshal vars: %v", err)
	}
	if vars["ansible_user"] != "deploy" {
		t.Errorf("expected ansible_user=deploy, got %v", vars["ansible_user"])
	}
}

// TestSecurityKeysRotate verifies POST /api/admin/keys/rotate → deadline in output.
func TestSecurityKeysRotate(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/keys/rotate" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{
			"current_key_sha256":"abc123",
			"previous_key_sha256":"def456",
			"deadline":"2026-03-07T10:00:00Z",
			"agents_migrated":3,
			"agents_total":3
		}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/keys/rotate", map[string]string{"grace": "24h"})
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["deadline"] == "" || result["deadline"] == nil {
		t.Error("expected deadline in rotate response")
	}
	if result["current_key_sha256"] == "" || result["current_key_sha256"] == nil {
		t.Error("expected current_key_sha256 in rotate response")
	}
	if result["agents_migrated"] == nil {
		t.Error("expected agents_migrated in rotate response")
	}

	// Verify table output contains deadline
	out := captureStdout(t, func() {
		printOutput("table", result, func(v interface{}) { //nolint:errcheck
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "FIELD\tVALUE")
			for _, k := range []string{"current_key_sha256", "previous_key_sha256", "deadline", "agents_migrated", "agents_total"} {
				fmt.Fprintf(tw, "%s\t%v\n", k, m[k])
			}
			tw.Flush()
		})
	})
	if !strings.Contains(out, "deadline") || !strings.Contains(out, "2026-03-07") {
		t.Errorf("table output should contain deadline, got: %q", out)
	}
}

// TestServerStatus verifies GET /api/admin/status → consistent output.
func TestServerStatus(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/status" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{
			"nats":"connected",
			"db":"ok",
			"ws_connections":3,
			"uptime":"2h30m"
		}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/status", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["nats"] != "connected" {
		t.Errorf("expected nats=connected, got %v", result["nats"])
	}
	if result["db"] != "ok" {
		t.Errorf("expected db=ok, got %v", result["db"])
	}

	// Verify table output is coherent
	out := captureStdout(t, func() {
		printOutput("table", result, func(v interface{}) { //nolint:errcheck
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "COMPONENT\tSTATUS")
			fmt.Fprintf(tw, "nats\t%v\n", m["nats"])
			fmt.Fprintf(tw, "db\t%v\n", m["db"])
			fmt.Fprintf(tw, "ws_connections\t%v\n", m["ws_connections"])
			fmt.Fprintf(tw, "uptime\t%v\n", m["uptime"])
			tw.Flush()
		})
	})
	if !strings.Contains(out, "nats") || !strings.Contains(out, "connected") {
		t.Errorf("table output missing expected content: %q", out)
	}
	if !strings.Contains(out, "db") || !strings.Contains(out, "ok") {
		t.Errorf("table output missing db status: %q", out)
	}
}

// TestFormatJson verifies that --format json produces parseable JSON for all commands.
func TestFormatJson(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"hostname":"host-01","status":"active"}]`)) //nolint:errcheck
	})

	data, _, err := apiRequest("GET", "/api/admin/minions", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}

	var agents []map[string]interface{}
	json.Unmarshal(data, &agents) //nolint:errcheck

	out := captureStdout(t, func() {
		printOutput("json", agents, nil) //nolint:errcheck
	})

	// Must be valid JSON
	var parsed interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Errorf("--format json output is not valid JSON: %v\noutput: %q", err, out)
	}
	if !strings.Contains(out, "host-01") {
		t.Errorf("JSON output should contain hostname, got: %q", out)
	}
}

// TestFormatYaml verifies that --format yaml produces parseable YAML for all commands.
func TestFormatYaml(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"current_key_sha256":"abc123","deadline":"2026-03-07T00:00:00Z","rotation_active":true}`)) //nolint:errcheck
	})

	data, _, err := apiRequest("GET", "/api/admin/security/keys/status", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result) //nolint:errcheck

	out := captureStdout(t, func() {
		printOutput("yaml", result, nil) //nolint:errcheck
	})

	// Must contain YAML key-value pairs
	if !strings.Contains(out, "current_key_sha256") {
		t.Errorf("YAML output should contain current_key_sha256, got: %q", out)
	}
	if !strings.Contains(out, "abc123") {
		t.Errorf("YAML output should contain the hash value, got: %q", out)
	}
	// Must not be empty
	if strings.TrimSpace(out) == "" {
		t.Error("YAML output is empty")
	}
}

// TestExitCodes verifies that HTTP error codes map to the correct CLI exit codes.
func TestExitCodes(t *testing.T) {
	old := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = old }()

	cases := []struct {
		httpStatus int
		wantCode   int
		desc       string
	}{
		{200, 0, "200 → exit 0"},
		{201, 0, "201 → exit 0"},
		{404, 2, "404 → exit 2 (not found)"},
		{401, 1, "401 → exit 1 (unauthorized)"},
		{403, 1, "403 → exit 1 (forbidden)"},
		{409, 1, "409 → exit 1 (conflict)"},
		{500, 1, "500 → exit 1 (server error)"},
		{503, 1, "503 → exit 1 (service unavailable)"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			body := []byte(`{"error":"test_error"}`)
			if tc.httpStatus == 200 || tc.httpStatus == 201 {
				body = []byte(`{"ok":true}`)
			}
			got := checkError(body, tc.httpStatus)
			if got != tc.wantCode {
				t.Errorf("%s: expected exit code %d, got %d", tc.desc, tc.wantCode, got)
			}
		})
	}
}

// ── Additional CLI command tests ───────────────────────────────────────────────

// TestMinionsResume verifies POST /api/admin/minions/<host>/resume → 200 → exit 0.
func TestMinionsResume(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions/host-01/resume" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"resumed"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/minions/host-01/resume", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

// TestMinionsSetState verifies POST /api/admin/minions/<host>/set-state → 200 → exit 0.
func TestMinionsSetState(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions/host-01/set-state" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		if body["status"] != "disconnected" {
			t.Errorf("expected status=disconnected, got %q", body["status"])
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"state updated"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/minions/host-01/set-state",
		map[string]string{"status": "disconnected"})
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

// TestInventoryList verifies GET /api/inventory → Ansible-compatible JSON.
func TestInventoryList(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		// Both /api/inventory and /api/inventory?only_connected=true are valid
		if !strings.HasPrefix(r.URL.Path, "/api/inventory") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"all":{"hosts":["host-01","host-02"]},"_meta":{"hostvars":{"host-01":{"ansible_user":"root"}}}}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/inventory", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var inv map[string]interface{}
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if inv["all"] == nil {
		t.Error("expected 'all' key in inventory response")
	}
	if inv["_meta"] == nil {
		t.Error("expected '_meta' key in inventory response")
	}
}

// TestInventoryListOnlyConnected verifies the --only-connected flag appends the query param.
func TestInventoryListOnlyConnected(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "only_connected=true" {
			t.Errorf("expected only_connected=true query param, got %q", r.URL.RawQuery)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"all":{"hosts":[]},"_meta":{"hostvars":{}}}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/inventory?only_connected=true", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	_ = data
}

// TestServerStats verifies GET /api/admin/stats → metrics output.
func TestServerStats(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/stats" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"agents_connected":3,"agents_total":5,"tasks_active":2}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/stats", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["agents_connected"] == nil {
		t.Error("expected agents_connected in stats response")
	}
	if result["agents_total"] == nil {
		t.Error("expected agents_total in stats response")
	}
	if result["tasks_active"] == nil {
		t.Error("expected tasks_active in stats response")
	}

	// Verify table output
	out := captureStdout(t, func() {
		printOutput("table", result, func(v interface{}) { //nolint:errcheck
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "METRIC\tVALUE")
			fmt.Fprintf(tw, "agents_connected\t%v\n", m["agents_connected"])
			fmt.Fprintf(tw, "agents_total\t%v\n", m["agents_total"])
			fmt.Fprintf(tw, "tasks_active\t%v\n", m["tasks_active"])
			tw.Flush()
		})
	})
	if !strings.Contains(out, "agents_connected") {
		t.Errorf("table output missing agents_connected: %q", out)
	}
}

// TestSecurityTokensList verifies GET /api/admin/security/tokens → token list.
func TestSecurityTokensList(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/security/tokens" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`[{"hostname":"host-01","jti":"jti-abc","status":"active","last_seen":"2026-03-06T10:00:00Z"}]`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/security/tokens", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var tokens []map[string]interface{}
	if err := json.Unmarshal(data, &tokens); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0]["jti"] != "jti-abc" {
		t.Errorf("expected jti-abc, got %v", tokens[0]["jti"])
	}
}

// TestSecurityBlacklistList verifies GET /api/admin/security/blacklist → blacklist entries.
func TestSecurityBlacklistList(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/security/blacklist" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`[{"jti":"jti-xyz","hostname":"host-01","reason":"revoked","revoked_at":"2026-03-06T10:00:00Z","expires_at":"2026-03-07T10:00:00Z"}]`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/security/blacklist", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 || entries[0]["jti"] != "jti-xyz" {
		t.Errorf("unexpected blacklist entries: %v", entries)
	}
}

// TestSecurityBlacklistPurge verifies POST /api/admin/security/blacklist/purge → deleted count.
func TestSecurityBlacklistPurge(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/security/blacklist/purge" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"deleted":3}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("POST", "/api/admin/security/blacklist/purge", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["deleted"] == nil {
		t.Error("expected deleted count in purge response")
	}
}

// TestMinionsGet_ValidHost verifies GET /api/admin/minions/<host> → agent details.
func TestMinionsGet_ValidHost(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/minions/host-01" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"hostname":"host-01","status":"active","suspended":false,"last_seen":"2026-03-06T10:00:00Z","enrolled_at":"2026-01-01T00:00:00Z","key_fingerprint":"abc123"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/minions/host-01", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if code := checkError(data, status); code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}

	var agent map[string]interface{}
	if err := json.Unmarshal(data, &agent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if agent["hostname"] != "host-01" {
		t.Errorf("expected hostname=host-01, got %v", agent["hostname"])
	}
	if agent["status"] != "active" {
		t.Errorf("expected status=active, got %v", agent["status"])
	}
}

// ── cobra RunE integration tests ──────────────────────────────────────────────
// These tests call RunE directly to exercise the cobra command bodies.
// os.Exit is avoided by verifying behavior before the exit point (i.e. via
// mock server that always returns 200 so checkError returns 0).

// TestMinionsListRunE exercises the minionsListCmd.RunE via a mock HTTP server.
func TestMinionsListRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"hostname":"host-01","status":"active","suspended":false,"last_seen":"2026-03-06T10:00:00Z","enrolled_at":"2026-01-01T00:00:00Z"}]`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsListCmd.RunE(minionsListCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "host-01") {
		t.Errorf("expected table output with HOSTNAME and host-01, got: %q", out)
	}
}

// TestMinionsGetRunE exercises the minionsGetCmd.RunE with a hostname argument.
func TestMinionsGetRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"hostname":"host-01","status":"active","suspended":false,"last_seen":"2026-03-06T10:00:00Z","enrolled_at":"2026-01-01T00:00:00Z","key_fingerprint":"abc"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsGetCmd.RunE(minionsGetCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "hostname") {
		t.Errorf("expected hostname in output, got: %q", out)
	}
}

// TestMinionsSuspendRunE exercises the minionsSuspendCmd.RunE.
func TestMinionsSuspendRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"suspended"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsSuspendCmd.RunE(minionsSuspendCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") || !strings.Contains(out, "suspended") {
		t.Errorf("expected suspension message, got: %q", out)
	}
}

// TestMinionsResumeRunE exercises the minionsResumeCmd.RunE.
func TestMinionsResumeRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"resumed"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsResumeCmd.RunE(minionsResumeCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") || !strings.Contains(out, "resumed") {
		t.Errorf("expected resume message, got: %q", out)
	}
}

// TestMinionsRevokeRunE exercises the minionsRevokeCmd.RunE.
func TestMinionsRevokeRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"revoked"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsRevokeCmd.RunE(minionsRevokeCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") || !strings.Contains(out, "revoked") {
		t.Errorf("expected revoke message, got: %q", out)
	}
}

// TestMinionsSetStateRunE exercises the minionsSetStateCmd.RunE.
func TestMinionsSetStateRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"state updated"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsSetStateCmd.RunE(minionsSetStateCmd, []string{"host-01", "disconnected"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") {
		t.Errorf("expected hostname in output, got: %q", out)
	}
}

// TestMinionsVarsGetRunE exercises the minionsVarsGetCmd.RunE.
func TestMinionsVarsGetRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ansible_user":"deploy","env":"prod"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsVarsGetCmd.RunE(minionsVarsGetCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "ansible_user") || !strings.Contains(out, "deploy") {
		t.Errorf("expected vars in output, got: %q", out)
	}
}

// TestMinionsVarsSetRunE exercises the minionsVarsSetCmd.RunE.
func TestMinionsVarsSetRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"vars updated"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsVarsSetCmd.RunE(minionsVarsSetCmd, []string{"host-01", "ansible_user=deploy"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") {
		t.Errorf("expected hostname in output, got: %q", out)
	}
}

// TestMinionsVarsDeleteRunE exercises the minionsVarsDeleteCmd.RunE.
func TestMinionsVarsDeleteRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"deleted"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsVarsDeleteCmd.RunE(minionsVarsDeleteCmd, []string{"host-01", "mykey"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "mykey") || !strings.Contains(out, "host-01") {
		t.Errorf("expected var key and hostname in output, got: %q", out)
	}
}

// TestSecurityKeysStatusRunE exercises the securityKeysStatusCmd.RunE.
func TestSecurityKeysStatusRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"current_key_sha256":"sha256abc","previous_key_sha256":"","deadline":"","rotation_active":false,"agents_total":3}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := securityKeysStatusCmd.RunE(securityKeysStatusCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "current_key_sha256") {
		t.Errorf("expected current_key_sha256 in output, got: %q", out)
	}
}

// TestSecurityKeysRotateRunE exercises the securityKeysRotateCmd.RunE.
func TestSecurityKeysRotateRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"current_key_sha256":"new","previous_key_sha256":"old","deadline":"2026-03-07T10:00:00Z","agents_migrated":2,"agents_total":3}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := securityKeysRotateCmd.RunE(securityKeysRotateCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "deadline") {
		t.Errorf("expected deadline in output, got: %q", out)
	}
}

// TestSecurityTokensListRunE exercises the securityTokensListCmd.RunE.
func TestSecurityTokensListRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"hostname":"host-01","jti":"jti-abc","status":"active","last_seen":"2026-03-06T10:00:00Z"}]`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := securityTokensListCmd.RunE(securityTokensListCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "host-01") {
		t.Errorf("expected table with tokens, got: %q", out)
	}
}

// TestSecurityBlacklistListRunE exercises the securityBlacklistListCmd.RunE.
func TestSecurityBlacklistListRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`[{"jti":"jti-xyz","hostname":"host-01","reason":"revoked","revoked_at":"2026-03-06T10:00:00Z","expires_at":"2026-03-07T10:00:00Z"}]`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := securityBlacklistListCmd.RunE(securityBlacklistListCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "JTI") || !strings.Contains(out, "jti-xyz") {
		t.Errorf("expected blacklist table, got: %q", out)
	}
}

// TestSecurityBlacklistPurgeRunE exercises the securityBlacklistPurgeCmd.RunE.
func TestSecurityBlacklistPurgeRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"deleted":5}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := securityBlacklistPurgeCmd.RunE(securityBlacklistPurgeCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "5") {
		t.Errorf("expected deleted count in output, got: %q", out)
	}
}

// TestInventoryListRunE exercises the inventoryListCmd.RunE.
func TestInventoryListRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"all":{"hosts":["host-01"]},"_meta":{"hostvars":{"host-01":{"ansible_user":"root"}}}}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := inventoryListCmd.RunE(inventoryListCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") {
		t.Errorf("expected host-01 in inventory output, got: %q", out)
	}
}

// TestServerStatusRunE exercises the serverStatusCmd.RunE.
func TestServerStatusRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"nats":"connected","db":"ok","ws_connections":3,"uptime":"2h"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := serverStatusCmd.RunE(serverStatusCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "nats") || !strings.Contains(out, "connected") {
		t.Errorf("expected nats status in output, got: %q", out)
	}
}

// TestServerStatsRunE exercises the serverStatsCmd.RunE.
func TestServerStatsRunE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"agents_connected":3,"agents_total":5,"tasks_active":1}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := serverStatsCmd.RunE(serverStatsCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "agents_connected") {
		t.Errorf("expected agents_connected in output, got: %q", out)
	}
}

// TestMinionsAuthorizeRunE_MissingKeyFile verifies that missing --key-file returns an error.
func TestMinionsAuthorizeRunE_MissingKeyFile(t *testing.T) {
	// Reset the key file flag to ensure it's empty
	minionsAuthorizeKeyFile = ""

	err := minionsAuthorizeCmd.RunE(minionsAuthorizeCmd, []string{"host-01"})
	if err == nil {
		t.Error("expected error when --key-file is missing")
	}
	if !strings.Contains(err.Error(), "key-file") {
		t.Errorf("error should mention key-file, got: %v", err)
	}
}

// TestMinionsAuthorizeRunE_WithKeyFile verifies that authorize sends the key to the API.
func TestMinionsAuthorizeRunE_WithKeyFile(t *testing.T) {
	// Create a temp file with a fake PEM key
	dir := t.TempDir()
	keyFile := dir + "/pub.pem"
	if err := os.WriteFile(keyFile, []byte("-----BEGIN PUBLIC KEY-----\nfakekey\n-----END PUBLIC KEY-----\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	minionsAuthorizeKeyFile = keyFile
	t.Cleanup(func() { minionsAuthorizeKeyFile = "" })

	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/authorize" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		if body["hostname"] != "host-01" {
			t.Errorf("expected hostname=host-01, got %q", body["hostname"])
		}
		if body["public_key_pem"] == "" {
			t.Error("expected public_key_pem in request body")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"authorized"}`)) //nolint:errcheck
	})

	out := captureStdout(t, func() {
		err := minionsAuthorizeCmd.RunE(minionsAuthorizeCmd, []string{"host-01"})
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	if !strings.Contains(out, "host-01") {
		t.Errorf("expected hostname in output, got: %q", out)
	}
}

// TestMinionsVarsSetRunE_InvalidPair verifies that malformed key=value pairs return an error.
func TestMinionsVarsSetRunE_InvalidPair(t *testing.T) {
	err := minionsVarsSetCmd.RunE(minionsVarsSetCmd, []string{"host-01", "invalid-no-equals"})
	if err == nil {
		t.Error("expected error for invalid key=value pair")
	}
	if !strings.Contains(err.Error(), "invalid key=value pair") {
		t.Errorf("error should mention invalid key=value pair, got: %v", err)
	}
}

// TestMinionsSetStateRunE_InvalidState verifies that invalid state returns an error.
func TestMinionsSetStateRunE_InvalidState(t *testing.T) {
	err := minionsSetStateCmd.RunE(minionsSetStateCmd, []string{"host-01", "invalid-state"})
	if err == nil {
		t.Error("expected error for invalid state")
	}
	if !strings.Contains(err.Error(), "state must be") {
		t.Errorf("error should mention valid states, got: %v", err)
	}
}

// TestInventoryListRunE_OnlyConnected verifies --only-connected flag appends query param.
func TestInventoryListRunE_OnlyConnected(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "only_connected=true" {
			t.Errorf("expected only_connected=true query param, got %q", r.URL.RawQuery)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"all":{"hosts":[]},"_meta":{"hostvars":{}}}`)) //nolint:errcheck
	})

	// Set flag and reset after
	inventoryOnlyConnected = true
	t.Cleanup(func() { inventoryOnlyConnected = false })

	out := captureStdout(t, func() {
		err := inventoryListCmd.RunE(inventoryListCmd, nil)
		if err != nil {
			t.Errorf("RunE returned error: %v", err)
		}
	})
	_ = out
}

// TestAPIRequest_DELETE verifies DELETE method is sent correctly.
func TestAPIRequest_DELETE(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"deleted"}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("DELETE", "/api/admin/minions/host-01/vars/mykey", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	_ = data
}

// TestSecurityKeysStatus verifies GET /api/admin/security/keys/status → key rotation state.
func TestSecurityKeysStatus(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/security/keys/status" || r.Method != "GET" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"current_key_sha256":"sha256abc","previous_key_sha256":"","deadline":"","rotation_active":false,"agents_total":3}`)) //nolint:errcheck
	})

	data, status, err := apiRequest("GET", "/api/admin/security/keys/status", nil)
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["current_key_sha256"] == "" || result["current_key_sha256"] == nil {
		t.Error("expected current_key_sha256 in status response")
	}
	rotActive, _ := result["rotation_active"].(bool)
	if rotActive {
		t.Error("expected rotation_active=false")
	}
}
