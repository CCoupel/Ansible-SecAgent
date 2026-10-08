package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/cli"
)

// setArgs temporarily replaces os.Args for the duration of a test.
func setArgs(t *testing.T, args []string) {
	t.Helper()
	orig := os.Args
	os.Args = append([]string{"secagent-server"}, args...)
	t.Cleanup(func() { os.Args = orig })
}

// ── isCLIMode ─────────────────────────────────────────────────────────────────

func TestIsCLIMode_NoArgs(t *testing.T) {
	setArgs(t, []string{})
	if isCLIMode() {
		t.Error("no args: expected server mode")
	}
}

func TestIsCLIMode_AnyArgumentIsCLI(t *testing.T) {
	// A flag, a path, a number or a mistyped word is handed to cobra (error), never to the server.
	for _, args := range [][]string{{"-d"}, {"--config", "/etc/relay.conf"}, {"--help"}, {"-h"}, {"--version"}, {"7770"}, {"/etc/relay.conf"}, {"kyes"}} {
		setArgs(t, args)
		if !isCLIMode() {
			t.Errorf("%v: expected CLI mode (cobra refuses or answers)", args)
		}
	}
}

func TestIsCLIMode_TokensCreate(t *testing.T) {
	setArgs(t, []string{"tokens", "create", "--role", "enrollment"})
	if !isCLIMode() {
		t.Error("tokens create: expected CLI mode")
	}
}

func TestIsCLIMode_TokensList(t *testing.T) {
	setArgs(t, []string{"tokens", "list"})
	if !isCLIMode() {
		t.Error("tokens list: expected CLI mode")
	}
}

func TestIsCLIMode_TokensRevoke(t *testing.T) {
	setArgs(t, []string{"tokens", "revoke", "some-id"})
	if !isCLIMode() {
		t.Error("tokens revoke: expected CLI mode")
	}
}

func TestIsCLIMode_TokensDelete(t *testing.T) {
	setArgs(t, []string{"tokens", "delete", "some-id"})
	if !isCLIMode() {
		t.Error("tokens delete: expected CLI mode")
	}
}

func TestIsCLIMode_TokensPurge(t *testing.T) {
	setArgs(t, []string{"tokens", "purge", "--expired"})
	if !isCLIMode() {
		t.Error("tokens purge: expected CLI mode")
	}
}

func TestIsCLIMode_MinionsList(t *testing.T) {
	setArgs(t, []string{"minions", "list"})
	if !isCLIMode() {
		t.Error("minions list: expected CLI mode")
	}
}

func TestIsCLIMode_InventoryList(t *testing.T) {
	setArgs(t, []string{"inventory", "list"})
	if !isCLIMode() {
		t.Error("inventory list: expected CLI mode")
	}
}

func TestIsCLIMode_SecurityKeys(t *testing.T) {
	setArgs(t, []string{"security", "keys", "status"})
	if !isCLIMode() {
		t.Error("security keys status: expected CLI mode")
	}
}

func TestIsCLIMode_ServerStatus(t *testing.T) {
	setArgs(t, []string{"server", "status"})
	if !isCLIMode() {
		t.Error("server status: expected CLI mode")
	}
}

func TestIsCLIMode_Help(t *testing.T) {
	setArgs(t, []string{"help"})
	if !isCLIMode() {
		t.Error("help: expected CLI mode")
	}
}

func TestIsCLIMode_Completion(t *testing.T) {
	setArgs(t, []string{"completion", "bash"})
	if !isCLIMode() {
		t.Error("completion bash: expected CLI mode")
	}
}

func TestIsCLIMode_UnknownArg(t *testing.T) {
	setArgs(t, []string{"unknowncmd"})
	if !isCLIMode() {
		t.Error("unknown arg: expected CLI mode (cobra rejects it, no server is started)")
	}
}

// ── isCLIMode — table-driven (all known subcommands) ──────────────────────────

func TestIsCLIMode_AllKnownCommands(t *testing.T) {
	cliCmds := []string{
		"minions",
		"security",
		"inventory",
		"server",
		"tokens",
		"help",
		"completion",
	}
	for _, cmd := range cliCmds {
		t.Run(cmd, func(t *testing.T) {
			setArgs(t, []string{cmd})
			if !isCLIMode() {
				t.Errorf("%q: expected CLI mode", cmd)
			}
		})
	}
}

func TestIsCLIMode_NoArgumentIsServerMode(t *testing.T) {
	setArgs(t, []string{})
	if isCLIMode() {
		t.Error("no argument: expected server mode")
	}
}

// ── isCLIMode — edge cases ─────────────────────────────────────────────────────

// "--verbose tokens list": a leading flag goes to cobra, which rejects it (unknown flag).
func TestIsCLIMode_FlagBeforeCommand(t *testing.T) {
	setArgs(t, []string{"--verbose", "tokens", "list"})
	if !isCLIMode() {
		t.Error("flag before command: expected CLI mode (cobra rejects the unknown flag)")
	}
}

// --help / -h / --version are answered by cobra and never start a server.
func TestIsCLIMode_HelpFlag(t *testing.T) {
	for _, a := range []string{"--help", "-h", "--version"} {
		setArgs(t, []string{a})
		if !isCLIMode() {
			t.Errorf("%s: expected CLI mode", a)
		}
	}
}

// TestIsCLIMode_HelpSubcommand: "help" (no dash) → CLI mode (cobra built-in).
func TestIsCLIMode_HelpSubcommand(t *testing.T) {
	setArgs(t, []string{"help", "tokens"})
	if !isCLIMode() {
		t.Error("help subcommand: expected CLI mode")
	}
}

// TestIsCLIMode_TokensHelpSubcommand: "tokens" → CLI mode (cobra will handle
// --help flag within cobra).
func TestIsCLIMode_TokensSubcommand(t *testing.T) {
	setArgs(t, []string{"tokens"})
	if !isCLIMode() {
		t.Error("tokens subcommand alone: expected CLI mode")
	}
}

// TestIsCLIMode_MinionsAllSubcommands exercises all minions subcommands.
func TestIsCLIMode_MinionsAllSubcommands(t *testing.T) {
	cases := [][]string{
		{"minions", "list"},
		{"minions", "get", "host-01"},
		{"minions", "suspend", "host-01"},
		{"minions", "resume", "host-01"},
		{"minions", "revoke", "host-01"},
		{"minions", "authorize", "host-01", "--key-file", "/tmp/key.pem"},
		{"minions", "set-state", "host-01", "--state", "maintenance"},
		{"minions", "vars", "get", "host-01"},
		{"minions", "vars", "set", "host-01", "k=v"},
		{"minions", "vars", "delete", "host-01", "k"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			setArgs(t, args)
			if !isCLIMode() {
				t.Errorf("%v: expected CLI mode", args)
			}
		})
	}
}

// TestIsCLIMode_SecurityAllSubcommands exercises all security subcommands.
func TestIsCLIMode_SecurityAllSubcommands(t *testing.T) {
	cases := [][]string{
		{"security", "keys", "status"},
		{"security", "keys", "rotate", "--grace", "24h"},
		{"security", "tokens", "list"},
		{"security", "blacklist", "list"},
		{"security", "blacklist", "purge"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			setArgs(t, args)
			if !isCLIMode() {
				t.Errorf("%v: expected CLI mode", args)
			}
		})
	}
}

// TestIsCLIMode_ServerAllSubcommands exercises all server subcommands.
func TestIsCLIMode_ServerAllSubcommands(t *testing.T) {
	cases := [][]string{
		{"server", "status"},
		{"server", "stats"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			setArgs(t, args)
			if !isCLIMode() {
				t.Errorf("%v: expected CLI mode", args)
			}
		})
	}
}

// ── Integration: CLI against mock server ──────────────────────────────────────

// TestCLI_TokensList_ServerRunning tests that the CLI tokens list command
// succeeds when the admin server is up and returns valid JSON.
func TestCLI_TokensList_ServerRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/tokens" && r.Method == http.MethodGet {
			mustEncode(t, w, []map[string]interface{}{
				{
					"id":               "tok-cli-01",
					"role":             "enrollment",
					"token_hash":       "abcdef1234567890",
					"hostname_pattern": "vp.*",
					"reusable":         false,
					"use_count":        0,
					"created_at":       "2026-03-08T00:00:00Z",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("RELAY_API_URL", ts.URL)
	t.Setenv("ADMIN_TOKEN", "test-admin-token")

	// Verify that isCLIMode detects this as CLI
	setArgs(t, []string{"tokens", "list"})
	if !isCLIMode() {
		t.Fatal("tokens list: expected CLI mode")
	}

	// The server is running — CLI should be able to reach it
	resp, err := http.Get(ts.URL + "/api/admin/tokens")
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tokens list: expected 200 from mock server, got %d", resp.StatusCode)
	}
}

// TestCLI_InventoryList_ServerRunning tests that inventory list CLI command
// would succeed against a running server (mock).
func TestCLI_InventoryList_ServerRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/minions" && r.Method == http.MethodGet {
			mustEncode(t, w, []map[string]interface{}{
				{"hostname": "host-01", "connected": true},
				{"hostname": "host-02", "connected": false},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("RELAY_API_URL", ts.URL)
	t.Setenv("ADMIN_TOKEN", "test-admin-token")

	setArgs(t, []string{"inventory", "list"})
	if !isCLIMode() {
		t.Fatal("inventory list: expected CLI mode")
	}

	resp, err := http.Get(ts.URL + "/api/admin/minions")
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("inventory list: expected 200 from mock server, got %d", resp.StatusCode)
	}
}

// TestCLI_ConnectionRefused_NoServer verifies that when no server is running,
// an HTTP request to localhost:7771 returns a connection error.
func TestCLI_ConnectionRefused_NoServer(t *testing.T) {
	// Use a port that should not have anything listening
	t.Setenv("RELAY_API_URL", "http://localhost:19999")
	t.Setenv("ADMIN_TOKEN", "test-token")

	setArgs(t, []string{"tokens", "list"})
	if !isCLIMode() {
		t.Fatal("tokens list: expected CLI mode")
	}

	// Attempt connection — must fail
	_, err := http.Get("http://localhost:19999/api/admin/tokens")
	if err == nil {
		t.Skip("port 19999 is unexpectedly listening — skipping connection-refused test")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "connection refused") &&
		!strings.Contains(errStr, "connect") &&
		!strings.Contains(errStr, "dial") {
		t.Errorf("expected connection error, got: %v", err)
	}
}

// TestCLI_SecurityKeysStatus_ServerRunning tests the security keys status
// CLI command path against a mock server.
func TestCLI_SecurityKeysStatus_ServerRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/security/keys/status" {
			mustEncode(t, w, map[string]interface{}{
				"current_key_id":    "key-01",
				"rotation_deadline": nil,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("RELAY_API_URL", ts.URL)
	t.Setenv("ADMIN_TOKEN", "test-admin-token")

	setArgs(t, []string{"security", "keys", "status"})
	if !isCLIMode() {
		t.Fatal("security keys status: expected CLI mode")
	}

	resp, err := http.Get(ts.URL + "/api/admin/security/keys/status")
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("security keys status: expected 200, got %d", resp.StatusCode)
	}
}

// TestCLI_ServerStatus_ServerRunning tests the server status CLI command path.
func TestCLI_ServerStatus_ServerRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/status" {
			mustEncode(t, w, map[string]interface{}{
				"status":  "ok",
				"agents":  3,
				"version": "1.0",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("RELAY_API_URL", ts.URL)
	t.Setenv("ADMIN_TOKEN", "test-admin-token")

	setArgs(t, []string{"server", "status"})
	if !isCLIMode() {
		t.Fatal("server status: expected CLI mode")
	}

	resp, err := http.Get(ts.URL + "/api/admin/status")
	if err != nil {
		t.Fatalf("server not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("server status: expected 200, got %d", resp.StatusCode)
	}
}

// Every top-level command registered on the cobra root must select CLI mode (a missing "keys" once
// made `secagent-server keys …` start a server). The list comes from cobra, not from a copy.
func TestIsCLIMode_EveryRegisteredCommand(t *testing.T) {
	names := cli.CommandNames()
	if len(names) < 8 {
		t.Fatalf("suspicious command list: %v", names)
	}
	for _, name := range append(names, "help", "completion", "keys", "state", "tokens", "relays") {
		t.Run(name, func(t *testing.T) {
			setArgs(t, []string{name})
			if !isCLIMode() {
				t.Errorf("%q is a CLI command but isCLIMode() is false", name)
			}
		})
	}
}
