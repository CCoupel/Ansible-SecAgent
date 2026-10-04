package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// serverInventoryResponse simulates what the relay server returns
var serverInventoryResponse = `{
  "all": {
    "hosts": ["host-a", "host-b"]
  },
  "_meta": {
    "hostvars": {
      "host-a": {
        "ansible_connection": "relay",
        "ansible_host": "host-a",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-05T10:00:00Z"
      },
      "host-b": {
        "ansible_connection": "relay",
        "ansible_host": "host-b",
        "secagent_status": "connected",
        "secagent_last_seen": "2026-03-05T10:01:00Z"
      }
    }
  }
}`

// newTestServer creates a mock relay server for tests
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// ========================================================================
// fetchInventory
// ========================================================================

func TestFetchInventorySuccess(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/inventory" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	cfg := config{
		serverURL: srv.URL,
		insecure:  true,
	}

	inv, err := fetchInventory(cfg)
	if err != nil {
		t.Fatalf("fetchInventory: %v", err)
	}

	if len(inv.All.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(inv.All.Hosts))
	}
	if _, ok := inv.Meta.Hostvars["host-a"]; !ok {
		t.Error("missing hostvars for host-a")
	}
}

func TestFetchInventoryOnlyConnected(t *testing.T) {
	querySeen := ""
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		querySeen = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	cfg := config{
		serverURL:     srv.URL,
		insecure:      true,
		onlyConnected: true,
	}

	_, err := fetchInventory(cfg)
	if err != nil {
		t.Fatalf("fetchInventory: %v", err)
	}

	if querySeen != "only_connected=true" {
		t.Errorf("expected only_connected=true query, got %q", querySeen)
	}
}

func TestFetchInventoryWithToken(t *testing.T) {
	authSeen := ""
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		authSeen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	cfg := config{
		serverURL: srv.URL,
		token:     "mysecrettoken",
		insecure:  true,
	}

	_, err := fetchInventory(cfg)
	if err != nil {
		t.Fatalf("fetchInventory: %v", err)
	}

	if authSeen != "Bearer mysecrettoken" {
		t.Errorf("expected Bearer token header, got %q", authSeen)
	}
}

func TestFetchInventoryHTTPError(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":"missing_authorization"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	cfg := config{
		serverURL: srv.URL,
		insecure:  true,
	}

	_, err := fetchInventory(cfg)
	if err == nil {
		t.Error("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention 401: %v", err)
	}
}

func TestFetchInventoryInvalidJSON(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("not valid json")); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	cfg := config{serverURL: srv.URL, insecure: true}

	_, err := fetchInventory(cfg)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFetchInventoryServerUnreachable(t *testing.T) {
	cfg := config{
		serverURL: "http://127.0.0.1:1", // port 1 est toujours refusé
		insecure:  true,
	}

	_, err := fetchInventory(cfg)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

// ========================================================================
// cmdList
// ========================================================================

func TestCmdListOutput(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	// Capture stdout
	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	cfg := config{serverURL: srv.URL, insecure: true}
	err := cmdList(cfg)

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stdout = old

	if err != nil {
		t.Fatalf("cmdList: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := pr.Read(buf)
	output := string(buf[:n])

	// Valider que c'est du JSON valide avec les champs attendus
	var result AnsibleInventory
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("cmdList output is not valid JSON: %v\nOutput: %s", err, output)
	}

	if len(result.All.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(result.All.Hosts))
	}
	if result.Meta.Hostvars == nil {
		t.Error("_meta.hostvars is nil")
	}
}

func TestCmdListEmptyInventory(t *testing.T) {
	emptyResp := `{"all": {"hosts": []}, "_meta": {"hostvars": {}}}`
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(emptyResp)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	cfg := config{serverURL: srv.URL, insecure: true}
	err := cmdList(cfg)

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stdout = old

	if err != nil {
		t.Fatalf("cmdList empty: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := pr.Read(buf)
	output := string(buf[:n])

	var result AnsibleInventory
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("cmdList empty output is not valid JSON: %v", err)
	}
	// Doit avoir un tableau vide (pas null) pour hosts
	if result.All.Hosts == nil {
		t.Error("hosts should be [] not null")
	}
}

// ========================================================================
// cmdHost
// ========================================================================

func TestCmdHostFound(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	cfg := config{serverURL: srv.URL, insecure: true}
	err := cmdHost(cfg, "host-a")

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stdout = old

	if err != nil {
		t.Fatalf("cmdHost: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := pr.Read(buf)
	output := string(buf[:n])

	var vars map[string]any
	if err := json.Unmarshal([]byte(output), &vars); err != nil {
		t.Fatalf("cmdHost output is not valid JSON: %v\nOutput: %s", err, output)
	}
	if vars["ansible_host"] != "host-a" {
		t.Errorf("expected ansible_host=host-a, got %v", vars["ansible_host"])
	}
}

func TestCmdHostNotFound(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(serverInventoryResponse)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	cfg := config{serverURL: srv.URL, insecure: true}
	err := cmdHost(cfg, "nonexistent-host")

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stdout = old

	if err != nil {
		t.Fatalf("cmdHost unknown: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := pr.Read(buf)
	output := strings.TrimSpace(string(buf[:n]))

	// Doit retourner {} pour les hôtes inconnus
	if output != "{}" {
		t.Errorf("expected {} for unknown host, got %q", output)
	}
}

func TestCmdHostServerError(t *testing.T) {
	// Simule une erreur serveur → cmdHost doit quand même retourner {} sans erreur
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"error":"internal"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	defer srv.Close()

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	cfg := config{serverURL: srv.URL, insecure: true}
	err := cmdHost(cfg, "host-a")

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stdout = old

	// cmdHost ne doit pas retourner d'erreur (comportement Ansible : {} en cas d'erreur)
	if err != nil {
		t.Fatalf("cmdHost on server error should not return error: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := pr.Read(buf)
	output := strings.TrimSpace(string(buf[:n]))

	if output != "{}" {
		t.Errorf("expected {} on server error, got %q", output)
	}
}

// ========================================================================
// newHTTPClient
// ========================================================================

func TestNewHTTPClientDefault(t *testing.T) {
	cfg := config{}
	client, err := newHTTPClient(cfg)
	if err != nil {
		t.Fatalf("newHTTPClient default: %v", err)
	}
	if client == nil {
		t.Error("client is nil")
	}
}

func TestNewHTTPClientInsecure(t *testing.T) {
	cfg := config{insecure: true}
	client, err := newHTTPClient(cfg)
	if err != nil {
		t.Fatalf("newHTTPClient insecure: %v", err)
	}
	if client == nil {
		t.Error("client is nil")
	}
}

func TestNewHTTPClientInvalidCABundle(t *testing.T) {
	cfg := config{caBundle: "/nonexistent/ca.pem"}
	_, err := newHTTPClient(cfg)
	if err == nil {
		t.Error("expected error for nonexistent CA bundle")
	}
}

func TestNewHTTPClientInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	if err := os.WriteFile(caFile, []byte("not valid pem"), 0644); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	cfg := config{caBundle: caFile}
	_, err := newHTTPClient(cfg)
	if err == nil {
		t.Error("expected error for invalid CA PEM")
	}
}

// ========================================================================
// loadConfig
// ========================================================================

func TestLoadConfigDefaults(t *testing.T) {
	// Forcer les variables à vide — t.Setenv restaure automatiquement la valeur d'origine.
	// getenv() traite "" comme absent et retourne le fallback.
	t.Setenv("RELAY_SERVER_URL", "")
	t.Setenv("RELAY_TOKEN", "")
	t.Setenv("RELAY_CA_BUNDLE", "")
	t.Setenv("RELAY_INSECURE_TLS", "")
	t.Setenv("RELAY_ONLY_CONNECTED", "")

	cfg := loadConfig()

	if cfg.serverURL != "https://localhost:7770" {
		t.Errorf("default serverURL: got %q", cfg.serverURL)
	}
	if cfg.token != "" {
		t.Errorf("default token should be empty, got %q", cfg.token)
	}
	if cfg.insecure {
		t.Error("default insecure should be false")
	}
	if cfg.onlyConnected {
		t.Error("default onlyConnected should be false")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// t.Setenv définit la variable ET restaure la valeur d'origine en fin de test.
	t.Setenv("RELAY_SERVER_URL", "https://relay.example.com")
	t.Setenv("RELAY_TOKEN", "mytoken")
	t.Setenv("RELAY_INSECURE_TLS", "true")
	t.Setenv("RELAY_ONLY_CONNECTED", "true")

	cfg := loadConfig()

	if cfg.serverURL != "https://relay.example.com" {
		t.Errorf("serverURL: got %q", cfg.serverURL)
	}
	if cfg.token != "mytoken" {
		t.Errorf("token: got %q", cfg.token)
	}
	if !cfg.insecure {
		t.Error("insecure should be true")
	}
	if !cfg.onlyConnected {
		t.Error("onlyConnected should be true")
	}
}

// ========================================================================
// getenv
// ========================================================================

func TestGetenvWithValue(t *testing.T) {
	t.Setenv("TEST_RELAY_KEY", "hello")

	if v := getenv("TEST_RELAY_KEY", "default"); v != "hello" {
		t.Errorf("expected hello, got %q", v)
	}
}

func TestGetenvFallback(t *testing.T) {
	t.Setenv("TEST_RELAY_KEY_MISSING", "")
	if v := getenv("TEST_RELAY_KEY_MISSING", "fallback"); v != "fallback" {
		t.Errorf("expected fallback, got %q", v)
	}
}

// ========================================================================
// closeBody
// ========================================================================

// errCloser est un io.Closer dont Close() retourne toujours une erreur.
type errCloser struct{ err error }

func (e *errCloser) Close() error { return e.err }

func TestCloseBodyNoError(t *testing.T) {
	// closeBody ne doit pas paniquer quand Close() réussit
	var closed bool
	rc := &mockCloser{closeFn: func() error { closed = true; return nil }}
	closeBody(rc)
	if !closed {
		t.Error("expected Close() to be called")
	}
}

func TestCloseBodyLogsErrorOnStderr(t *testing.T) {
	// closeBody doit journaliser l'erreur sur stderr sans toucher stdout
	oldErr := os.Stderr
	pr, pw, _ := os.Pipe()
	os.Stderr = pw

	closeBody(&errCloser{err: errors.New("disk full")})

	if err := pw.Close(); err != nil {
		t.Errorf("close pipe: %v", err)
	}
	os.Stderr = oldErr

	buf := make([]byte, 256)
	n, _ := pr.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "disk full") {
		t.Errorf("expected error message on stderr, got %q", output)
	}
}

// mockCloser permet de contrôler le comportement de Close dans les tests.
type mockCloser struct {
	closeFn func() error
}

func (m *mockCloser) Close() error { return m.closeFn() }
