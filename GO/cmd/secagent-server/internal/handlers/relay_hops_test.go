// relay_hops_test.go — Tests for X-Relay-Hops loop detection in exec/upload/fetch handlers.
//
// Spec reference: exec.go lines 219-231 / 362-372 / 459-469
//
// With v3.0 (#123), the hop budget is only enforced on INCOMING requests:
//   - X-Relay-Hops ≤ 0   → HTTP 508 relay_loop_detected (loop guard)
//   - X-Relay-Hops absent → proceeds with DefaultMaxHops (no block)
//   - X-Relay-Hops > 0   → proceeds (budget decremented, stored in context)
//
// These tests require proxyRouter to be non-nil; otherwise the hop check is skipped.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secagent-server/cmd/secagent-server/internal/proxy"
)

// setupHopsTest creates a store + plugin token + ProxyRouter.
// Returns the request decorator for plugin auth.
func setupHopsTest(t *testing.T) func(r *http.Request) *http.Request {
	t.Helper()
	_, withAuth := setupProxyTest(t)
	return withAuth
}

// ── ExecCommand hop counting ──────────────────────────────────────────────────

func TestExecCommand_RelayLoopDetected_ZeroHops(t *testing.T) {
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/any-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxy.RelayHopsHeader, "0")
	req.SetPathValue("hostname", "any-host")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	if w.Code != http.StatusLoopDetected {
		t.Fatalf("expected 508 relay_loop_detected, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	if resp["error"] != "relay_loop_detected" {
		t.Errorf("expected error=relay_loop_detected, got %q", resp["error"])
	}
}

func TestExecCommand_RelayLoopDetected_NegativeHops(t *testing.T) {
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/any-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxy.RelayHopsHeader, "-1")
	req.SetPathValue("hostname", "any-host")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	if w.Code != http.StatusLoopDetected {
		t.Fatalf("expected 508 for negative hops, got %d — %s", w.Code, w.Body.String())
	}
}

func TestExecCommand_NoHopsHeader_Proceeds(t *testing.T) {
	// No X-Relay-Hops header → uses DefaultMaxHops → does not trigger 508.
	// Host is not registered → falls through to agent_offline (503), not 508.
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/non-existent-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "non-existent-host")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	// Must NOT be 508 (loop detection did not fire)
	if w.Code == http.StatusLoopDetected {
		t.Fatalf("unexpected 508 with no hops header")
	}
}

func TestExecCommand_PositiveHops_Proceeds(t *testing.T) {
	// X-Relay-Hops: 5 → budget decremented to 4, request proceeds normally.
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/non-existent-host2", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxy.RelayHopsHeader, "5")
	req.SetPathValue("hostname", "non-existent-host2")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	if w.Code == http.StatusLoopDetected {
		t.Fatalf("unexpected 508 with hops=5")
	}
}

// ── UploadFile hop counting ───────────────────────────────────────────────────

func TestUploadFile_RelayLoopDetected_ZeroHops(t *testing.T) {
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"dest": "/tmp/f.txt", "data": "aGVsbG8="})
	req := withAuth(httptest.NewRequest("POST", "/api/upload/any-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxy.RelayHopsHeader, "0")
	req.SetPathValue("hostname", "any-host")
	w := httptest.NewRecorder()

	UploadFile(w, req)

	if w.Code != http.StatusLoopDetected {
		t.Fatalf("expected 508 relay_loop_detected for upload, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	if resp["error"] != "relay_loop_detected" {
		t.Errorf("expected error=relay_loop_detected, got %q", resp["error"])
	}
}

// ── FetchFile hop counting ────────────────────────────────────────────────────

func TestFetchFile_RelayLoopDetected_ZeroHops(t *testing.T) {
	withAuth := setupHopsTest(t)

	body, _ := json.Marshal(map[string]interface{}{"src": "/etc/hosts"})
	req := withAuth(httptest.NewRequest("POST", "/api/fetch/any-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxy.RelayHopsHeader, "0")
	req.SetPathValue("hostname", "any-host")
	w := httptest.NewRecorder()

	FetchFile(w, req)

	if w.Code != http.StatusLoopDetected {
		t.Fatalf("expected 508 relay_loop_detected for fetch, got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	if resp["error"] != "relay_loop_detected" {
		t.Errorf("expected error=relay_loop_detected, got %q", resp["error"])
	}
}
