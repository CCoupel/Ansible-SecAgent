package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func authorize(t *testing.T, admin, host string) (int, map[string]any) {
	t.Helper()
	code, body := adminCall(t, admin, "POST", "/api/admin/authorize", map[string]any{"hostname": host, "public_key_pem": "pem", "approved_by": "ci"})
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return code, m
}

// With no write guard (or a guard that refuses) a write is a visible 503 state_read_only with a short
// reason, never the generic 500 db_error; the status says read_only and why.
func TestReadOnly_WriteIs503StateReadOnlyWithAReason(t *testing.T) {
	var mode atomic.Value
	mode.Store("ok")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	_, _, admin, _ := startNode(t, func(c *Config) {
		c.WriteGuard = func() error {
			if mode.Load() == "ok" {
				return nil
			}
			return errors.New("lock: cannot confirm ownership")
		}
	})
	if code, _ := authorize(t, admin, "before"); code >= 300 {
		t.Fatalf("a write with a healthy guard must work: %d", code)
	}
	_, st := adminCall(t, admin, "GET", "/api/admin/status", nil)
	var status map[string]any
	_ = json.Unmarshal(st, &status)
	if status["state_mode"] != "read_write" || status["write_seq"] == nil {
		t.Errorf("status of a writable master: %v", status)
	}

	mode.Store("refuse")
	for i := 0; i < 3; i++ {
		code, m := authorize(t, admin, "after")
		if code != http.StatusServiceUnavailable || m["error"] != "state_read_only" || m["reason"] != "ownership not confirmed" {
			t.Fatalf("refused write: %d %v, want 503 state_read_only / ownership not confirmed", code, m)
		}
	}
	if n := strings.Count(buf.String(), "write refused (503 state_read_only)"); n != 1 {
		t.Errorf("the refusal is logged once a minute, got %d lines", n)
	}
	_, st = adminCall(t, admin, "GET", "/api/admin/status", nil)
	status = map[string]any{}
	_ = json.Unmarshal(st, &status)
	if status["state_mode"] != "read_only" || status["state_mode_reason"] != "ownership not confirmed" {
		t.Errorf("status of a read-only instance: %v", status)
	}
}

func TestReadOnly_NoWriteGuardReasonAndNode(t *testing.T) {
	n, _, admin, _ := startNode(t, func(c *Config) { c.WriteGuard = nil })
	code, m := authorize(t, admin, "x")
	if code != http.StatusServiceUnavailable || m["error"] != "state_read_only" || m["reason"] != "no write guard" {
		t.Fatalf("%d %v", code, m)
	}
	if mode, reason := n.StateMode(); mode != "read_only" || reason != "no write guard" {
		t.Errorf("StateMode = %s/%s", mode, reason)
	}
	n.Abort()
	if _, reason := n.StateMode(); reason != "lock lost" {
		t.Errorf("after Abort the reason is %q, want lock lost", reason)
	}
}

// A genuine failure that is NOT the read-only state keeps its 500 (the rewrite is exact).
func TestReadOnlyRewrite_OnlyRewritesDBErrorWhileReadOnly(t *testing.T) {
	n, _, _, _ := startNode(t, nil) // writable
	h := n.readOnlyRewrite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"db_error"}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "db_error") {
		t.Fatalf("a db_error on a writable instance stays a 500: %d %s", rec.Code, rec.Body.String())
	}
	other := n.readOnlyRewrite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	n.cfg.WriteGuard = nil // now read-only
	rec = httptest.NewRecorder()
	other.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil))
	if rec.Code != 500 {
		t.Fatalf("another 500 is never rewritten: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil))
	if rec.Code != 503 {
		t.Fatalf("db_error while read-only must be 503, got %d", rec.Code)
	}
}

// A revocation that cannot be persisted must not cut the agent with 4001: the new master would not
// know the revocation and the agent could never come back.
func TestReadOnly_RevokeThatCannotBePersistedDoesNotClose4001(t *testing.T) {
	var refuse atomic.Bool
	n, _, admin, _ := startNode(t, func(c *Config) {
		c.WriteGuard = func() error {
			if refuse.Load() {
				return errors.New("refused")
			}
			return nil
		}
	})
	if err := n.store.UpsertAgent(context.Background(), "victim", "pem", "jti-victim"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	refuse.Store(true)
	code, body := adminCall(t, admin, "POST", "/api/admin/revoke/victim", nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "state_read_only") {
		t.Fatalf("a revoke whose blacklist write was refused must be a visible 503, got %d %s", code, body)
	}
	refuse.Store(false)
	if bl, _ := n.store.IsJTIBlacklisted(context.Background(), "jti-victim"); bl {
		t.Error("nothing was persisted: the jti must not be blacklisted")
	}
	if code, body := adminCall(t, admin, "POST", "/api/admin/revoke/victim", nil); code != http.StatusOK {
		t.Fatalf("the retry once writable must succeed: %d %s", code, body)
	}
}
