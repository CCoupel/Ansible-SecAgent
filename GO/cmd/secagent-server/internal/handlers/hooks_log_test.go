package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

func withJournal(t *testing.T) *actionlog.Journal {
	t.Helper()
	j, err := actionlog.Open(actionlog.Options{Path: filepath.Join(t.TempDir(), "actions.log")})
	if err != nil {
		t.Fatal(err)
	}
	SetActionJournal(j)
	t.Cleanup(func() { SetActionJournal(nil); _ = j.Close() })
	return j
}

func TestAdminHooksLog_ReadsTheJournalWithFilters(t *testing.T) {
	j := withJournal(t)
	for i, ev := range []string{"host.new", "host.up", "host.new"} {
		if err := j.Append(actionlog.Entry{ID: "id" + string(rune('a'+i)), Event: ev, Hostname: "h" + string(rune('1'+i%2)), ActionType: "file",
			ConfigSnapshot: `{"type":"file"}`, Success: true, DurationMs: 3, ExecutedAt: time.Unix(1700000000+int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	call := func(q string) (int, []map[string]any) {
		w := httptest.NewRecorder()
		AdminHooksLog(w, adminReq("GET", "/api/admin/hooks/log"+q, nil))
		var out []map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call(""); code != http.StatusOK || len(out) != 3 || out[0]["id"] != "idc" {
		t.Errorf("all: %d %v", code, out)
	}
	if _, out := call("?event=host.new"); len(out) != 2 {
		t.Errorf("event filter: %d", len(out))
	}
	if _, out := call("?hostname=h2"); len(out) != 1 {
		t.Errorf("hostname filter: %d", len(out))
	}
	if _, out := call("?limit=1"); len(out) != 1 {
		t.Errorf("limit: %d", len(out))
	}
	if code, _ := call("?limit=0"); code != http.StatusBadRequest {
		t.Errorf("limit=0: %d", code)
	}
	if code, _ := call("?limit=201"); code != http.StatusBadRequest {
		t.Errorf("limit=201: %d", code)
	}
}

func TestAdminHooksLog_RequiresAdminAndAJournal(t *testing.T) {
	SetActionJournal(nil)
	w := httptest.NewRecorder()
	AdminHooksLog(w, adminReq("GET", "/api/admin/hooks/log", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "action_log_not_initialized") {
		t.Errorf("no journal: %d %s", w.Code, w.Body.String())
	}
	withJournal(t)
	w = httptest.NewRecorder()
	AdminHooksLog(w, httptest.NewRequest("GET", "/api/admin/hooks/log", nil)) // no admin token
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", w.Code)
	}
}
