package cli

// #233: minions delete, relays revoke and relays remove [--revoke]: confirmation, refusal without a
// terminal, names resolved to row ids. The CLI runs as a subprocess whose stdin is not a terminal.

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

type calls struct {
	mu sync.Mutex
	l  []string
}

func (c *calls) add(s string) { c.mu.Lock(); c.l = append(c.l, s); c.mu.Unlock() }
func (c *calls) all() string  { c.mu.Lock(); defer c.mu.Unlock(); return strings.Join(c.l, "\n") }

const relaysJSON = `{"relays":[{"id":"uuid-1111","relay_id":"relay-a"},{"id":"uuid-2222","relay_id":"ghost"},{"id":"uuid-3333","relay_id":"dup"},{"id":"uuid-4444","relay_id":"dup"}]}`

func adminAPI(t *testing.T, minionStatus string, removeStatus int, removeBody string) *calls {
	t.Helper()
	c := &calls{}
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		c.add(r.Method + " " + r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/admin/relays":
			_, _ = w.Write([]byte(relaysJSON))
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/admin/minions/"):
			_, _ = w.Write([]byte(`{"hostname":"web1","status":"` + minionStatus + `"}`))
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/admin/minions/"):
			_, _ = w.Write([]byte(`{"hostname":"web1","status":"deleted"}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/revoke"):
			_, _ = w.Write([]byte(`{"revoked":true}`))
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/api/admin/relays/"):
			w.WriteHeader(removeStatus)
			_, _ = w.Write([]byte(removeBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return c
}

func TestMinionsDelete_RefusedWithoutATerminalUnlessYes(t *testing.T) {
	c := adminAPI(t, "disconnected", 204, "")
	_, errOut, code := runCLI(t, "minions", "delete", "web1")
	if code != ExitRefused || !strings.Contains(errOut, "--yes") {
		t.Fatalf("exit %d, stderr %q: want %d and the hint to pass --yes", code, errOut, ExitRefused)
	}
	if strings.Contains(c.all(), "DELETE") {
		t.Fatalf("nothing may be deleted without confirmation:\n%s", c.all())
	}
	out, errOut, code := runCLI(t, "minions", "delete", "web1", "--yes")
	if code != 0 || !strings.Contains(out, "deleted") || !strings.Contains(c.all(), "DELETE /api/admin/minions/web1") {
		t.Fatalf("exit %d out=%q err=%q calls:\n%s", code, out, errOut, c.all())
	}
}

func TestMinionsDelete_TellsWhenTheAgentIsConnected(t *testing.T) {
	adminAPI(t, "connected", 204, "")
	out, _, code := runCLI(t, "minions", "delete", "web1", "--yes")
	if code != 0 || !strings.Contains(out, "is connected") || !strings.Contains(out, "minions revoke") {
		t.Fatalf("exit %d out=%q: a connected agent must be flagged with the revoke alternative", code, out)
	}
}

func TestRelaysRevoke_ResolvesTheRelayIDAndNeedsConfirmation(t *testing.T) {
	c := adminAPI(t, "", 204, "")
	if _, _, code := runCLI(t, "relays", "revoke", "ghost"); code != ExitRefused || strings.Contains(c.all(), "POST") {
		t.Fatalf("exit %d: revoke without a terminal and without --yes must be refused, calls:\n%s", code, c.all())
	}
	out, errOut, code := runCLI(t, "relays", "revoke", "ghost", "--yes")
	if code != 0 || !strings.Contains(c.all(), "POST /api/admin/relays/uuid-2222/revoke") {
		t.Fatalf("exit %d out=%q err=%q calls:\n%s", code, out, errOut, c.all())
	}
	// the row id is accepted too
	runCLI(t, "relays", "revoke", "uuid-1111", "--yes")
	if !strings.Contains(c.all(), "POST /api/admin/relays/uuid-1111/revoke") {
		t.Fatalf("the row id must be accepted:\n%s", c.all())
	}
}

func TestRelaysResolve_UnknownAndAmbiguousNamesAreErrors(t *testing.T) {
	c := adminAPI(t, "", 204, "")
	if _, errOut, code := runCLI(t, "relays", "remove", "nobody"); code == 0 || !strings.Contains(errOut, "no relay") {
		t.Fatalf("unknown relay: exit %d %q", code, errOut)
	}
	if _, errOut, code := runCLI(t, "relays", "remove", "dup"); code == 0 || !strings.Contains(errOut, "matches 2 rows") {
		t.Fatalf("ambiguous relay_id: exit %d %q", code, errOut)
	}
	if strings.Contains(c.all(), "DELETE") {
		t.Fatalf("nothing may be removed on an unresolved name:\n%s", c.all())
	}
}

func TestRelaysRemove_NotRevokedPointsAtRevoke(t *testing.T) {
	c := adminAPI(t, "", 409, `{"error":"relay_not_revoked"}`)
	_, errOut, code := runCLI(t, "relays", "remove", "ghost")
	if code == 0 || !strings.Contains(errOut, "relay_not_revoked") || !strings.Contains(errOut, "remove --revoke ghost") {
		t.Fatalf("exit %d stderr %q: the 409 must name the --revoke remedy", code, errOut)
	}
	if !strings.Contains(c.all(), "DELETE /api/admin/relays/uuid-2222") {
		t.Fatalf("the name must be resolved to the row id:\n%s", c.all())
	}
}

func TestRelaysRemove_RevokeThenRemove(t *testing.T) {
	c := adminAPI(t, "", 204, "")
	if _, _, code := runCLI(t, "relays", "remove", "--revoke", "ghost"); code != ExitRefused {
		t.Fatalf("--revoke without a terminal and without --yes must be refused: %d", code)
	}
	out, errOut, code := runCLI(t, "relays", "remove", "--revoke", "--yes", "ghost")
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errOut)
	}
	calls := c.all()
	if strings.Index(calls, "POST /api/admin/relays/uuid-2222/revoke") < 0 || strings.Index(calls, "DELETE /api/admin/relays/uuid-2222") < strings.Index(calls, "POST /api/admin/relays/uuid-2222/revoke") {
		t.Fatalf("revoke must come before remove:\n%s", calls)
	}
}

func TestKeysLinkStatus_WithoutARotationDoesNotSaySinceTheRotation(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"root_id":"root","seq":1,"current_kid":"K","relays":[{"relay_id":"c","state":"confirmed","confirmed":true,"direct":false}],"not_direct":["c"]}`))
	})
	out, _, code := runCLI(t, "keys", "link-status")
	if code != 0 || strings.Contains(out, "since the rotation") || !strings.Contains(out, "since this node started") {
		t.Fatalf("exit %d out=%q: outside a rotation the wording must not mention the rotation", code, out)
	}
}
