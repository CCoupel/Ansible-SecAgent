package handlers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

const hostileID = "bad one\n[SECURITY WARNING] forged"

// A route written before the validation (hostile relay_id / chain / hostname) never reaches the
// Ansible inventory: no group named after it, no hostvars, no forged log line.
func TestInventory_LegacyHostileRoutesAreNeverServed(t *testing.T) {
	s := legacyStore(t) // holds the hostile relay_nodes row the routes below point to
	h := sha256.Sum256([]byte(proxyTestToken))
	if err := s.CreatePluginToken(context.Background(), storage.PluginToken{
		ID: "tok-legacy", TokenHash: fmt.Sprintf("%x", h), Role: "plugin", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	SetProxyRouter(proxy.NewProxyRouter(s))
	t.Cleanup(func() { SetProxyRouter(nil) })
	withAuth := func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer "+proxyTestToken)
		return r
	}
	logs := captureLog(t)
	seedNode(t, s, "dmz1", "connected")
	route(t, s, "good-host", "dmz1", "dmz1")
	route(t, s, "bad-relay-host", hostileID, hostileID)
	route(t, s, "bad-chain-host", "dmz1", "dmz1", hostileID)
	route(t, s, "bad host\nname", "dmz1", "dmz1")

	code, inv := getInv(t, withAuth, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	eq(t, "all.hosts", inv.All.Hosts, "good-host")
	if len(inv.Groups) != 1 || inv.Groups["dmz1"].Hosts == nil {
		t.Errorf("groups = %v, want only dmz1", inv.Groups)
	}
	assertValidAnsibleInventory(t, inv)
	for _, h := range []string{"bad-relay-host", "bad-chain-host"} {
		if _, ok := inv.Meta.Hostvars[h]; ok {
			t.Errorf("hostvars of the malformed route %q were served", h)
		}
	}
	if strings.Contains(logs.String(), "\n[SECURITY WARNING] forged") {
		t.Errorf("a hostile value forged a log line: %q", logs.String())
	}
}

// legacyStore returns a store whose relay_nodes contains a malformed relay_id that bypassed the
// validation (written straight through the state engine, then reopened).
func legacyStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Engine().Mutate(func(tx *state.Tx) error {
		return tx.PutRelayNode(state.RelayNode{ID: "legacy-uuid", RelayID: hostileID, Mode: "pull", CreatedAt: time.Unix(0, 0)})
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = storage.OpenTestDir(dir)
	if err != nil {
		t.Fatalf("a malformed row must not break the startup: %v", err)
	}
	prevAdmin, prevRegister := adminStore, registerStore
	SetAdminStore(s)
	SetRegisterStore(s)
	t.Cleanup(func() {
		adminStore, registerStore = prevAdmin, prevRegister
		_ = s.Close()
	})
	return s
}

var stampedLine = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d `)

// Revoking then deleting a legacy relay whose id is hostile logs ONE line per action, with the id
// quoted: no forged line.
func TestAdminRevokeDelete_LegacyHostileRelayIDDoesNotForgeLogs(t *testing.T) {
	legacyStore(t)
	logs := captureLog(t)
	for _, call := range []struct {
		h      http.HandlerFunc
		method string
		want   int
	}{{AdminRevokeRelay, "POST", http.StatusOK}, {AdminDeleteRelay, "DELETE", http.StatusNoContent}} {
		req := adminReq(call.method, "/api/admin/relays/legacy-uuid", nil)
		req.SetPathValue("id", "legacy-uuid")
		rr := httptest.NewRecorder()
		call.h(rr, req)
		if rr.Code != call.want {
			t.Fatalf("%s: %d %s", call.method, rr.Code, rr.Body.String())
		}
	}
	out := strings.TrimRight(logs.String(), "\n")
	for _, line := range strings.Split(out, "\n") {
		if !stampedLine.MatchString(line) {
			t.Errorf("a log line was forged by the hostile id: %q", line)
		}
	}
	if !strings.Contains(out, `relay_id="bad one\n[SECURITY WARNING] forged"`) {
		t.Errorf("the id must be quoted in the revoke/delete logs:\n%s", out)
	}
}
