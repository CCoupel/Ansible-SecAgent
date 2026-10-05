package handlers

import (
	"net/http"
	"strings"
	"testing"
)

// relay_id ends up in logs, environment variables, hook files and Ansible group names: the admin
// API refuses anything but [A-Za-z0-9][A-Za-z0-9_-]{0,62}, whatever the mode, without echoing it.
func TestAdminCreateRelay_RelayIDShape(t *testing.T) {
	valid := []string{"dmz1", "Zone_A-2", "a", "0abc", strings.Repeat("a", 63), "all", "ungrouped", "_meta"[1:]}
	invalid := []string{"a b", "a/b", "..", "a.b", strings.Repeat("a", 64), strings.Repeat("a", 200), "a\nb", "x;rm", "-x", "_x",
		"a\r\n[SECURITY WARNING] forged", "é", "a\x00b", "a b", "a\tb"}
	for _, mode := range []string{"pull", "push"} {
		for _, id := range valid {
			t.Run("valid/"+mode+"/"+id, func(t *testing.T) {
				useFreshStores(t)
				t.Setenv("RSA_MASTER_KEY", "unit-test-master-key")
				body := map[string]interface{}{"relay_id": id, "mode": mode}
				if mode == "push" {
					body["url"], body["token"] = "wss://relay.example.com:7772", "tok"
				}
				rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", body)
				if rr.Code != http.StatusCreated {
					t.Errorf("%q refused: %d %s", id, rr.Code, rr.Body.String())
				}
			})
		}
		for i, id := range invalid {
			t.Run("invalid/"+mode+"/"+string(rune('a'+i)), func(t *testing.T) {
				useFreshStores(t)
				t.Setenv("RSA_MASTER_KEY", "unit-test-master-key")
				logs := captureLog(t)
				body := map[string]interface{}{"relay_id": id, "mode": mode}
				if mode == "push" {
					body["url"], body["token"] = "wss://relay.example.com:7772", "tok"
				}
				rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", body)
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("%q accepted: %d %s", id, rr.Code, rr.Body.String())
				}
				if strings.Contains(rr.Body.String(), "forged") || strings.Contains(logs.String(), "\n[SECURITY WARNING] forged") {
					t.Errorf("the raw id was echoed: %s / %s", rr.Body.String(), logs.String())
				}
			})
		}
	}
}
