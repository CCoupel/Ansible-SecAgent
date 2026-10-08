package server

// #151 (L7, plan rev2 §5 "démarrage avec une ligne push stockée devenue interdite") — a stored push
// line that the policy (REPEATER_DIAL_DENY_CIDRS / REPEATER_DIAL_ALLOW_CIDRS) now forbids is NEVER
// dialed at startup, with a [SECURITY WARNING] naming the relay and the category, never the address
// or the token. The other lines of the table are still started.
//
// specConfigureDialPolicy is wired by the dev of #151 (dialpolicy_spec_wire_test.go in this package):
// it applies the three settings to the repeater package guard and returns the restore function.
// nil = the test is skipped as PENDING.

import (
	"log"
	"os"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/storage"
)

var specConfigureDialPolicy func(allowLoopback bool, deny, allow string) (restore func(), err error)

func TestStartPushDialers_AStoredLineForbiddenByThePolicyIsNeverDialed(t *testing.T) {
	if specConfigureDialPolicy == nil {
		t.Skip("PENDING #151: specConfigureDialPolicy is not wired yet (dialpolicy_spec_wire_test.go)")
	}
	for _, tc := range []struct {
		name        string
		deny, allow string
		rows        map[string]string // relay_id → url
		started     []string
		warn        map[string]string // relay_id → category expected in the warning
	}{
		{"deny", "10.1.0.0/16", "", map[string]string{"denied": "wss://10.1.2.3:7772", "fine": "wss://192.168.1.5:7772"},
			[]string{"fine"}, map[string]string{"denied": "deny"}},
		{"allow", "", "192.168.0.0/16", map[string]string{"outside": "wss://10.1.2.3:7772", "inside": "wss://192.168.1.5:7772"},
			[]string{"inside"}, map[string]string{"outside": "not_allowed"}},
		{"one forbidden address refuses the whole list", "10.1.0.0/16", "", map[string]string{"mixed": "wss://192.168.1.5:7772,wss://10.1.2.3:7772"},
			nil, map[string]string{"mixed": "deny"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RSA_MASTER_KEY", "main-test-master-key")
			st, err := storage.OpenTemp()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			for id, url := range tc.rows {
				sealed, err := handlers.SealPushToken(id, "child-jwt-"+id)
				if err != nil {
					t.Fatal(err)
				}
				seedRelay(t, st, id, "push", url, sealed)
			}
			restore, err := specConfigureDialPolicy(false, tc.deny, tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()

			var out strings.Builder
			log.SetOutput(&out)
			defer log.SetOutput(os.Stderr)
			v := &validatingStarter{}
			startPushDialers(st, v)

			if strings.Join(v.started, ",") != strings.Join(tc.started, ",") {
				t.Fatalf("started = %v, want %v", v.started, tc.started)
			}
			logs := out.String()
			for id, cat := range tc.warn {
				if !strings.Contains(logs, "[SECURITY WARNING]") || !strings.Contains(logs, `"`+id+`"`) || !strings.Contains(logs, cat) {
					t.Errorf("a [SECURITY WARNING] naming %q and the category %q is expected:\n%s", id, cat, logs)
				}
			}
			for _, leak := range []string{"10.1.2.3", "child-jwt-"} {
				if strings.Contains(logs, leak) {
					t.Errorf("the log must not contain %q:\n%s", leak, logs)
				}
			}
		})
	}
}
