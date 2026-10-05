package main

import (
	"strings"
	"testing"
)

func TestBuildEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		srv, ws string
		want    int // addresses, 0 = error expected
		errHas  string
	}{
		"single values (compatibility)": {"https://h1:7770", "wss://h1:7772/ws/agent", 1, ""},
		"paired lists":                  {"https://h1:7770, https://h2:7770", "wss://h1:7772/ws/agent,wss://h2:7772/ws/agent", 2, ""},
		"different lengths refused":     {"https://h1:7770,https://h2:7770", "wss://h1:7772/ws/agent", 0, "same length"},
		"different lengths (other way)": {"https://h1:7770", "wss://h1:7772/ws/agent,wss://h2:7772/ws/agent", 0, "same length"},
		"duplicate address":             {"https://h1:7770,https://h1:7770", "wss://a/ws/agent,wss://b/ws/agent", 0, "RELAY_SERVER_URL"},
		"empty":                         {"", "wss://a/ws/agent", 0, "RELAY_SERVER_URL"},
		"wrong scheme for the WS list":  {"https://h1:7770", "https://h1:7772/ws/agent", 0, "RELAY_WS_URL"},
		"userinfo refused":              {"https://user:SECRETPW@h1:7770", "wss://h1:7772/ws/agent", 0, "userinfo"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, wsr, err := buildEndpoints(tc.srv, tc.ws)
			if tc.want == 0 {
				if err == nil || !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.errHas)
				}
				if strings.Contains(err.Error(), "SECRETPW") || strings.Contains(err.Error(), "h1:7770") {
					t.Errorf("the error echoes an address: %v", err)
				}
				return
			}
			if err != nil || srv.Len() != tc.want || wsr.Len() != tc.want {
				t.Fatalf("got %v %v err %v", srv, wsr, err)
			}
		})
	}
}
