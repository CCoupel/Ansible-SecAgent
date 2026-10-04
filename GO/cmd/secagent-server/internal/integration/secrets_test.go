package integration

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertNoSecrets fails when a token (raw, fragments, base64) or the Authorization header shows up
// in the logs of the nodes. The become password is checked by TestChain_ThreeLevels….
func assertNoSecrets(t *testing.T, logs string, tokens ...string) {
	t.Helper()
	needles := []string{"Authorization", "Bearer ", becomeSecret, base64.StdEncoding.EncodeToString([]byte(becomeSecret))}
	for _, tok := range tokens {
		if len(tok) < 20 {
			t.Fatalf("token too short to be a meaningful needle: %q", tok)
		}
		needles = append(needles, tok, base64.StdEncoding.EncodeToString([]byte(tok)))
		if len(tok) >= 40 { // JWTs: also their fragments
			needles = append(needles, tok[:20], tok[len(tok)/2-10:len(tok)/2+10], tok[len(tok)-20:])
		}
	}
	for _, n := range needles {
		if strings.Contains(logs, n) {
			t.Errorf("secret leaked in node logs: %q", n)
		}
	}
}

// nodeSecrets lists the long-lived secrets of nodes: admin token, JWT signing secret, plugin token.
func nodeSecrets(nodes ...*node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.adminTok, n.jwtSecret)
		if n.plugin != "" {
			out = append(out, n.plugin)
		}
	}
	return out
}
