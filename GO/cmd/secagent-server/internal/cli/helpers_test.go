package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// mustEncode encodes v into w using json.Encoder.
// Reports a non-fatal error via t.Errorf — safe from HTTP handler goroutines.
func mustEncode(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("mustEncode: %v", err)
	}
}

// mustDecode decodes JSON from r into v.
// Reports a non-fatal error via t.Errorf — safe from HTTP handler goroutines.
func mustDecode(t *testing.T, r io.Reader, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Errorf("mustDecode: %v", err)
	}
}
