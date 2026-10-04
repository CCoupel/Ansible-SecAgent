package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// mustUnmarshal unmarshals JSON data into v, fatally failing the test on error.
// Use instead of bare json.Unmarshal to keep errcheck satisfied and get an
// early, clear failure message when JSON is malformed.
func mustUnmarshal(t *testing.T, data []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("mustUnmarshal: %v", err)
	}
}

// mustDecode decodes JSON from r into v, fatally failing the test on error.
// Use instead of bare json.NewDecoder(r).Decode(v) to keep errcheck satisfied.
func mustDecode(t *testing.T, r io.Reader, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("mustDecode: %v", err)
	}
}

// mustEncode encodes v as JSON into w, reporting an error (non-fatal) on failure.
// Uses t.Errorf (never t.Fatal) because it is called from HTTP handler goroutines
// where t.FailNow would cause a runtime.Goexit panic.
func mustEncode(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("mustEncode: %v", err)
	}
}
