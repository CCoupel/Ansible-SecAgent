package main

import (
	"encoding/json"
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
