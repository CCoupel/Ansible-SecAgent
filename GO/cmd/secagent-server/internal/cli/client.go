// Package cli implements the secagent-server command-line interface (ARCHITECTURE.md §21).
// All commands talk to the admin API (port 7771) using RELAY_API_URL + ADMIN_TOKEN env vars.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"
)

// apiURL returns the base URL for admin API calls.
// Reads RELAY_API_URL env var; defaults to http://localhost:7771.
func apiURL() string {
	if u := os.Getenv("RELAY_API_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:7771"
}

// checkHTTPS returns an error if the URL uses plain HTTP for a non-loopback address.
// This prevents ADMIN_TOKEN from being sent in cleartext over the network.
func checkHTTPS(u string) error {
	isLocal := strings.Contains(u, "localhost") || strings.Contains(u, "127.0.0.1")
	if !isLocal && strings.HasPrefix(u, "http://") {
		return fmt.Errorf("RELAY_API_URL uses http:// for a non-local address — use https:// to protect ADMIN_TOKEN in transit")
	}
	return nil
}

// adminToken returns the ADMIN_TOKEN env var.
func adminToken() string {
	return os.Getenv("ADMIN_TOKEN")
}

// httpClient is the shared HTTP client with a reasonable timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// apiRequest performs an authenticated HTTP request to the admin API.
// Returns the response body bytes and HTTP status code.
func apiRequest(method, path string, body interface{}) ([]byte, int, error) {
	base := apiURL()
	if err := checkHTTPS(base); err != nil {
		return nil, 0, err
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, base+path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}

	return data, resp.StatusCode, nil
}

// checkError prints an API error message and returns the appropriate exit code.
// Callers should os.Exit with the returned code when this returns non-zero.
func checkError(data []byte, status int) int {
	switch status {
	case 200, 201:
		return 0
	case 404:
		var e map[string]string
		json.Unmarshal(data, &e) //nolint:errcheck
		fmt.Fprintf(os.Stderr, "Error: not found — %s\n", e["error"])
		return 2
	case 401, 403:
		fmt.Fprintln(os.Stderr, "Error: unauthorized — check ADMIN_TOKEN")
		return 1
	default:
		var e map[string]string
		json.Unmarshal(data, &e) //nolint:errcheck
		msg := e["error"]
		if msg == "" {
			msg = string(data)
		}
		fmt.Fprintf(os.Stderr, "Error: %s (HTTP %d)\n", msg, status)
		return 1
	}
}

// ── Output formatting ─────────────────────────────────────────────────────────

// printOutput formats and prints v according to format ("json", "yaml", "table").
// tableFunc is called for table format; if nil, falls back to JSON.
func printOutput(format string, v interface{}, tableFunc func(interface{})) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case "yaml":
		return yaml.NewEncoder(os.Stdout).Encode(v)
	default: // "table"
		if tableFunc != nil {
			tableFunc(v)
			return nil
		}
		// fallback to JSON if no table renderer provided
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
}

// newTabWriter returns a tabwriter for aligned table output.
func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}
