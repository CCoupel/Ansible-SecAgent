// Package cli implements the secagent-server command-line interface (ARCHITECTURE.md §21).
// All commands talk to the admin API (port 7771) using RELAY_API_URL + ADMIN_TOKEN env vars.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"secagent-server/cmd/secagent-server/internal/tlsca"
)

// apiURLs returns the admin API base URLs: RELAY_API_URL is a comma-separated list (one per relay
// instance, tried in order); defaults to http://localhost:7771.
func apiURLs() ([]string, error) {
	v := strings.TrimSpace(os.Getenv("RELAY_API_URL"))
	if v == "" {
		return []string{"http://localhost:7771"}, nil
	}
	parts := strings.Split(v, ",")
	if len(parts) > 16 {
		return nil, fmt.Errorf("RELAY_API_URL: too many addresses (max 16)")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		u, err := url.Parse(p)
		if p == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("RELAY_API_URL: each address must be an http(s):// URL")
		}
		if u.User != nil {
			return nil, fmt.Errorf("RELAY_API_URL: an address must not contain userinfo")
		}
		if seen[p] {
			return nil, fmt.Errorf("RELAY_API_URL: duplicate address")
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// apiURL returns the first admin API base URL (kept for callers that need a single address).
func apiURL() string {
	if l, err := apiURLs(); err == nil {
		return l[0]
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

// apiClient returns the HTTP client of the admin API calls. With REPEATER_CA_FILE set, the relay API
// certificate is verified against that CA bundle ONLY (the system roots are replaced, #147); a CA file
// that cannot be used is an error, never a silent fallback to the system roots.
func apiClient() (*http.Client, error) {
	tlsCfg, err := tlsca.FromEnv()
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		return httpClient, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Timeout: httpClient.Timeout, Transport: tr}, nil
}

// apiRequest performs an authenticated HTTP request to the admin API.
// With several RELAY_API_URL addresses: a read (GET/HEAD) moves to the next address on any transport
// failure; a write only does so when the request provably left nothing on the wire (failure before
// the headers were written) — otherwise it may have been applied and is NOT replayed elsewhere.
// Returns the response body bytes and HTTP status code.
func apiRequest(method, path string, body interface{}) ([]byte, int, error) {
	bases, err := apiURLs()
	if err != nil {
		return nil, 0, err
	}
	for _, b := range bases {
		if err := checkHTTPS(b); err != nil {
			return nil, 0, err
		}
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
	}
	idempotent := method == http.MethodGet || method == http.MethodHead
	var lastErr error
	for _, base := range bases {
		data, status, sent, err := apiRequestOnce(base, method, path, payload)
		if err == nil {
			return data, status, nil
		}
		lastErr = err
		if sent && !idempotent {
			return nil, status, err // may have been applied: never replay a write on another address
		}
	}
	return nil, 0, lastErr
}

// apiRequestOnce performs one attempt against base. sent reports whether the request headers reached
// the wire (the request may then have been processed by the server).
func apiRequestOnce(base, method, path string, payload []byte) (data []byte, status int, sent bool, err error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, base+path, bodyReader)
	if err != nil {
		return nil, 0, false, fmt.Errorf("build request: %w", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteHeaders: func() { sent = true },
	}))
	req.Header.Set("Authorization", "Bearer "+adminToken())
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := apiClient()
	if err != nil {
		return nil, 0, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, sent, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, true, fmt.Errorf("read body: %w", err)
	}
	return data, resp.StatusCode, true, nil
}

// checkError prints an API error message and returns the appropriate exit code.
// Callers should os.Exit with the returned code when this returns non-zero.
func checkError(data []byte, status int) int {
	switch status {
	case 200, 201:
		return 0
	case 404:
		var e map[string]string
		_ = json.Unmarshal(data, &e) // best-effort; empty map handled below
		_, _ = fmt.Fprintf(os.Stderr, "Error: not found — %s\n", e["error"])
		return 2
	case 401, 403:
		_, _ = fmt.Fprintln(os.Stderr, "Error: unauthorized — check ADMIN_TOKEN")
		return 1
	default:
		var e map[string]string
		_ = json.Unmarshal(data, &e) // best-effort; empty map handled below
		msg := e["error"]
		if msg == "" {
			msg = string(data)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s (HTTP %d)\n", msg, status)
		return 1
	}
}

// ── Output formatting ─────────────────────────────────────────────────────────

// printOutput formats and prints v according to format ("json", "yaml", "table").
// tableFunc is called for table format; if nil, falls back to JSON.
func printOutput(format string, v interface{}, tableFunc func(interface{}) error) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case "yaml":
		return yaml.NewEncoder(os.Stdout).Encode(v)
	default: // "table"
		if tableFunc != nil {
			return tableFunc(v)
		}
		// fallback to JSON if no table renderer provided
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
}

// tabPrinter is an errWriter for tabwriter output.
// Individual write errors are captured; all are surfaced on flush().
type tabPrinter struct {
	tw  *tabwriter.Writer
	err error
}

// newTabPrinter returns a tabPrinter backed by a tabwriter writing to os.Stdout.
func newTabPrinter() *tabPrinter {
	return &tabPrinter{tw: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)}
}

// println writes a line to the underlying tabwriter.
func (p *tabPrinter) println(s string) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.tw, s)
	}
}

// printf writes a formatted line to the underlying tabwriter.
func (p *tabPrinter) printf(format string, args ...interface{}) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.tw, format, args...)
	}
}

// flush flushes the tabwriter and returns the first error encountered.
func (p *tabPrinter) flush() error {
	if p.err != nil {
		return p.err
	}
	return p.tw.Flush()
}
