package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Executor runs a single hook action and returns (success, errMsg, durationMs).
// The executor does NOT persist logs — the Dispatcher owns that responsibility.
type Executor interface {
	Execute(ctx context.Context, action ActionDef, vars map[string]string) (success bool, errMsg string, durationMs int64)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// backoffDuration returns the wait before the n-th retry (0-indexed).
// Sequence: n=0→0s, n=1→1s, n=2→2s, n=3→4s … capped at 60s.
func backoffDuration(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	shift := uint(n - 1)
	if shift > 5 {
		shift = 5
	}
	secs := int64(1) << shift
	if secs > 60 {
		secs = 60
	}
	return time.Duration(secs) * time.Second
}

// computeHMAC returns "sha256=<hex(HMAC-SHA256(key, body))>".
func computeHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// renderAny walks an arbitrary value and renders string leaves using Render.
func renderAny(v interface{}, vars map[string]string) interface{} {
	switch tv := v.(type) {
	case string:
		return Render(tv, vars)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(tv))
		for k, val := range tv {
			out[k] = renderAny(val, vars)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(tv))
		for i, val := range tv {
			out[i] = renderAny(val, vars)
		}
		return out
	default:
		return v
	}
}

// ── WebhookExecutor ───────────────────────────────────────────────────────────

// WebhookExecutor delivers a standardised JSON POST with optional HMAC signing.
// Retries with exponential backoff on 5xx / network errors.
// Stops immediately on 4xx (permanent consumer failure).
type WebhookExecutor struct {
	client *http.Client
}

// webhookPayload is the standardised JSON body sent by webhook actions.
type webhookPayload struct {
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	Host      webhookHost `json:"host"`
	webhookRelay
}

type webhookHost struct {
	Hostname   string `json:"hostname"`
	Status     string `json:"status,omitempty"`
	EnrolledAt string `json:"enrolled_at,omitempty"`
}

// webhookRelay carries the relay path of a propagated event (omitted for local events).
type webhookRelay struct {
	Chain  []string `json:"relay_chain,omitempty"`
	Origin string   `json:"relay_origin,omitempty"`
}

func (e *WebhookExecutor) Execute(ctx context.Context, action ActionDef, vars map[string]string) (bool, string, int64) {
	payload := webhookPayload{
		Event:     vars["event"],
		Timestamp: vars["timestamp"],
		Host: webhookHost{
			Hostname:   vars["hostname"],
			Status:     vars["status"],
			EnrolledAt: vars["enrolled_at"],
		},
	}
	if rc := vars["relay_chain"]; rc != "" {
		payload.Chain = strings.Split(rc, ",")
		payload.Origin = vars["relay_origin"]
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Sprintf("marshal payload: %v", err), 0
	}

	timeout := action.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	maxRetries := action.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	var lastErrMsg string
	var lastDur int64

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, "context cancelled", 0
			case <-time.After(backoffDuration(attempt)):
			}
		}

		success, errMsg, dur := e.doRequest(ctx, action, bodyBytes, vars["event"], timeout)
		if success {
			return true, "", dur
		}
		// 4xx → permanent failure, no retry
		if strings.HasPrefix(errMsg, "HTTP 4") {
			return false, errMsg, dur
		}
		lastErrMsg = errMsg
		lastDur = dur
	}
	return false, lastErrMsg, lastDur
}

func (e *WebhookExecutor) doRequest(ctx context.Context, action ActionDef, bodyBytes []byte, event string, timeoutSeconds int) (bool, string, int64) {
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, action.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Sprintf("build request: %v", err), 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "secagent-server/1.0")
	req.Header.Set("X-Event", event)
	if action.Secret != "" {
		req.Header.Set("X-Signature", computeHMAC(bodyBytes, action.Secret))
	}

	t0 := time.Now()
	resp, doErr := e.client.Do(req)
	dur := time.Since(t0).Milliseconds()
	if doErr != nil {
		return false, doErr.Error(), dur
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	sc := resp.StatusCode
	if sc >= 200 && sc < 300 {
		return true, "", dur
	}
	return false, fmt.Sprintf("HTTP %d", sc), dur
}

// ── ShellExecutor ─────────────────────────────────────────────────────────────

// ShellExecutor runs a local script or binary as a subprocess.
type ShellExecutor struct{}

func (e *ShellExecutor) Execute(ctx context.Context, action ActionDef, vars map[string]string) (bool, string, int64) {
	if action.Cmd == "" {
		return false, "missing cmd", 0
	}

	timeout := action.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}

	// Render template variables in args
	args := make([]string, len(action.Args))
	for i, a := range action.Args {
		args[i] = Render(a, vars)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, action.Cmd, args...)
	cmd.Env = append(os.Environ(),
		"SECAGENT_EVENT="+vars["event"],
		"SECAGENT_HOSTNAME="+vars["hostname"],
		"SECAGENT_TIMESTAMP="+vars["timestamp"],
		"SECAGENT_STATUS="+vars["status"],
	)
	if ea := vars["enrolled_at"]; ea != "" {
		cmd.Env = append(cmd.Env, "SECAGENT_ENROLLED_AT="+ea)
	}
	if rc := vars["relay_chain"]; rc != "" {
		cmd.Env = append(cmd.Env, "SECAGENT_RELAY_CHAIN="+rc, "SECAGENT_RELAY_ORIGIN="+vars["relay_origin"])
	}

	var stderr strings.Builder
	cmd.Stderr = &stderr

	t0 := time.Now()
	runErr := cmd.Run()
	dur := time.Since(t0).Milliseconds()

	if runErr != nil {
		msg := runErr.Error()
		if s := strings.TrimSpace(stderr.String()); s != "" {
			msg = s
		}
		return false, msg, dur
	}
	return true, "", dur
}

// ── FileExecutor ──────────────────────────────────────────────────────────────

// FileExecutor appends a rendered string to a file.
type FileExecutor struct {
	// openFileFn overrides os.OpenFile; used only in tests to inject
	// a WriteCloser whose Close() returns a controlled error.
	openFileFn func(name string, flag int, perm os.FileMode) (io.WriteCloser, error)
}

// openFile returns an io.WriteCloser for the given path/flags, using
// openFileFn when set (tests) or os.OpenFile otherwise.
func (e *FileExecutor) openFile(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	if e.openFileFn != nil {
		return e.openFileFn(name, flag, perm)
	}
	return os.OpenFile(name, flag, perm)
}

func (e *FileExecutor) Execute(ctx context.Context, action ActionDef, vars map[string]string) (ok bool, msg string, elapsed int64) {
	if action.Path == "" {
		return false, "missing path", 0
	}
	if action.Append == "" {
		return false, "missing append", 0
	}

	path := Render(action.Path, vars)
	content := Render(action.Append, vars)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Sprintf("mkdir: %v", err), 0
	}

	t0 := time.Now()
	f, err := e.openFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false, fmt.Sprintf("open: %v", err), time.Since(t0).Milliseconds()
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && ok {
			// Write succeeded but Close failed (e.g. deferred flush on NFS).
			// Report the action as failed so the caller is not misled.
			ok = false
			msg = fmt.Sprintf("close: %v", cerr)
		}
	}()

	if _, err := f.Write([]byte(content)); err != nil {
		return false, fmt.Sprintf("write: %v", err), time.Since(t0).Milliseconds()
	}
	return true, "", time.Since(t0).Milliseconds()
}

// ── APIExecutor ───────────────────────────────────────────────────────────────

// APIExecutor performs an HTTP request with a configurable method and optional body.
type APIExecutor struct {
	client *http.Client
}

func (e *APIExecutor) Execute(ctx context.Context, action ActionDef, vars map[string]string) (bool, string, int64) {
	method := strings.ToUpper(action.Method)
	if method == "" {
		method = http.MethodGet
	}
	timeout := action.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	maxRetries := action.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	url := Render(action.URL, vars)

	// Build body bytes (render template in body)
	var bodyBytes []byte
	switch b := action.Body.(type) {
	case json.RawMessage:
		// Render templates directly in the raw JSON string
		bodyBytes = []byte(Render(string(b), vars))
	case nil:
		// no body
	default:
		// map[string]interface{} or other JSON-decoded type — render string values
		rendered := renderAny(b, vars)
		var marshalErr error
		bodyBytes, marshalErr = json.Marshal(rendered)
		if marshalErr != nil {
			log.Printf("[WARN] hooks api: marshal body: %v", marshalErr)
		}
	}

	var lastErrMsg string
	var lastDur int64

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, "context cancelled", 0
			case <-time.After(backoffDuration(attempt)):
			}
		}

		success, errMsg, dur := e.doRequest(ctx, action, method, url, bodyBytes, timeout)
		if success {
			return true, "", dur
		}
		if strings.HasPrefix(errMsg, "HTTP 4") {
			return false, errMsg, dur
		}
		lastErrMsg = errMsg
		lastDur = dur
	}
	return false, lastErrMsg, lastDur
}

func (e *APIExecutor) doRequest(ctx context.Context, action ActionDef, method, url string, bodyBytes []byte, timeoutSeconds int) (bool, string, int64) {
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)
	if err != nil {
		return false, fmt.Sprintf("build request: %v", err), 0
	}
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "secagent-server/1.0")
	for k, v := range action.Headers {
		req.Header.Set(k, v)
	}

	t0 := time.Now()
	resp, doErr := e.client.Do(req)
	dur := time.Since(t0).Milliseconds()
	if doErr != nil {
		return false, doErr.Error(), dur
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	sc := resp.StatusCode
	if sc >= 200 && sc < 300 {
		return true, "", dur
	}
	return false, fmt.Sprintf("HTTP %d", sc), dur
}
