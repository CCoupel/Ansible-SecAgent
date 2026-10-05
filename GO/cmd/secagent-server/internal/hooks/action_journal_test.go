package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

// #161: the journal gets one line per action, without any secret of the hook configuration.

func TestDispatcher_JournalNeverContainsSecrets(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // refuses connections: the error message quotes the URL

	const (
		authSecret = "Bearer SUPER-SECRET-AUTH-TOKEN"
		hmacSecret = "HMAC-SECRET-VALUE"
		urlToken   = "URL-QUERY-TOKEN-XYZ"
		bodySecret = "BODY-SECRET-VALUE"
		argSecret  = "ARG-SECRET-VALUE"
	)
	journalPath := filepath.Join(t.TempDir(), "actions.log")
	j, err := actionlog.Open(actionlog.Options{Path: journalPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()

	d := NewDispatcher(j, 10)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.new", Actions: []ActionDef{
		{Type: "api", Method: "POST", URL: ok.URL + "/notify?token=" + urlToken,
			Headers: map[string]string{"Authorization": authSecret}, Body: map[string]string{"pw": bodySecret}, TimeoutSeconds: 3},
		{Type: "webhook", URL: deadURL + "/hook?access_token=" + urlToken, Secret: hmacSecret, MaxRetries: 0, TimeoutSeconds: 2},
		{Type: "shell", Cmd: "/bin/true", Args: []string{"--password", argSecret}, TimeoutSeconds: 3},
	}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Dispatch("host.new", "h1", "disconnected", "2026-10-05T10:00:00Z")

	deadline := time.Now().Add(10 * time.Second)
	for {
		if got, _ := j.List(actionlog.Filter{}); len(got) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			got, _ := j.List(actionlog.Filter{})
			t.Fatalf("only %d journal lines", len(got))
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{authSecret, "SUPER-SECRET-AUTH-TOKEN", hmacSecret, urlToken, bodySecret, argSecret} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the journal leaks %q:\n%s", secret, raw)
		}
	}
	types := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var e actionlog.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		types[e.ActionType] = true
		if e.Event != "host.new" || e.Hostname != "h1" || e.ID == "" || e.ExecutedAt.IsZero() {
			t.Errorf("incomplete entry: %+v", e)
		}
		if e.ConfigSnapshot == "" {
			t.Errorf("a masked snapshot is expected: %+v", e)
		}
	}
	if !types["api"] || !types["webhook"] || !types["shell"] {
		t.Errorf("one line per action expected, got types %v", types)
	}
}

// failingLogger returns an error for every entry.
type failingLogger struct {
	mu    sync.Mutex
	calls int
}

func (f *failingLogger) Append(actionlog.Entry) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return errors.New("disk full")
}

func TestDispatcher_JournalFailureDoesNotBlockTheDispatch(t *testing.T) {
	var logs bytes.Buffer
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }))
	defer log.SetOutput(prev)

	dir := t.TempDir()
	f1, f2 := filepath.Join(dir, "one.log"), filepath.Join(dir, "two.log")
	fl := &failingLogger{}
	d := NewDispatcher(fl, 10)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{
		{Event: "host.new", Actions: []ActionDef{{Type: "file", Path: f1, Append: "x\n"}}},
		{Event: "host.up", Actions: []ActionDef{{Type: "file", Path: f2, Append: "y\n"}}},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Dispatch("host.new", "h", "x", "")
	d.Dispatch("host.up", "h", "x", "")
	waitFile(t, f1, 3*time.Second)
	waitFile(t, f2, 3*time.Second) // the second event is still dispatched after the journal failures
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		out := logs.String()
		mu.Unlock()
		if strings.Count(out, "[WARN] hooks: action journal: disk full") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected a [WARN] per failed append, logs:\n%s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }

// #161b: the SERVER LOG (shipped to central systems) must not leak what the journal masks: Go's
// HTTP errors quote the whole URL, query-string tokens included.
func TestDispatcher_ServerLogNeverContainsSecrets(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // refuses connections: the error quotes the URL

	const (
		urlToken   = "URL-QUERY-TOKEN-XYZ"
		hmacSecret = "HMAC-SECRET-VALUE"
		authSecret = "SUPER-SECRET-AUTH-TOKEN"
		userinfo   = "hunter2"
	)
	var logs bytes.Buffer
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }))
	defer log.SetOutput(prev)

	j, err := actionlog.Open(actionlog.Options{Path: filepath.Join(t.TempDir(), "actions.log")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := NewDispatcher(j, 10)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.new", Actions: []ActionDef{
		{Type: "webhook", URL: strings.Replace(deadURL, "http://", "http://admin:"+userinfo+"@", 1) + "/hook?access_token=" + urlToken, Secret: hmacSecret, TimeoutSeconds: 2},
		{Type: "api", Method: "POST", URL: deadURL + "/x?token=" + urlToken, Headers: map[string]string{"Authorization": "Bearer " + authSecret}, TimeoutSeconds: 2},
		{Type: "api", Method: "GET", URL: "http://bad host/x?token=" + urlToken, TimeoutSeconds: 2}, // url.Parse error quoting a URL with a space
	}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Dispatch("host.new", "h1", "disconnected", "2026-10-05T10:00:00Z")

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := strings.Count(logs.String(), " FAIL: ")
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 3 FAIL log lines, got %d:\n%s", n, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	for _, secret := range []string{urlToken, hmacSecret, authSecret, userinfo, "Bearer"} {
		if strings.Contains(out, secret) {
			t.Errorf("the server log leaks %q:\n%s", secret, out)
		}
	}
}
