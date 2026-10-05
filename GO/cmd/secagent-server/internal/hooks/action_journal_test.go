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
		pathSecret = "SLACKPATHSECRET"
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
		{Type: "webhook", URL: deadURL + "/services/T0/B0/" + pathSecret + "?access_token=" + urlToken, Secret: hmacSecret, MaxRetries: 0, TimeoutSeconds: 2},
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
	for _, secret := range []string{authSecret, "SUPER-SECRET-AUTH-TOKEN", hmacSecret, urlToken, bodySecret, argSecret, pathSecret} {
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

func (f *failingLogger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
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
	for fl.count() < 2 { // both actions reach the journal
		if time.Now().After(deadline) {
			t.Fatalf("both actions must still reach the journal: %d", fl.count())
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	// R4: one warning per minute, not one per failed append
	if n := strings.Count(out, "[WARN] hooks: action journal: disk full"); n != 1 {
		t.Fatalf("expected exactly 1 [WARN] for 2 failed appends, got %d:\n%s", n, out)
	}
}

func TestDispatcher_JournalWarningIsRateLimitedPerMinute(t *testing.T) {
	var logs bytes.Buffer
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }))
	defer log.SetOutput(prev)

	d := NewDispatcher(&failingLogger{}, 1)
	now := time.Unix(1700000000, 0)
	d.warnNow = func() time.Time { return now }
	err := errors.New("disk full")
	for i := 0; i < 5; i++ {
		d.warnJournal(err)
	}
	now = now.Add(61 * time.Second)
	d.warnJournal(err)
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if n := strings.Count(out, "[WARN] hooks: action journal: disk full"); n != 2 {
		t.Fatalf("expected 2 warnings (before/after the minute), got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "(4 similar warning(s) suppressed)") {
		t.Errorf("the suppressed count must be reported:\n%s", out)
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
		pathSecret = "SLACKPATHSECRET"
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
		{Type: "webhook", URL: strings.Replace(deadURL, "http://", "http://admin:"+userinfo+"@", 1) + "/services/T0/B0/" + pathSecret + "?access_token=" + urlToken, Secret: hmacSecret, TimeoutSeconds: 2},
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
	for _, secret := range []string{urlToken, hmacSecret, authSecret, userinfo, "Bearer", pathSecret} {
		if strings.Contains(out, secret) {
			t.Errorf("the server log leaks %q:\n%s", secret, out)
		}
	}
}

// #161c: the stderr of a shell command (it may print rendered arguments, tokens…) reaches neither
// the journal nor the server log: only the exit status does.
func TestDispatcher_ShellStderrNeverReachesJournalOrLog(t *testing.T) {
	const leak = "STDERR-SECRET-TOKEN"
	var logs bytes.Buffer
	var mu sync.Mutex
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }))
	defer log.SetOutput(prev)

	journalPath := filepath.Join(t.TempDir(), "actions.log")
	j, err := actionlog.Open(actionlog.Options{Path: journalPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	d := NewDispatcher(j, 10)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.new", Actions: []ActionDef{
		{Type: "shell", Cmd: "/bin/sh", Args: []string{"-c", "echo $0 >&2; exit 3", leak}, TimeoutSeconds: 3},
	}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Dispatch("host.new", "h1", "x", "")
	deadline := time.Now().Add(5 * time.Second)
	var got []actionlog.Entry
	for len(got) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no journal line")
		}
		time.Sleep(10 * time.Millisecond)
		got, _ = j.List(actionlog.Filter{})
	}
	time.Sleep(50 * time.Millisecond) // the log line follows the append
	raw, _ := os.ReadFile(journalPath)
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if bytes.Contains(raw, []byte(leak)) || strings.Contains(out, leak) {
		t.Errorf("stderr leaked:\njournal: %s\nlog: %s", raw, out)
	}
	if got[0].Success || !strings.Contains(got[0].Error, "exit status 3") {
		t.Errorf("the exit status must be reported: %+v", got[0])
	}
}
