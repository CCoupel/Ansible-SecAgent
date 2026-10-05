package actionlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newJournal(t *testing.T, mod func(*Options)) (*Journal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "actions.log")
	o := Options{Path: path}
	if mod != nil {
		mod(&o)
	}
	j, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path
}

func entry(i int, event, host string) Entry {
	return Entry{ID: fmt.Sprintf("id-%04d", i), Event: event, Hostname: host, ActionType: "webhook", ActionIndex: i % 3,
		Success: i%2 == 0, Error: "", DurationMs: int64(i), ExecutedAt: time.Unix(1700000000+int64(i), 0).UTC()}
}

func TestAppendWritesOneValidJSONLinePerEntryAt0600(t *testing.T) {
	j, path := newJournal(t, nil)
	for i := 0; i < 5; i++ {
		if err := j.Append(entry(i, "host.new", "h1")); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5", len(lines))
	}
	for i, l := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if e.ID != fmt.Sprintf("id-%04d", i) || e.Event != "host.new" || e.ExecutedAt.IsZero() {
			t.Errorf("line %d: %+v", i, e)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", fi.Mode().Perm())
	}
}

func TestRotationBySize(t *testing.T) {
	j, path := newJournal(t, func(o *Options) { o.MaxBytes = 600; o.Files = 3 })
	for i := 0; i < 60; i++ {
		if err := j.Append(entry(i, "host.up", "h")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if fi.Size() > 600+300 { // one line may straddle at most
			t.Errorf("%s is %d bytes: not rotated by size", name, fi.Size())
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("more files than configured")
	}
	// the newest entries are in the current file, the oldest rotated files were dropped
	got, err := j.List(Filter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != "id-0059" {
		t.Errorf("most recent first: got %s", got[0].ID)
	}
	if len(got) >= 60 {
		t.Errorf("%d entries kept: the oldest files must have been dropped", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID >= got[i-1].ID {
			t.Fatalf("order broken at %d: %s then %s", i, got[i-1].ID, got[i].ID)
		}
	}
}

func TestRotationSurvivesAReopenedJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.log")
	j1, _ := Open(Options{Path: path, MaxBytes: 500, Files: 2})
	for i := 0; i < 3; i++ {
		_ = j1.Append(entry(i, "e", "h"))
	}
	_ = j1.Close()
	j2, _ := Open(Options{Path: path, MaxBytes: 500, Files: 2})
	defer func() { _ = j2.Close() }()
	for i := 3; i < 12; i++ {
		if err := j2.Append(entry(i, "e", "h")); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := j2.List(Filter{Limit: 200})
	if len(got) == 0 || got[0].ID != "id-0011" {
		t.Fatalf("got %v", got)
	}
}

func TestListFiltersLimitAndTornLines(t *testing.T) {
	j, path := newJournal(t, nil)
	for i := 0; i < 10; i++ {
		ev, h := "host.new", "a"
		if i%2 == 1 {
			ev, h = "host.up", "b"
		}
		if err := j.Append(entry(i, ev, h)); err != nil {
			t.Fatal(err)
		}
	}
	// a crash left a torn last line
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"id":"torn","event":"ho`)
	_ = f.Close()

	all, err := j.List(Filter{})
	if err != nil || len(all) != 10 {
		t.Fatalf("torn line must be skipped: %d entries, %v", len(all), err)
	}
	if got, _ := j.List(Filter{Event: "host.up"}); len(got) != 5 || got[0].Event != "host.up" {
		t.Errorf("event filter: %d", len(got))
	}
	if got, _ := j.List(Filter{Hostname: "a"}); len(got) != 5 {
		t.Errorf("hostname filter: %d", len(got))
	}
	if got, _ := j.List(Filter{Event: "host.new", Hostname: "b"}); len(got) != 0 {
		t.Errorf("combined filter: %d", len(got))
	}
	if got, _ := j.List(Filter{Limit: 3}); len(got) != 3 || got[0].ID != "id-0009" {
		t.Errorf("limit: %v", got)
	}
	if got, _ := j.List(Filter{}); len(got) != 10 {
		t.Errorf("default limit 50 returns everything here: %d", len(got))
	}
	// a missing journal is an empty list, not an error
	empty, _ := Open(Options{Path: filepath.Join(t.TempDir(), "none.log")})
	if got, err := empty.List(Filter{}); err != nil || len(got) != 0 {
		t.Errorf("missing file: %v %v", got, err)
	}
}

func TestConcurrentAppendsAreNeverInterleaved(t *testing.T) {
	j, path := newJournal(t, func(o *Options) { o.MaxBytes = 4096; o.Files = 50 })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := j.Append(entry(g*1000+i, "e", "h")); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	total := 0
	for i := 0; i < 50; i++ {
		name := path
		if i > 0 {
			name = fmt.Sprintf("%s.%d", path, i)
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for _, l := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
			if len(l) == 0 {
				continue
			}
			var e Entry
			if err := json.Unmarshal(l, &e); err != nil {
				t.Fatalf("interleaved/torn line in %s: %v", name, err)
			}
			total++
		}
	}
	if total != 800 {
		t.Errorf("%d lines, want 800", total)
	}
}

func TestGuardRefusesWritesOfASecondary(t *testing.T) {
	allowed := false
	j, path := newJournal(t, func(o *Options) {
		o.Guard = func() error {
			if allowed {
				return nil
			}
			return errors.New("not the master")
		}
	})
	if err := j.Append(entry(1, "e", "h")); err == nil || !strings.Contains(err.Error(), "not the master") {
		t.Fatalf("a secondary must not write: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the file must not even be created by a secondary")
	}
	allowed = true // promotion: everything that follows is appended
	if err := j.Append(entry(2, "e", "h")); err != nil {
		t.Fatal(err)
	}
	if got, _ := j.List(Filter{}); len(got) != 1 || got[0].ID != "id-0002" {
		t.Errorf("%v", got)
	}
}

func TestAppendAfterCloseDoesNotReopenTheFile(t *testing.T) {
	j, _ := newJournal(t, nil)
	_ = j.Append(entry(1, "e", "h"))
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(entry(2, "e", "h")); err == nil {
		t.Error("a closed journal must refuse appends")
	}
}

func TestAppendFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, _ := Open(Options{Path: filepath.Join(blocker, "actions.log")}) // a FILE where a directory is needed
	if err := j.Append(entry(1, "e", "h")); err == nil {
		t.Fatal("expected an error")
	}
}

// ── redaction (security) ─────────────────────────────────────────────────────

func TestRedactActionMasksEverySecret(t *testing.T) {
	raw := []byte(`{"type":"api","url":"https://user:pw-in-url@hooks.example.com/v1/notify?token=Q-TOKEN&a=1#frag-secret",
		"secret":"HMAC-SECRET","method":"POST",
		"headers":{"Authorization":"Bearer SUPER-SECRET-TOKEN","X-Api-Key":"KEY-123"},
		"body":{"password":"BODY-SECRET"},"cmd":"/usr/bin/notify","args":["--password","ARG-SECRET"],
		"append":"line with TEMPLATE-SECRET","max_retries":3,"timeout_seconds":10}`)
	out := RedactAction(raw)
	for _, secret := range []string{"HMAC-SECRET", "SUPER-SECRET-TOKEN", "KEY-123", "BODY-SECRET", "ARG-SECRET", "Q-TOKEN", "pw-in-url", "user:", "frag-secret", "v1/notify", "token=", "TEMPLATE-SECRET"} {
		if strings.Contains(out, secret) {
			t.Errorf("snapshot leaks %q: %s", secret, out)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("snapshot is not JSON: %v", err)
	}
	// what is useful for an audit stays
	if m["type"] != "api" || m["method"] != "POST" || m["cmd"] != "/usr/bin/notify" || m["max_retries"] != float64(3) {
		t.Errorf("non-sensitive fields lost: %s", out)
	}
	if h := m["headers"].(map[string]any); h["Authorization"] != Mask || h["X-Api-Key"] != Mask {
		t.Errorf("header keys must stay with masked values: %v", h)
	}
	if u := m["url"].(string); !strings.HasPrefix(u, "https://hooks.example.com/"+Mask+"?"+Mask) || strings.Contains(u, "v1/notify") {
		t.Errorf("url: %s", u)
	}
	if m["secret"] != Mask || m["body"] != Mask {
		t.Errorf("secret/body: %v %v", m["secret"], m["body"])
	}
	for _, a := range m["args"].([]any) {
		if a != Mask {
			t.Errorf("shell argument not masked: %v", a)
		}
	}
	if got := RedactAction([]byte("not json")); strings.Contains(got, "not json") {
		t.Errorf("unparsable input must not be echoed: %s", got)
	}
}

func TestRedactErrorMasksURLsInMessages(t *testing.T) {
	msg := "Post \"https://admin:hunter2@hooks.example.com/services/T0/B0/S3CRET?token=S3CRET&k=v\": dial tcp 10.0.0.1:443: connect: connection refused;\nsecond line http://a/b?sig=ZZZ."
	out := RedactError(msg)
	for _, secret := range []string{"hunter2", "S3CRET", "ZZZ", "admin:"} {
		if strings.Contains(out, secret) {
			t.Errorf("error leaks %q: %s", secret, out)
		}
	}
	if strings.Contains(out, "\n") {
		t.Error("an error must be one line")
	}
	if !strings.Contains(out, "connection refused") || !strings.Contains(out, "hooks.example.com") {
		t.Errorf("diagnostic value lost: %s", out)
	}
	if RedactError("") != "" || RedactError("plain failure") != "plain failure" {
		t.Error("plain messages are untouched")
	}
}

func TestRedactErrorMasksQuotedURLsWithoutScheme(t *testing.T) {
	for _, msg := range []string{
		`parse "http://bad host/x?token=S3CRET": invalid character " " in host name`,
		`parse "hooks.example.com/x?token=S3CRET": first path segment in URL cannot contain colon`,
		`Get "http://u:S3CRET@h/p?k=S3CRET#S3CRET": EOF`,
	} {
		if out := RedactError(msg); strings.Contains(out, "S3CRET") {
			t.Errorf("RedactError(%q) leaks: %s", msg, out)
		}
	}
}

func TestRedactActionMasksUnknownFieldsByDefault(t *testing.T) {
	out := RedactAction([]byte(`{"type":"webhook","token":"NEW-TOKEN","api_key":{"k":"NEW-KEY"},"password":["P"],"timeout_seconds":5}`))
	for _, secret := range []string{"NEW-TOKEN", "NEW-KEY", `"P"`} {
		if strings.Contains(out, secret) {
			t.Errorf("a field unknown to the allow-list must be masked, leaks %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, `"type":"webhook"`) || !strings.Contains(out, `"timeout_seconds":5`) {
		t.Errorf("kept fields lost: %s", out)
	}
}

func TestOpenRefusesASymbolicLinkAtTheJournalPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "actions.log")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	j, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	if err := j.Append(entry(1, "host.new", "h")); err == nil {
		t.Fatal("append through a symbolic link must be refused")
	}
	if got, _ := os.ReadFile(target); string(got) != "precious\n" {
		t.Errorf("the link target was written: %q", got)
	}
}

// R1: chat webhooks (Slack, Discord, Teams) carry their secret in the URL PATH.
func TestRedactURLNeverKeepsThePath(t *testing.T) {
	const secret = "SLACKPATHSECRET"
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/" + secret:                   "https://hooks.slack.com/***",
		"https://discord.com:8443/api/webhooks/1/" + secret + "?wait=true#f": "https://discord.com:8443/***?***",
		"https://u:p@h.example/":                                             "https://h.example",
		"not a url":                                                          Mask,
		"/relative/" + secret:                                                Mask,
	} {
		got := RedactURL(in)
		if got != want || strings.Contains(got, secret) {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
	snap := RedactAction([]byte(`{"type":"webhook","url":"https://hooks.slack.com/services/T0/B0/` + secret + `"}`))
	if strings.Contains(snap, secret) {
		t.Errorf("snapshot leaks the path secret: %s", snap)
	}
	for _, msg := range []string{
		`Post "https://hooks.slack.com/services/T0/B0/` + secret + `": dial tcp: connection refused`,
		`dial failed for https://hooks.slack.com/services/T0/B0/` + secret + ` (timeout)`,
	} {
		if out := RedactError(msg); strings.Contains(out, secret) {
			t.Errorf("RedactError leaks the path secret: %s", out)
		}
	}
}
