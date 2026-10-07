// Package actionlog is the append-only journal of the hook actions (#161): one JSON line per
// executed action, in a file separate from the state file. It replaces the action_log table, which
// would have forced a full rewrite of the state file at every hook.
//
// It is an AUDIT trail: no fsync per line (the last lines may be lost in a crash), rotation by
// size, and no secret ever reaches it (see Redact*): a hook configuration holds webhook HMAC
// secrets and authorization headers.
package actionlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Defaults and environment.
const (
	// EnvPath overrides the journal path; default STATE_DIR/actions.log.
	EnvPath         = "RELAY_ACTION_LOG"
	DefaultFileName = "actions.log"
	// DefaultMaxBytes and DefaultFiles: 10 MiB × 5 files (actions.log, .1 … .4).
	DefaultMaxBytes = 10 << 20
	DefaultFiles    = 5
	// MaxList caps what one read returns.
	MaxList = 200
)

// Entry is one journal line.
type Entry struct {
	ID          string `json:"id"`
	Event       string `json:"event"`
	Hostname    string `json:"hostname"`
	ActionType  string `json:"action_type"`
	ActionIndex int    `json:"action_index"`
	// ConfigSnapshot is the action definition with every sensitive field masked (RedactAction).
	ConfigSnapshot string    `json:"config_snapshot,omitempty"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	DurationMs     int64     `json:"duration_ms"`
	ExecutedAt     time.Time `json:"executed_at"`
}

// Filter selects entries when reading (zero value = no filter, Limit 50).
type Filter struct {
	Event    string
	Hostname string
	Limit    int
}

// Options configures a Journal.
type Options struct {
	Path     string
	MaxBytes int64 // rotate when the next line would exceed it (default 10 MiB)
	Files    int   // total files kept, current included (default 5)
	// Guard is consulted before every write; an error skips the write. #163 connects the
	// master-only rule here (a secondary never writes). nil = writes allowed.
	Guard func() error
}

// Journal appends entries and reads them back.
type Journal struct {
	opts Options

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
}

// PathFromEnv returns RELAY_ACTION_LOG, else <stateDir>/actions.log.
func PathFromEnv(stateDir string) string {
	if p := os.Getenv(EnvPath); p != "" {
		return p
	}
	return filepath.Join(stateDir, DefaultFileName)
}

// Open prepares the journal (the file is created at the first append).
func Open(o Options) (*Journal, error) {
	if o.Path == "" {
		return nil, errors.New("actionlog: empty path")
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Files <= 0 {
		o.Files = DefaultFiles
	}
	return &Journal{opts: o}, nil
}

// SetGuard connects (or replaces) the write guard.
func (j *Journal) SetGuard(g func() error) {
	j.mu.Lock()
	j.opts.Guard = g
	j.mu.Unlock()
}

// Close releases the file handle.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closed = true // a late append (dispatcher still draining) must not reopen the file
	return j.closeLocked()
}

func (j *Journal) closeLocked() error {
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}

// Append writes one line. It never fsyncs. An error is returned for the caller to log as a
// warning; it must never block the dispatch of hooks.
func (j *Journal) Append(e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("actionlog: marshal: %w", err)
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("actionlog: journal is closed")
	}
	if j.opts.Guard != nil {
		if err := j.opts.Guard(); err != nil {
			return fmt.Errorf("actionlog: write refused by the guard: %w", err)
		}
	}
	if j.f == nil {
		if err := j.openLocked(); err != nil {
			return err
		}
	}
	if j.size > 0 && j.size+int64(len(line)) > j.opts.MaxBytes {
		if err := j.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := j.f.Write(line)
	j.size += int64(n)
	if err != nil {
		_ = j.closeLocked() // reopened (and re-measured) on the next append
		return fmt.Errorf("actionlog: write: %w", err)
	}
	return nil
}

// openLocked opens the journal with O_NOFOLLOW (Linux, the v1 scope): a symbolic link planted at
// the journal path is refused instead of being written through to its target.
func (j *Journal) openLocked() error {
	if err := os.MkdirAll(filepath.Dir(j.opts.Path), 0o700); err != nil {
		return fmt.Errorf("actionlog: create directory: %w", err)
	}
	f, err := os.OpenFile(j.opts.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("actionlog: open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("actionlog: stat: %w", err)
	}
	j.f, j.size = f, fi.Size()
	return nil
}

// rotateLocked shifts actions.log → .1 → .2 … and drops the oldest.
func (j *Journal) rotateLocked() error {
	if err := j.closeLocked(); err != nil {
		return fmt.Errorf("actionlog: close before rotation: %w", err)
	}
	p := j.opts.Path
	if err := os.Remove(fmt.Sprintf("%s.%d", p, j.opts.Files-1)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("actionlog: rotate: %w", err)
	}
	for i := j.opts.Files - 2; i >= 1; i-- {
		if err := os.Rename(fmt.Sprintf("%s.%d", p, i), fmt.Sprintf("%s.%d", p, i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("actionlog: rotate: %w", err)
		}
	}
	if j.opts.Files > 1 {
		if err := os.Rename(p, p+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("actionlog: rotate: %w", err)
		}
	} else if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("actionlog: rotate: %w", err)
	}
	return j.openLocked()
}

// readNoFollow reads a journal file without following a symbolic link (as openLocked does for
// writing): a link planted in place of the journal or of a rotated file is refused, its target is
// never read. A missing file is os.ErrNotExist.
func readNoFollow(name string) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("refusing to follow a symbolic link")
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// List returns the most recent entries first (current file, then the rotated ones), after the
// filter, capped at MaxList. Unreadable lines (a torn last line after a crash) are skipped.
func (j *Journal) List(f Filter) ([]Entry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxList {
		limit = MaxList
	}
	out := make([]Entry, 0, limit)
	for i := 0; i < j.opts.Files && len(out) < limit; i++ {
		name := j.opts.Path
		if i > 0 {
			name = fmt.Sprintf("%s.%d", j.opts.Path, i)
		}
		data, err := readNoFollow(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("actionlog: read %s: %w", name, err)
		}
		lines := bytes.Split(data, []byte{'\n'})
		for k := len(lines) - 1; k >= 0 && len(out) < limit; k-- {
			if len(bytes.TrimSpace(lines[k])) == 0 {
				continue
			}
			var e Entry
			if json.Unmarshal(lines[k], &e) != nil {
				continue
			}
			if f.Event != "" && e.Event != f.Event {
				continue
			}
			if f.Hostname != "" && e.Hostname != f.Hostname {
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// ── redaction ────────────────────────────────────────────────────────────────

// Mask replaces every sensitive value.
const Mask = "***"

// keptActionFields is the ALLOW-list of the action fields written as they are: they carry no
// secret (the action kind, the HTTP method, the retry count, the timeouts, the executable and
// file locations). Anything not listed here — and not handled by a dedicated rule below (url,
// headers) — is MASKED: secure by default. A new field of the action definition therefore never
// reaches the journal (nor GET /api/admin/hooks/log) in clear by omission; to keep it visible
// for the audit, classify it here. hooks.TestRedactActionClassifiesEveryActionField fails while
// an ActionDef field is classified nowhere.
var keptActionFields = map[string]bool{
	"type":            true,
	"method":          true,
	"cmd":             true,
	"path":            true,
	"max_retries":     true,
	"timeout_seconds": true,
}

// KeptActionFields returns the fields written in clear (copy, for tests and documentation).
func KeptActionFields() []string {
	out := make([]string, 0, len(keptActionFields))
	for k := range keptActionFields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RedactAction renders a hook action definition for the journal. Secure by default: only the
// fields of keptActionFields are kept as they are; the url keeps scheme, host and port only (see
// RedactURL); the header and env variable names are kept with masked values and the shell arguments become a list
// of masks; every other
// field — the webhook HMAC secret, the body, shell arguments, the append template, and any field
// added later — is masked. raw is the JSON of the action definition.
func RedactAction(raw []byte) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return `{"redacted":true}`
	}
	for k, v := range m {
		switch {
		case keptActionFields[k]:
		case k == "url":
			if s, ok := v.(string); ok {
				m[k] = RedactURL(s)
			} else {
				m[k] = Mask
			}
		case k == "headers", k == "env": // names stay, values are masked
			if h, ok := v.(map[string]any); ok {
				for hk := range h {
					h[hk] = Mask
				}
			} else {
				m[k] = Mask
			}
		case k == "args": // the number of arguments stays visible, never their values
			if a, ok := v.([]any); ok {
				for i := range a {
					a[i] = Mask
				}
			} else {
				m[k] = Mask
			}
		default:
			m[k] = Mask
		}
	}
	// keys are emitted in a stable order (json.Marshal sorts map keys)
	out, err := json.Marshal(m)
	if err != nil {
		return `{"redacted":true}`
	}
	return string(out)
}

// RedactURL keeps only the scheme, the host and the port. The path is replaced by "/***" and the
// query string by "?***": chat webhooks (Slack, Discord, Teams…) carry their secret IN THE PATH,
// and no path segment can be assumed harmless. The userinfo and the fragment are dropped. A value
// that is not an absolute URL is fully masked.
func RedactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Mask
	}
	out := u.Scheme + "://" + u.Host
	if p := u.EscapedPath(); p != "" && p != "/" {
		out += "/" + Mask
	}
	if u.RawQuery != "" || u.ForceQuery {
		out += "?" + Mask
	}
	return out
}

// quotedURLInError matches the url.Error forms: Get|Head|Post|Put|Patch|Delete|Options|parse "…".
var quotedURLInError = regexp.MustCompile(`\b(?:Get|Head|Post|Put|Patch|Delete|Options|Connect|Trace|parse) "(?:[^"\\]|\\.)*"`)

var urlInText = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// RedactError masks the URLs found in an error message (Go's HTTP errors quote the full URL,
// query string and userinfo included) and flattens it to one line.
func RedactError(msg string) string {
	// Go's url.Error quotes the URL (%q): `Post "<url>": …`, `parse "<url>": …`. The quoted part
	// is masked first, whatever it contains (a URL with a space or without a scheme is not matched
	// by the generic pattern below, and its query string would leak).
	msg = quotedURLInError.ReplaceAllStringFunc(msg, func(m string) string {
		i := strings.IndexByte(m, '"')
		return m[:i] + `"` + RedactURL(m[i+1:len(m)-1]) + `"`
	})
	msg = urlInText.ReplaceAllStringFunc(msg, func(m string) string {
		// a trailing punctuation belongs to the sentence, not to the URL
		trail := ""
		for len(m) > 0 && strings.ContainsRune(`.,;:)]}`, rune(m[len(m)-1])) {
			trail = string(m[len(m)-1]) + trail
			m = m[:len(m)-1]
		}
		return RedactURL(m) + trail
	})
	return strings.Join(strings.Fields(msg), " ")
}
