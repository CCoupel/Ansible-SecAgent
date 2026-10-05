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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
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

func (j *Journal) openLocked() error {
	if err := os.MkdirAll(filepath.Dir(j.opts.Path), 0o700); err != nil {
		return fmt.Errorf("actionlog: create directory: %w", err)
	}
	f, err := os.OpenFile(j.opts.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
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
		data, err := os.ReadFile(name)
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

// RedactAction renders a hook action definition for the journal: the type, method, timeouts and
// non-sensitive locations are kept, every value that may carry a secret is masked — the webhook
// HMAC secret, header VALUES (keys stay), the body, shell arguments, the query string and the
// userinfo of a URL. raw is the JSON of the action definition.
func RedactAction(raw []byte) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return `{"redacted":true}`
	}
	for k, v := range m {
		switch k {
		case "secret", "body", "append":
			m[k] = Mask
		case "headers":
			if h, ok := v.(map[string]any); ok {
				for hk := range h {
					h[hk] = Mask
				}
			} else {
				m[k] = Mask
			}
		case "args":
			if a, ok := v.([]any); ok {
				for i := range a {
					a[i] = Mask
				}
			} else {
				m[k] = Mask
			}
		case "url":
			if s, ok := v.(string); ok {
				m[k] = RedactURL(s)
			}
		}
	}
	// keys are emitted in a stable order (json.Marshal sorts map keys)
	out, err := json.Marshal(m)
	if err != nil {
		return `{"redacted":true}`
	}
	return string(out)
}

// RedactURL drops the userinfo and masks the values of the query string and the fragment.
func RedactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return Mask
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"="+Mask)
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

var urlInText = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// RedactError masks the URLs found in an error message (Go's HTTP errors quote the full URL,
// query string and userinfo included) and flattens it to one line.
func RedactError(msg string) string {
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
