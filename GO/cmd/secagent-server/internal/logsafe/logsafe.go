// Package logsafe stops log forging: whatever a peer, an agent or a legacy database row managed to
// put in a value (a newline followed by a fake "[SECURITY WARNING]" line), one log call is ONE line.
package logsafe

import (
	"bytes"
	"io"
	"log"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type writer struct {
	mu sync.Mutex
	w  io.Writer
}

// Sanitize escapes the control characters of a log message (everything except the single
// trailing newline the logger adds): \n \r \t and the other C0/C1 controls, NEL, LS, PS.
func Sanitize(msg []byte) []byte {
	trailing := bytes.HasSuffix(msg, []byte("\n"))
	if trailing {
		msg = msg[:len(msg)-1]
	}
	var b strings.Builder
	for len(msg) > 0 {
		r, size := utf8.DecodeRune(msg)
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\x`)
			b.WriteString(strings.ToLower(string("0123456789abcdef"[msg[0]>>4]) + string("0123456789abcdef"[msg[0]&15])))
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r) || r == ' ' || r == ' ':
			b.WriteString(`\u`)
			b.WriteString(strings.ToLower(string("0123456789abcdef"[(r>>12)&15]) + string("0123456789abcdef"[(r>>8)&15]) + string("0123456789abcdef"[(r>>4)&15]) + string("0123456789abcdef"[r&15])))
		default:
			b.WriteRune(r)
		}
		msg = msg[size:]
	}
	if trailing {
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(Sanitize(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

var installOnce sync.Mutex

// Install wraps the standard logger's output (idempotent: an already wrapped output is kept).
func Install() {
	installOnce.Lock()
	defer installOnce.Unlock()
	if _, ok := log.Writer().(*writer); ok {
		return
	}
	log.SetOutput(&writer{w: log.Writer()})
}

// Installed reports whether the standard logger's output is the sanitizing wrapper.
func Installed() bool { _, ok := log.Writer().(*writer); return ok }
