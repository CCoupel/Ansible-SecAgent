package server

// Visible read-only state (#163, QA #160 R2): a write refused because this process holds no write
// guard, lost the lock or cannot confirm it is an explicit 503 {"error":"state_read_only"}, not a
// generic 500 db_error; the admin status and the local status file expose the write mode.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/lock"
)

// StateMode reports whether a write would be accepted right now: "read_write" or "read_only" with a
// short reason ("no write guard", "lock lost", "ownership not confirmed").
func (n *Node) StateMode() (mode, reason string) {
	select {
	case <-n.abort:
		return "read_only", "lock lost"
	default:
	}
	if n.cfg.WriteGuard == nil {
		return "read_only", "no write guard"
	}
	if err := n.cfg.WriteGuard(); err != nil {
		if errors.Is(err, lock.ErrNotMaster) {
			return "read_only", "lock lost"
		}
		return "read_only", "ownership not confirmed"
	}
	return "read_write", ""
}

// SetLockStatus gives the node the lock's status (role, beat) for the admin status.
func (n *Node) SetLockStatus(fn func() lock.Status) {
	n.instMu.Lock()
	n.lockStatus = fn
	n.instMu.Unlock()
}

// StatusFields are the instance fields added to /api/admin/status.
func (n *Node) StatusFields() map[string]interface{} {
	mode, reason := n.StateMode()
	out := map[string]interface{}{"state_mode": mode, "write_seq": n.store.WriteSeq()}
	if reason != "" {
		out["state_mode_reason"] = reason
	}
	n.instMu.Lock()
	role, id, ls := n.instRole, n.instID, n.lockStatus
	n.instMu.Unlock()
	if role != "" {
		out["role"], out["instance_id"] = role, id
	}
	if ls != nil {
		if st := ls(); !st.LastBeatOK.IsZero() {
			out["last_beat_at"] = st.LastBeatOK.UTC().Format(time.RFC3339)
			out["beat"] = st.Beat
		}
	}
	return out
}

// readOnlyRewrite turns the db_error 500 of a handler into 503 state_read_only when, and only when,
// the state really is read-only at that moment (a genuine database failure stays a 500).
func (n *Node) readOnlyRewrite(next http.Handler) http.Handler {
	var logMu sync.Mutex
	var lastLog time.Time
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &holdWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if rw.held && rw.status == http.StatusInternalServerError && isDBError(rw.buf.Bytes()) {
			if mode, reason := n.StateMode(); mode == "read_only" {
				logMu.Lock()
				due := time.Since(lastLog) > time.Minute
				if due {
					lastLog = time.Now()
				}
				logMu.Unlock()
				if due { // once a minute: a refused burst must not flood the log
					log.Printf("[WARN] write refused (503 state_read_only): %s — this instance is not the confirmed master", reason)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "state_read_only", "reason": reason})
				return
			}
		}
		rw.flush()
	})
}

func isDBError(b []byte) bool {
	var m map[string]string
	return json.Unmarshal(bytes.TrimSpace(b), &m) == nil && m["error"] == "db_error"
}

// holdWriter keeps a 500 response (status and body) so that it can be replaced; every other
// response is passed through untouched and immediately.
type holdWriter struct {
	http.ResponseWriter
	status int
	held   bool
	buf    bytes.Buffer
}

func (h *holdWriter) WriteHeader(code int) {
	if h.status != 0 {
		return
	}
	h.status = code
	if code == http.StatusInternalServerError {
		h.held = true
		return
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *holdWriter) Write(b []byte) (int, error) {
	if h.status == 0 {
		h.WriteHeader(http.StatusOK)
	}
	if h.held {
		return h.buf.Write(b)
	}
	return h.ResponseWriter.Write(b)
}

// flush releases a held 500 as it was.
func (h *holdWriter) flush() {
	if h.held {
		h.ResponseWriter.WriteHeader(h.status)
		_, _ = h.ResponseWriter.Write(h.buf.Bytes())
		h.held = false
	}
}

// Hijack and Flush keep WebSocket upgrades and streaming working through the wrapper.
func (h *holdWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := h.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	return hj.Hijack()
}

func (h *holdWriter) Flush() {
	if f, ok := h.ResponseWriter.(http.Flusher); ok && !h.held {
		f.Flush()
	}
}
