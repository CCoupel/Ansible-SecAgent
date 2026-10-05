package hooks

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

// ── Job ───────────────────────────────────────────────────────────────────────

type dispatchJob struct {
	event      string
	hostname   string
	status     string
	enrolledAt string   // only set for host.new
	timestamp  string   // RFC3339 — captured at Dispatch time
	relayChain []string // relays traversed since the origin; empty for an event of this node
}

// ── ActionLogger interface ─────────────────────────────────────────────────────

// ActionLogger persists execution results (the append-only journal, #161). An error must never
// block the dispatch: it is logged as a warning.
type ActionLogger interface {
	Append(entry actionlog.Entry) error
}

// buildVars constructs the template variable map from a dispatch job's fields.
func buildVars(event, hostname, status, timestamp, enrolledAt string, relayChain []string) map[string]string {
	origin := ""
	if len(relayChain) > 0 {
		origin = relayChain[0]
	}
	return map[string]string{
		"event":        event,
		"hostname":     hostname,
		"status":       status,
		"timestamp":    timestamp,
		"enrolled_at":  enrolledAt,
		"relay_chain":  strings.Join(relayChain, ","),
		"relay_origin": origin,
	}
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

// Dispatcher receives lifecycle events and executes all configured hooks asynchronously.
type Dispatcher struct {
	mu     sync.RWMutex
	config *HooksConfig

	queue chan dispatchJob
	store ActionLogger

	// slots bounds the actions running at once (one goroutine each): slow webhooks with many
	// retries, or a burst of events from a hostile child, cannot pile goroutines up. Actions that
	// find no free slot are dropped with a warning (the dispatch never blocks) and counted.
	slots   chan struct{}
	dropped atomic.Int64

	// upstream, when set, receives every LOCAL event of a propagated kind (see Propagated) so that
	// it can be forwarded to the parent. Events received from a child (DispatchChain) are never
	// handed to it: a received event is never forwarded back up from here.
	upstream func(event, hostname, status, enrolledAt string)

	webhookExec *WebhookExecutor
	shellExec   *ShellExecutor
	fileExec    *FileExecutor
	apiExec     *APIExecutor
}

// GlobalDispatcher is the server-wide singleton injected from main.go.
var GlobalDispatcher *Dispatcher

// NewDispatcher creates a Dispatcher with a buffered queue of bufSize events.
func NewDispatcher(store ActionLogger, bufSize int) *Dispatcher {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // do not follow 3xx
		},
	}
	return &Dispatcher{
		slots:       make(chan struct{}, maxConcurrentActions()),
		queue:       make(chan dispatchJob, bufSize),
		store:       store,
		webhookExec: &WebhookExecutor{client: client},
		shellExec:   &ShellExecutor{},
		fileExec:    &FileExecutor{},
		apiExec:     &APIExecutor{client: client},
	}
}

// DefaultMaxConcurrentActions is the default bound of simultaneously running hook actions;
// RELAY_HOOKS_MAX_CONCURRENT_ACTIONS overrides it (read when the dispatcher is created).
const DefaultMaxConcurrentActions = 64

func maxConcurrentActions() int {
	if n, err := strconv.Atoi(os.Getenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS")); err == nil && n > 0 {
		return n
	}
	return DefaultMaxConcurrentActions
}

// DroppedActions returns how many actions were dropped because the concurrency bound was reached.
func (d *Dispatcher) DroppedActions() int64 { return d.dropped.Load() }

// SetConfig replaces the active hooks configuration.
// Thread-safe; called from main.go at startup and on SIGHUP.
func (d *Dispatcher) SetConfig(cfg *HooksConfig) {
	d.mu.Lock()
	d.config = cfg
	d.mu.Unlock()

	if cfg == nil {
		log.Println("[HOOKS] Config cleared — 0 hooks active")
	} else {
		log.Printf("[HOOKS] Config loaded — %d hook(s) active", len(cfg.Hooks))
	}
}

// Start launches the background goroutine that drains the event queue.
// Returns immediately; the goroutine exits when ctx is cancelled.
func (d *Dispatcher) Start(ctx context.Context) {
	go func() {
		log.Println("[HOOKS] Dispatcher started")
		for {
			select {
			case <-ctx.Done():
				log.Printf("[HOOKS] Dispatcher stopped: %v", ctx.Err())
				return
			case job, ok := <-d.queue:
				if !ok {
					return
				}
				d.processJob(ctx, job)
			}
		}
	}()
}

// Propagated reports whether an event kind is propagated upstream through the relay tree.
func Propagated(event string) bool {
	switch event {
	case "host.up", "host.down", "host.new":
		return true
	}
	return false
}

// SetUpstream installs the forwarder of local events to the parent (nil = none). Thread-safe.
func (d *Dispatcher) SetUpstream(fn func(event, hostname, status, enrolledAt string)) {
	d.mu.Lock()
	d.upstream = fn
	d.mu.Unlock()
}

// Dispatch enqueues a LOCAL event (relay_chain empty) for asynchronous hook execution and, for
// propagated kinds, hands it to the upstream forwarder.
// Never blocks: events are silently dropped when the queue is full.
// enrolledAt is only non-empty for host.new events.
func (d *Dispatcher) Dispatch(event, hostname, status, enrolledAt string) {
	d.DispatchChain(event, hostname, status, enrolledAt, nil)
	if !Propagated(event) {
		return
	}
	d.mu.RLock()
	fwd := d.upstream
	d.mu.RUnlock()
	if fwd != nil {
		fwd(event, hostname, status, enrolledAt)
	}
}

// DispatchChain enqueues an event that travelled through the given relays (origin first) for hook
// execution on THIS node only: it never forwards (the caller forwards a received event itself).
func (d *Dispatcher) DispatchChain(event, hostname, status, enrolledAt string, relayChain []string) {
	job := dispatchJob{
		event:      event,
		hostname:   hostname,
		status:     status,
		enrolledAt: enrolledAt,
		timestamp:  time.Now().UTC().Format(time.RFC3339),
		relayChain: append([]string(nil), relayChain...),
	}
	select {
	case d.queue <- job:
	default:
		log.Printf("[WARN] hooks queue full, dropping event=%s hostname=%s", event, hostname)
	}
}

// processJob finds the matching HookDef and launches one goroutine per action.
func (d *Dispatcher) processJob(ctx context.Context, job dispatchJob) {
	d.mu.RLock()
	cfg := d.config
	d.mu.RUnlock()

	if cfg == nil {
		return
	}

	vars := buildVars(job.event, job.hostname, job.status, job.timestamp, job.enrolledAt, job.relayChain)

	for _, hookDef := range cfg.Hooks {
		if hookDef.Event != job.event || !hookDef.Filter.Matches(job.relayChain) {
			continue
		}
		for idx, action := range hookDef.Actions {
			action := action // capture for goroutine
			idx := idx
			select {
			case d.slots <- struct{}{}:
			default:
				// log at most once per 100 drops: the log itself must not become the flood
				if n := d.dropped.Add(1); n%100 == 1 {
					log.Printf("[SECURITY WARNING] hooks: %d concurrent actions running, action dropped (total dropped=%d) event=%s hostname=%q",
						cap(d.slots), n, job.event, job.hostname)
				}
				continue
			}
			go func() {
				defer func() { <-d.slots }()
				d.executeAction(ctx, job, action, idx, vars)
			}()
		}
		return // first matching HookDef wins
	}
}

// executeAction runs one action and appends the result to the action journal.
func (d *Dispatcher) executeAction(ctx context.Context, job dispatchJob, action ActionDef, idx int, vars map[string]string) {
	var ex Executor
	switch action.Type {
	case "webhook":
		ex = d.webhookExec
	case "shell":
		ex = d.shellExec
	case "file":
		ex = d.fileExec
	case "api":
		ex = d.apiExec
	default:
		log.Printf("[WARN] hooks: unknown action type %q for event %s hostname=%s", action.Type, job.event, job.hostname)
		return
	}

	success, errMsg, durationMs := ex.Execute(ctx, action, vars)

	// The hook configuration holds secrets (webhook HMAC key, authorization headers, URLs with
	// tokens): the journal gets a masked snapshot and an error with its URLs masked.
	raw, _ := json.Marshal(action)
	entry := actionlog.Entry{
		ID:             uuid.New().String(),
		Event:          job.event,
		Hostname:       job.hostname,
		ActionType:     action.Type,
		ActionIndex:    idx,
		ConfigSnapshot: actionlog.RedactAction(raw),
		Success:        success,
		Error:          actionlog.RedactError(errMsg),
		DurationMs:     durationMs,
		ExecutedAt:     time.Now().UTC(),
	}

	if d.store != nil {
		if err := d.store.Append(entry); err != nil {
			log.Printf("[WARN] hooks: action journal: %v", err)
		}
	}

	if success {
		log.Printf("[HOOKS] %s %s action[%d] type=%s OK duration=%dms", job.event, job.hostname, idx, action.Type, durationMs)
	} else {
		log.Printf("[HOOKS] %s %s action[%d] type=%s FAIL: %s duration=%dms", job.event, job.hostname, idx, action.Type, errMsg, durationMs)
	}
}
