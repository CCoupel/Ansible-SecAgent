package hooks

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
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
//
// Processing model (#183): a POOL OF WORKERS (RELAY_HOOKS_MAX_CONCURRENT_ACTIONS, default 64), each
// with its own bounded FIFO. An event goes to the worker chosen by a hash of its hostname, and the
// worker runs the actions of the event one after the other. Consequences, documented in
// HOOKS_SPEC.md:
//   - back-pressure instead of loss: no action is ever dropped because "too many are running";
//     they wait in the queue, which is sized for a fleet of more than 3 000 hosts;
//   - order: preserved PER HOSTNAME (host.up then host.down of one host never swap), no guarantee
//     between hosts;
//   - isolation: a slow webhook blocks its own worker only (bounded by timeout_seconds), the other
//     hosts keep progressing;
//   - bound: the queue holds RELAY_HOOKS_QUEUE_SIZE events in all (default 10 000, split over the
//     workers); beyond it an event is rejected, COUNTED (DroppedEvents) and reported by one
//     aggregated warning + journal entry per minute, never one line per event.
type Dispatcher struct {
	mu     sync.RWMutex
	config *HooksConfig

	store ActionLogger

	workers      []*hookWorker
	perWorkerCap int

	pending  atomic.Int64 // events accepted and not yet fully processed (queued or running)
	inflight atomic.Int64 // events being processed right now
	stopping atomic.Bool  // Drain was called: no new event is accepted

	droppedEvents  atomic.Int64 // events rejected: queue full or dispatcher stopping
	droppedActions atomic.Int64 // actions lost with queued events at an abrupt stop
	started        atomic.Bool
	wg             sync.WaitGroup

	// upstream, when set, receives every LOCAL event of a propagated kind (see Propagated) so that
	// it can be forwarded to the parent. Events received from a child (DispatchChain) are never
	// handed to it: a received event is never forwarded back up from here.
	upstream func(event, hostname, status, enrolledAt string)

	// journalWarn rate-limits the warning logged when the journal cannot be written: one per
	// minute (with the count of the suppressed ones), not one per action.
	warnMu    sync.Mutex
	warnLast  time.Time
	warnQuiet int
	warnNow   func() time.Time // test seam, nil = time.Now

	abandonMu sync.Mutex
	abandoned []dispatchJob

	// drop report: what was already announced (aggregated warning + journal entry per period).
	reportMu      sync.Mutex
	reportedEv    int64
	reportedAct   int64
	reportEvery   time.Duration // test seam
	drainInterval time.Duration // test seam

	webhookExec *WebhookExecutor
	shellExec   *ShellExecutor
	fileExec    *FileExecutor
	apiExec     *APIExecutor
}

type hookWorker struct {
	ch chan dispatchJob
}

// Stats is a snapshot of the dispatcher, exposed by GET /api/admin/status.
type Stats struct {
	Workers        int   `json:"workers"`
	QueueCapacity  int   `json:"queue_capacity"`
	QueueDepth     int   `json:"hooks_queue_depth"`
	Inflight       int64 `json:"hooks_inflight"`
	DroppedEvents  int64 `json:"hooks_dropped_events"`
	DroppedActions int64 `json:"hooks_dropped_actions"`
}

// GlobalDispatcher is the server-wide singleton injected from main.go.
var GlobalDispatcher *Dispatcher

// Defaults of the queue (RELAY_HOOKS_QUEUE_SIZE) and of the reporting / shutdown delays.
const (
	// DefaultQueueSize holds several events per host for a fleet of more than 3 000 hosts (a
	// reconnection of everybody gives host.up, plus relay.* events). Memory: an event is about
	// 200 bytes plus its strings, so ~2–3 MB at the default.
	DefaultQueueSize = 10000
	// DefaultDropReportInterval is the period of the aggregated drop warning / journal entry.
	DefaultDropReportInterval = time.Minute
	// DefaultDrainTimeout bounds the flush of the queue on a clean stop.
	DefaultDrainTimeout = 10 * time.Second
)

// QueueSizeFromEnv returns RELAY_HOOKS_QUEUE_SIZE (a positive integer), else DefaultQueueSize.
func QueueSizeFromEnv() int {
	if n, err := strconv.Atoi(os.Getenv("RELAY_HOOKS_QUEUE_SIZE")); err == nil && n > 0 {
		return n
	}
	return DefaultQueueSize
}

// NewDispatcher creates a Dispatcher whose queues hold bufSize events in all (split over the
// workers, at least one slot each when bufSize > 0; 0 = unbuffered, an event is accepted only when
// a worker is waiting).
func NewDispatcher(store ActionLogger, bufSize int) *Dispatcher {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // do not follow 3xx
		},
	}
	n := maxConcurrentActions()
	per := 0
	if bufSize > 0 {
		per = (bufSize + n - 1) / n
	}
	d := &Dispatcher{
		store:         store,
		perWorkerCap:  per,
		workers:       make([]*hookWorker, n),
		reportEvery:   DefaultDropReportInterval,
		drainInterval: 10 * time.Millisecond,
		webhookExec:   &WebhookExecutor{client: client},
		shellExec:     &ShellExecutor{},
		fileExec:      &FileExecutor{},
		apiExec:       &APIExecutor{client: client},
	}
	for i := range d.workers {
		d.workers[i] = &hookWorker{ch: make(chan dispatchJob, per)}
	}
	return d
}

// DefaultMaxConcurrentActions is the default number of workers, i.e. of events processed at
// once; RELAY_HOOKS_MAX_CONCURRENT_ACTIONS overrides it (read when the dispatcher is created).
const DefaultMaxConcurrentActions = 64

func maxConcurrentActions() int {
	if n, err := strconv.Atoi(os.Getenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS")); err == nil && n > 0 {
		return n
	}
	return DefaultMaxConcurrentActions
}

// DroppedEvents returns how many events were rejected (queue full, or dispatcher stopping).
func (d *Dispatcher) DroppedEvents() int64 { return d.droppedEvents.Load() }

// DroppedActions returns how many actions were lost with events still queued at an abrupt stop
// (it must stay 0 while the dispatcher runs).
func (d *Dispatcher) DroppedActions() int64 { return d.droppedActions.Load() }

// Stats returns a snapshot of the queue and of the counters.
func (d *Dispatcher) Stats() Stats {
	depth := 0
	for _, w := range d.workers {
		depth += len(w.ch)
	}
	return Stats{
		Workers:        len(d.workers),
		QueueCapacity:  d.perWorkerCap * len(d.workers),
		QueueDepth:     depth,
		Inflight:       d.inflight.Load(),
		DroppedEvents:  d.droppedEvents.Load(),
		DroppedActions: d.droppedActions.Load(),
	}
}

// workerFor returns the worker that owns a hostname: the same host always lands on the same
// worker, which is what preserves the order of its events.
func (d *Dispatcher) workerFor(hostname string) *hookWorker {
	h := fnv.New32a()
	_, _ = h.Write([]byte(hostname))
	return d.workers[int(h.Sum32()%uint32(len(d.workers)))]
}

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

// Start launches the workers and the drop reporter. It returns immediately; they stop when ctx
// is cancelled: an ABRUPT stop (the events still queued are lost, counted and logged). For a clean
// stop call Drain first.
func (d *Dispatcher) Start(ctx context.Context) {
	if !d.started.CompareAndSwap(false, true) {
		return
	}
	log.Printf("[HOOKS] Dispatcher started (%d workers, queue %d events)", len(d.workers), d.perWorkerCap*len(d.workers))
	for _, w := range d.workers {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-w.ch:
					if ctx.Err() != nil { // stopping: do not start it, it is counted as lost
						d.abandon(job)
						return
					}
					d.inflight.Add(1)
					d.processJob(ctx, job)
					d.inflight.Add(-1)
					d.pending.Add(-1)
				}
			}
		}()
	}
	go func() { // not part of wg: it waits for the workers on stop
		tick := time.NewTicker(d.reportEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				d.stopReport()
				return
			case <-tick.C:
				d.reportDrops()
			}
		}
	}()
}

// abandon keeps a job a worker took out of its queue just as the dispatcher was stopping: it is
// accounted with the queued ones by stopReport.
func (d *Dispatcher) abandon(job dispatchJob) {
	d.abandonMu.Lock()
	d.abandoned = append(d.abandoned, job)
	d.abandonMu.Unlock()
}

// stopReport runs once the context is cancelled: it accounts for what was still queued, then
// announces the drops one last time.
func (d *Dispatcher) stopReport() {
	d.wg.Wait() // the workers are gone: what is left in the queues is lost
	lostEvents, lostActions := 0, 0
	d.abandonMu.Lock()
	for _, job := range d.abandoned {
		lostEvents++
		lostActions += d.actionsOf(job)
		d.pending.Add(-1)
	}
	d.abandoned = nil
	d.abandonMu.Unlock()
	for _, w := range d.workers {
		for drained := false; !drained; {
			select {
			case job := <-w.ch:
				lostEvents++
				lostActions += d.actionsOf(job)
				d.pending.Add(-1)
			default:
				drained = true
			}
		}
	}
	if lostEvents > 0 {
		d.droppedEvents.Add(int64(lostEvents))
		d.droppedActions.Add(int64(lostActions))
		log.Printf("[HOOKS] Dispatcher stopped: %d queued event(s) not processed (%d action(s)) — they are lost", lostEvents, lostActions)
	} else {
		log.Printf("[HOOKS] Dispatcher stopped")
	}
	d.reportDrops()
}

// journalWarnInterval is the minimum delay between two journal-failure warnings.
const journalWarnInterval = time.Minute

// warnJournal logs a journal write failure at most once per journalWarnInterval.
func (d *Dispatcher) warnJournal(err error) {
	d.warnMu.Lock()
	now := time.Now()
	if d.warnNow != nil {
		now = d.warnNow()
	}
	if !d.warnLast.IsZero() && now.Sub(d.warnLast) < journalWarnInterval {
		d.warnQuiet++
		d.warnMu.Unlock()
		return
	}
	quiet := d.warnQuiet
	d.warnLast, d.warnQuiet = now, 0
	d.warnMu.Unlock()
	if quiet > 0 {
		log.Printf("[WARN] hooks: action journal: %v (%d similar warning(s) suppressed)", err, quiet)
		return
	}
	log.Printf("[WARN] hooks: action journal: %v", err)
}

// actionsOf returns the number of actions an event would have run with the current configuration.
func (d *Dispatcher) actionsOf(job dispatchJob) int {
	d.mu.RLock()
	cfg := d.config
	d.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	for _, h := range cfg.Hooks {
		if h.Event == job.event && h.Filter.Matches(job.relayChain) {
			return len(h.Actions)
		}
	}
	return 0
}

// Drain stops accepting events and waits, at most timeout, until everything already accepted is
// processed. It returns the number of events still pending when the delay is over (0 = flushed).
// Call it on a clean stop, before cancelling the context given to Start.
func (d *Dispatcher) Drain(timeout time.Duration) int64 {
	d.stopping.Store(true)
	deadline := time.Now().Add(timeout)
	for d.pending.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(d.drainInterval)
	}
	return d.pending.Load()
}

// reportDrops announces, once per period, what was dropped since the previous report: ONE
// warning and ONE journal entry (action_type "dropped") instead of a line per rejected event.
func (d *Dispatcher) reportDrops() {
	d.reportMu.Lock()
	ev, act := d.droppedEvents.Load(), d.droppedActions.Load()
	newEv, newAct := ev-d.reportedEv, act-d.reportedAct
	d.reportedEv, d.reportedAct = ev, act
	d.reportMu.Unlock()
	if newEv <= 0 && newAct <= 0 {
		return
	}
	msg := fmt.Sprintf("%d event(s) and %d action(s) dropped since the last report (totals: %d events, %d actions); "+
		"queue full or stopping, see RELAY_HOOKS_QUEUE_SIZE", newEv, newAct, ev, act)
	log.Printf("[WARN] hooks: %s", msg)
	if d.store != nil {
		if err := d.store.Append(actionlog.Entry{
			ID: uuid.New().String(), Event: "*", ActionType: "dropped", Error: msg, ExecutedAt: time.Now().UTC(),
		}); err != nil {
			d.warnJournal(err)
		}
	}
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
// It never blocks: an event the queue cannot take is rejected and counted (DroppedEvents).
func (d *Dispatcher) DispatchChain(event, hostname, status, enrolledAt string, relayChain []string) {
	if d.stopping.Load() {
		d.droppedEvents.Add(1)
		return
	}
	job := dispatchJob{
		event:      event,
		hostname:   hostname,
		status:     status,
		enrolledAt: enrolledAt,
		timestamp:  time.Now().UTC().Format(time.RFC3339),
		relayChain: append([]string(nil), relayChain...),
	}
	d.pending.Add(1)
	select {
	case d.workerFor(hostname).ch <- job:
	default:
		d.pending.Add(-1)
		d.droppedEvents.Add(1) // announced by reportDrops, not logged one by one
	}
}

// processJob finds the matching HookDef and runs its actions one after the other, in order.
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
			if ctx.Err() != nil {
				d.droppedActions.Add(int64(len(hookDef.Actions) - idx))
				return
			}
			d.executeAction(ctx, job, action, idx, vars)
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
		log.Printf("[WARN] hooks: unknown action type %q for event %q hostname=%q", action.Type, job.event, job.hostname)
		return
	}

	success, errMsg, durationMs := ex.Execute(ctx, action, vars)

	// The hook configuration holds secrets (webhook HMAC key, authorization headers, URLs with
	// tokens): the journal gets a masked snapshot and an error with its URLs masked.
	raw, _ := json.Marshal(action)
	safeErr := actionlog.RedactError(errMsg) // Go's errors quote the URL, query-string tokens included
	entry := actionlog.Entry{
		ID:             uuid.New().String(),
		Event:          job.event,
		Hostname:       job.hostname,
		ActionType:     action.Type,
		ActionIndex:    idx,
		ConfigSnapshot: actionlog.RedactAction(raw),
		Success:        success,
		Error:          safeErr,
		DurationMs:     durationMs,
		ExecutedAt:     time.Now().UTC(),
	}

	if d.store != nil {
		if err := d.store.Append(entry); err != nil {
			d.warnJournal(err)
		}
	}

	if success {
		log.Printf("[HOOKS] %s %s action[%d] type=%s OK duration=%dms", job.event, job.hostname, idx, action.Type, durationMs)
	} else {
		log.Printf("[HOOKS] %s %s action[%d] type=%s FAIL: %s duration=%dms", job.event, job.hostname, idx, action.Type, safeErr, durationMs) // never the raw errMsg: server logs are shipped elsewhere
	}
}
