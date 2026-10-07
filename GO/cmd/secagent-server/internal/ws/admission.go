package ws

// Admission of tasks (#179, L2): RegisterFuture (agent tasks) and RegisterRelayTaskFuture (tasks
// relayed to a child) are the SINGLE admission point. They enforce, before anything is sent:
//
//	MAX_TASKS_PER_AGENT      tasks in flight of one agent on this node          -> ErrAgentBusy       (429)
//	MAX_TASKS_INFLIGHT       tasks in flight on this node, relayed ones included -> ErrTooManyTasks    (429)
//	MAX_STDOUT_BUFFER_TOTAL  memory budget of the stdout buffers: every admitted task RESERVES
//	                         stdoutMaxBytes (5 MiB, the most it may hold) at admission, so
//	                         (tasks in flight + 1) x 5 MiB must fit in the budget   -> ErrMemoryBudget   (503)
//
// Every path that ends a task calls releaseTask, which is idempotent: the counters are decremented
// exactly once per admitted task (result, timeout, disconnection, revocation, loss of the lock...).
// A relayed task is counted at EVERY hop (each node admits it in its own counters).

import (
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Typed admission errors (the messages are the error codes of the REST contract).
var (
	ErrAgentBusy    = errors.New("agent_busy")
	ErrTooManyTasks = errors.New("too_many_tasks")
	ErrMemoryBudget = errors.New("memory_budget_exhausted")
)

// Defaults of the limits.
const (
	DefaultMaxTasksPerAgent   = 10
	DefaultMaxTasksInflight   = 1000
	DefaultMaxStdoutBufferTot = int64(1 << 30) // 1 GiB
)

// RetryAfterSeconds is the Retry-After (seconds) the REST layer sends with each refusal.
func RetryAfterSeconds(err error) int {
	switch {
	case errors.Is(err, ErrMemoryBudget):
		return 5
	case errors.Is(err, ErrTooManyTasks):
		return 2
	default:
		return 1
	}
}

// IsAdmissionError reports whether err is one of the typed admission refusals.
func IsAdmissionError(err error) bool {
	return errors.Is(err, ErrAgentBusy) || errors.Is(err, ErrTooManyTasks) || errors.Is(err, ErrMemoryBudget)
}

type admission struct {
	host   string // "" for a task relayed to a child (counted globally only)
	stdout int64  // bytes held by this task's stdout buffer
}

var (
	admMu         sync.Mutex
	admitted      = map[string]*admission{}
	perHostCount  = map[string]int{}
	inflightTotal int
	stdoutHeld    int64

	maxPerAgent    = DefaultMaxTasksPerAgent
	maxInflight    = DefaultMaxTasksInflight
	maxStdoutTotal = DefaultMaxStdoutBufferTot

	refusedLogs = newRefusalLogger()
)

// SetTaskLimits sets the limits (0 or negative keeps the default). Already admitted tasks are kept.
func SetTaskLimits(perAgent, inflight int, stdoutBudget int64) {
	admMu.Lock()
	defer admMu.Unlock()
	maxPerAgent, maxInflight, maxStdoutTotal = DefaultMaxTasksPerAgent, DefaultMaxTasksInflight, DefaultMaxStdoutBufferTot
	if perAgent > 0 {
		maxPerAgent = perAgent
	}
	if inflight > 0 {
		maxInflight = inflight
	}
	if stdoutBudget > 0 {
		maxStdoutTotal = stdoutBudget
	}
}

// admitTask counts a task. host == "" is a task relayed to a child (global limits only). A task id that
// is already admitted is released first (a re-registration never counts twice).
func admitTask(taskID, host string) error {
	admMu.Lock()
	defer admMu.Unlock()
	if old, ok := admitted[taskID]; ok {
		releaseLocked(taskID, old)
	}
	var err error
	switch {
	case host != "" && perHostCount[host] >= maxPerAgent:
		err = ErrAgentBusy
	case inflightTotal >= maxInflight:
		err = ErrTooManyTasks
	case int64(inflightTotal+1)*int64(stdoutMaxBytes) > maxStdoutTotal:
		// a reservation, not the bytes held so far: the stdout of a task arrives AFTER its admission, so
		// counting what is held would admit far more tasks than the memory can take (#179 load test)
		err = ErrMemoryBudget
	}
	if err != nil {
		refusedLogs.log(err, host, perHostCount[host], inflightTotal, stdoutHeld)
		return err
	}
	admitted[taskID] = &admission{host: host}
	inflightTotal++
	if host != "" {
		perHostCount[host]++
	}
	return nil
}

// releaseTask frees the slot (and the stdout bytes) of a task. Idempotent.
func releaseTask(taskID string) {
	admMu.Lock()
	defer admMu.Unlock()
	if a, ok := admitted[taskID]; ok {
		releaseLocked(taskID, a)
	}
}

func releaseLocked(taskID string, a *admission) {
	delete(admitted, taskID)
	inflightTotal--
	if a.host != "" {
		if perHostCount[a.host]--; perHostCount[a.host] <= 0 {
			delete(perHostCount, a.host)
		}
	}
	stdoutHeld -= a.stdout
}

// reserveStdout accounts n more bytes of stdout for an admitted task and returns how many may be
// kept (the rest is truncated): bounded by the 5 MiB of the task and by the global budget. A task that
// is not admitted keeps nothing.
func reserveStdout(taskID string, n int64) int64 {
	admMu.Lock()
	defer admMu.Unlock()
	a, ok := admitted[taskID]
	if !ok {
		return 0
	}
	allow := n
	if room := int64(stdoutMaxBytes) - a.stdout; allow > room {
		allow = room
	}
	if room := maxStdoutTotal - stdoutHeld; allow > room {
		allow = room
	}
	if allow < 0 {
		allow = 0
	}
	a.stdout += allow
	stdoutHeld += allow
	return allow
}

// refundStdout gives back n reserved bytes (the chunk kept was shorter than reserved).
func refundStdout(taskID string, n int64) {
	admMu.Lock()
	defer admMu.Unlock()
	if a, ok := admitted[taskID]; ok && n > 0 {
		a.stdout -= n
		stdoutHeld -= n
	}
}

// cutUTF8 truncates s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int64) string {
	if int64(len(s)) <= n {
		return s
	}
	cut := int(n)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ── observability (status, tests) ────────────────────────────────────────────

func inFlightOf(host string) int {
	admMu.Lock()
	defer admMu.Unlock()
	return perHostCount[host]
}

func inFlightAll() int {
	admMu.Lock()
	defer admMu.Unlock()
	return inflightTotal
}

func stdoutHeldBytes() int64 {
	admMu.Lock()
	defer admMu.Unlock()
	return stdoutHeld
}

// TasksInFlight returns the number of tasks in flight on this node (local and relayed).
func TasksInFlight() int { return inFlightAll() }

// ── refusal log: no command content, bounded rate ────────────────────────────

type refusalLogger struct {
	last       atomic.Int64 // unix nanoseconds of the last line
	suppressed atomic.Int64
}

func newRefusalLogger() *refusalLogger { return &refusalLogger{} }

// log writes at most one line per second; the others are counted and reported in the next line.
// Only the host name and the counters are logged: never a command, a stdin or a token.
func (l *refusalLogger) log(err error, host string, hostCount, total int, held int64) {
	now := time.Now().UnixNano()
	prev := l.last.Load()
	if now-prev < int64(time.Second) || !l.last.CompareAndSwap(prev, now) {
		l.suppressed.Add(1)
		return
	}
	log.Printf("[SECURITY WARNING] task refused at admission: reason=%s host=%q host_tasks=%d tasks=%d stdout_held=%d suppressed_since_last=%d",
		err.Error(), host, hostCount, total, held, l.suppressed.Swap(0))
}
