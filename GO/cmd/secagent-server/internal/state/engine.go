// Package state is the single-file state engine of a relay (v3.0.3, #159): the permanent data
// (agents, keys, token hashes, blacklist, relay nodes, encrypted server secrets) lives in memory,
// is read through indexes, and is persisted by ONE writer as an atomic replacement of
// relay.state. It replaces SQLite, which cannot be shared between two instances (WAL on NFS).
//
// The package is independent of storage and of the handlers, and uses no CGO.
package state

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"secagent-server/cmd/secagent-server/internal/crypto"
)

// Options configures an Engine.
type Options struct {
	// Dir is STATE_DIR (default DefaultStateDir).
	Dir string
	// FS is the file system (default OSFS); tests inject faults.
	FS FS
	// MaxBytes is the hard ceiling of the state file (default DefaultMaxBytes).
	MaxBytes int64
	// Instance identifies the writer in the file (writer_instance).
	Instance string
	// BeforeWrite is the write guard, called under the writer before anything is created on disk
	// and again just before the rename (the lock may be lost during the fsync): an error cancels
	// the write. With NO guard the engine refuses every write (no file, not even
	// relay.state.tmp), so two instances started together on one STATE_DIR can not both write.
	// #163 connects the lock-identity check here; it can also be set later with SetBeforeWrite.
	BeforeWrite func() error
	// Piggyback is called on the batch about to be written, to merge volatile data (last_seen,
	// last_used_*) into it: they are persisted only when the file is written anyway.
	Piggyback func(p *Payload)
	// MasterKey is RSA_MASTER_KEY. With it the file is authenticated (HMAC-SHA-256 under a key
	// derived from it: a state without a valid HMAC is refused, a state written by someone who
	// does not hold the key can not be forged or rolled back by edition), and every secret of
	// server_config / push relay token_secret must open with the binding of its own field (AAD).
	// Without it (tests) no HMAC is written or checked.
	MasterKey string
	// InsecureTestMode explicitly allows a file whose server_config secrets are in clear (a state
	// created with `state init --insecure-test-mode`). It is refused together with a MasterKey:
	// a server holding a master key never accepts a clear-text secret.
	InsecureTestMode bool
	// RequireEncryptedSecrets is kept for compatibility: a clear secret is now refused at write
	// and at load unless InsecureTestMode is set (and no MasterKey).
	RequireEncryptedSecrets bool
	// Now is the clock (tests).
	Now func() time.Time
}

// clearSecretsAllowed: only the explicit test mode, without master key, accepts clear secrets.
func (o *Options) clearSecretsAllowed() bool {
	return o.InsecureTestMode && o.MasterKey == "" && !o.RequireEncryptedSecrets
}

// codec builds the codec of these options.
func (o *Options) codec() (codec, error) {
	c := codec{masterKey: o.MasterKey, insecure: o.clearSecretsAllowed()}
	if o.MasterKey != "" {
		k, err := crypto.DeriveStateHMACKey(o.MasterKey)
		if err != nil {
			return codec{}, fmt.Errorf("state: derive the HMAC key: %w", err)
		}
		c.macKey = k
	}
	return c, nil
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// MaxBytesFromEnv reads STATE_MAX_BYTES (default DefaultMaxBytes; invalid → error).
func MaxBytesFromEnv() (int64, error) {
	v := os.Getenv(EnvMaxBytes)
	if v == "" {
		return DefaultMaxBytes, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: invalid value %q", EnvMaxBytes, v)
	}
	return n, nil
}

// DirFromEnv returns STATE_DIR (default /data).
func DirFromEnv() string {
	if v := os.Getenv(EnvStateDir); v != "" {
		return v
	}
	return DefaultStateDir
}

// Engine holds the in-memory state and its single writer.
type Engine struct {
	opts  Options
	fs    FS
	codec codec

	cur atomic.Pointer[model]

	guardMu sync.RWMutex
	guard   func() error

	qmu     sync.Mutex
	queue   []*request
	writing bool

	// wmu serializes the commit itself and Reload (the writer is unique by construction, this
	// protects the fields below against a concurrent Reload).
	wmu      sync.Mutex
	fromPrev bool   // the in-memory model was recovered from relay.state.prev: do not rotate over it
	srcFile  string // file the in-memory model was read from (v1 backup source)

	writes atomic.Uint64 // number of successful file replacements (observability, tests)
}

type request struct {
	fn   func(*Tx) error
	done chan error
}

// Open loads STATE_DIR: relay.state (or relay.state.prev with a SECURITY WARNING). A missing
// state is a *NotFoundError (the server must refuse to start); it is never created here.
func Open(opts Options) (*Engine, error) {
	if opts.Dir == "" {
		opts.Dir = DefaultStateDir
	}
	if opts.FS == nil {
		opts.FS = OSFS{}
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.Instance == "" {
		host, _ := os.Hostname()
		opts.Instance = fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	if opts.InsecureTestMode && opts.MasterKey != "" {
		return nil, fmt.Errorf("%w: insecure test mode is refused when a master key (RSA_MASTER_KEY) is configured", ErrSecurityInvariant)
	}
	c, err := opts.codec()
	if err != nil {
		return nil, err
	}
	ld, err := load(opts.FS, opts.Dir, opts.now(), c, opts.MaxBytes)
	if err != nil {
		return nil, err
	}
	e := &Engine{opts: opts, fs: opts.FS, guard: opts.BeforeWrite, fromPrev: ld.fromPrev, srcFile: ld.srcName(), codec: c}
	e.cur.Store(ld.m)
	if ld.m.schema == 1 {
		slog.Info("state schema_version 1 loaded: it will be migrated to 2 (backup " + V1BackupFile + ") by the first write of the master")
	}
	slog.Info("state loaded", "dir", opts.Dir, "write_seq", ld.m.seq, "agents", len(ld.m.Agents), "from_prev", ld.fromPrev)
	return e, nil
}

// Snapshot returns the current consistent view (never blocks, never does I/O).
func (e *Engine) Snapshot() Snapshot { return Snapshot{m: e.cur.Load()} }

// SetBeforeWrite connects (or replaces) the write guard.
func (e *Engine) SetBeforeWrite(fn func() error) {
	e.guardMu.Lock()
	e.guard = fn
	e.guardMu.Unlock()
}

// Writes returns the number of file replacements done by this engine (group commit: Writes is
// much smaller than the number of mutations).
func (e *Engine) Writes() uint64 { return e.writes.Load() }

// Reload re-reads the state from disk (used when a secondary becomes master: the file may have
// been written by the previous master).
func (e *Engine) Reload() error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	ld, err := load(e.fs, e.opts.Dir, e.opts.now(), e.codec, e.opts.MaxBytes)
	if err != nil {
		return err
	}
	e.fromPrev = ld.fromPrev
	e.srcFile = ld.srcName()
	e.cur.Store(ld.m)
	return nil
}

// Mutate applies fn to the state and returns once the result is DURABLE (renamed and the
// directory synced). fn runs on a private copy of the model through the Tx: if it returns an
// error, or breaks an invariant, nothing it did is kept and the error is returned. A mutation is
// atomic across entities (one function = one rename). Mutations arriving while a write is in
// progress are merged into the next one (group commit); each caller waits for its own.
// fn must be fast and must not call Mutate.
func (e *Engine) Mutate(fn func(*Tx) error) error {
	req := &request{fn: fn, done: make(chan error, 1)}
	e.qmu.Lock()
	e.queue = append(e.queue, req)
	if e.writing {
		e.qmu.Unlock()
		return <-req.done
	}
	e.writing = true
	e.qmu.Unlock()

	// This caller is the writer: drain the queue until its own mutation is done, then hand the
	// rest to a goroutine so that it returns promptly.
	for {
		e.qmu.Lock()
		batch := e.queue
		e.queue = nil
		if len(batch) == 0 {
			e.writing = false
			e.qmu.Unlock()
			break
		}
		e.qmu.Unlock()
		e.commit(batch)
		select {
		case err := <-req.done:
			e.qmu.Lock()
			rest := len(e.queue) > 0
			if !rest {
				e.writing = false
			}
			e.qmu.Unlock()
			if rest {
				go e.drain()
			}
			return err
		default:
		}
	}
	return <-req.done
}

// drain commits what is queued until the queue is empty (the writing flag is already held).
func (e *Engine) drain() {
	for {
		e.qmu.Lock()
		batch := e.queue
		e.queue = nil
		if len(batch) == 0 {
			e.writing = false
			e.qmu.Unlock()
			return
		}
		e.qmu.Unlock()
		e.commit(batch)
	}
}

// commit applies one batch: guard, private copy, mutations (each atomic), one atomic write, and
// only then the publication of the new model.
func (e *Engine) commit(batch []*request) {
	e.wmu.Lock()
	defer e.wmu.Unlock()

	results := make([]error, len(batch))
	finish := func() {
		for i, r := range batch {
			r.done <- results[i]
		}
	}
	failAll := func(err error) {
		for i := range results {
			if results[i] == nil {
				results[i] = err
			}
		}
		finish()
	}

	e.guardMu.RLock()
	guard := e.guard
	e.guardMu.RUnlock()
	if guard == nil {
		failAll(ErrNoWriteGuard)
		return
	}
	if err := guard(); err != nil {
		failAll(fmt.Errorf("state: write guard refused the write: %w", err))
		return
	}

	work := e.cur.Load().clone()
	applied := 0
	for i, r := range batch {
		tx := newTx(work, &e.opts)
		err := r.fn(tx)
		if err == nil {
			err = tx.finish()
		}
		if err != nil {
			tx.rollback()
			results[i] = err
			continue
		}
		applied++
	}
	if applied == 0 {
		finish()
		return
	}

	if work.schema == 1 {
		// Migration v1 -> v2: the file is rewritten as v2 by this write. The v1 content is first copied
		// to relay.state.v1.bak (rollback = this file + v3.0.3 binaries); a failed backup cancels the
		// whole batch and leaves the v1 state untouched. Idempotent: once written, the model is v2.
		if err := writeV1Backup(e.fs, e.opts.Dir, e.srcFile, e.opts.MaxBytes); err != nil {
			failAllApplied(results, batch, err)
			finish()
			return
		}
		slog.Info("state migration schema_version 1 -> 2", "backup", V1BackupFile)
	}
	if e.opts.Piggyback != nil {
		e.opts.Piggyback(&work.Payload)
	}
	work.seq++
	work.schema = SchemaVersion
	data, err := e.codec.encode(&work.Payload, work.seq, e.opts.Instance, e.opts.now())
	if err != nil {
		failAllApplied(results, batch, err)
		finish()
		return
	}
	if int64(len(data)) > e.opts.MaxBytes {
		failAllApplied(results, batch, fmt.Errorf("%w: %d bytes > %d", ErrTooLarge, len(data), e.opts.MaxBytes))
		finish()
		return
	}
	if err := atomicWrite(e.fs, e.opts.Dir, data, !e.fromPrev, guard); err != nil {
		failAllApplied(results, batch, err)
		finish()
		return
	}
	e.fromPrev = false
	e.writes.Add(1)
	e.cur.Store(work)
	finish()
}

// failAllApplied marks every mutation that was applied (results[i] == nil) as failed.
func failAllApplied(results []error, batch []*request, err error) {
	for i := range batch {
		if results[i] == nil {
			results[i] = err
		}
	}
}
