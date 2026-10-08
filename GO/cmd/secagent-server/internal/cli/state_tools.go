package cli

// `state verify` and `state restore` (#187): local commands, no API, no port.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
)

// Exit codes of `state verify` / `state restore` (documented, usable in scripts).
const (
	ExitOK            = 0
	ExitAuthFailed    = 2 // HMAC invalid or sha256 falsified
	ExitSchema        = 3 // unknown schema_version
	ExitInvariant     = 4 // invariant violated (structure, secret without "enc:", field binding)
	ExitUnreadable    = 5 // file unreadable, absent or not a state file
	ExitNoMasterKey   = 6 // RSA_MASTER_KEY missing
	ExitSeqTooLow     = 7 // write_seq below --min-write-seq
	ExitInstanceAlive = 8 // restore: an instance holds a fresh relay.lock
)

// ExitError carries the process exit status chosen by a command.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// verifyExit classifies a verification error into an exit code and an operator-facing reason that
// never contains a value from the file.
func verifyExit(err error) (int, string) {
	switch {
	case err == nil:
		return ExitOK, ""
	case errors.Is(err, state.ErrNoMasterKey):
		return ExitNoMasterKey, "RSA_MASTER_KEY is not set: it is required to verify the file (the HMAC key derives from it)"
	case errors.Is(err, state.ErrSchemaVersion):
		return ExitSchema, "unknown schema_version: this build cannot read the file"
	case errors.Is(err, state.ErrAuthentication):
		return ExitAuthFailed, "authentication failed: wrong RSA_MASTER_KEY or tampered file (clé maître incorrecte ou fichier falsifié)"
	case errors.Is(err, state.ErrChecksum):
		return ExitAuthFailed, "sha256 mismatch: the payload does not match its checksum (tampered or damaged file)"
	case errors.Is(err, state.ErrWriteSeqTooLow):
		return ExitSeqTooLow, err.Error()
	case errors.Is(err, state.ErrStructure), errors.Is(err, state.ErrSecurityInvariant):
		return ExitInvariant, "invariant violated: " + firstLine(err)
	default:
		return ExitUnreadable, "cannot read the file as a state: " + firstLine(err)
	}
}

// firstLine keeps the error short; the state package never puts values in its messages.
func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

var (
	stateVerifyMinSeq   uint64
	stateRestoreFrom    string
	stateRestoreDir     string
	stateRestoreMinSeq  uint64
	stateRestoreForce   bool
	stateLockParams     = lock.DefaultParams // tests shorten the observation
	stateLockClock      lock.Clock           // nil = real clock (tests inject)
	stateRestoreNowFunc = time.Now
)

var stateVerifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify a state file (schema, HMAC, checksum, invariants) without writing anything",
	Long: `Applies every check the server applies when it opens a state: schema_version, HMAC (key derived
from RSA_MASTER_KEY, read from the environment like the server), sha256, invariants and secrets
("enc:" prefix, field binding). Writes nothing, takes no lock, opens no port. The output never
contains a secret: only metadata and entity counts.

Exit codes:
  0  authentic and valid
  2  HMAC invalid (wrong RSA_MASTER_KEY or tampered file) or sha256 falsified
  3  unknown schema_version
  4  invariant violated (structure, secret without "enc:", field binding)
  5  file unreadable, absent or not a state file
  6  RSA_MASTER_KEY not set
  7  write_seq below --min-write-seq`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		verifyKey, mkErr := masterKeyFromEnv()
		if mkErr != nil {
			return mkErr
		}
		rep, err := state.VerifyFile(args[0], state.VerifyOptions{MasterKey: verifyKey})
		if err == nil && stateVerifyMinSeq > 0 && rep.WriteSeq < stateVerifyMinSeq {
			printReport(cmd, rep)
			return &ExitError{Code: ExitSeqTooLow, Msg: fmt.Sprintf("verdict: REFUSED: write_seq %d is below --min-write-seq %d (copy too old)", rep.WriteSeq, stateVerifyMinSeq)}
		}
		if err != nil {
			code, why := verifyExit(err)
			return &ExitError{Code: code, Msg: "verdict: REFUSED: " + why}
		}
		printReport(cmd, rep)
		_, werr := fmt.Fprintln(cmd.OutOrStdout(), "verdict: OK (authentic and valid)")
		return werr
	},
}

func printReport(cmd *cobra.Command, r *state.Report) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "schema_version: %d\nwrite_seq: %d\nwritten_at: %s\nwriter_instance: %s\n",
		r.SchemaVersion, r.WriteSeq, r.WrittenAt.UTC().Format(time.RFC3339), r.WriterInstance)
	var names []string
	for k := range r.Counts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		_, _ = fmt.Fprintf(out, "%s: %d\n", k, r.Counts[k])
	}
	// Link data (schema v2): presence and public identifiers only, never a key value.
	_, _ = fmt.Fprintf(out, "link_signing_key_current: %s\nlink_signing_key_previous: %s\n",
		presence(r.LinkSigningKeyCurrent), presence(r.LinkSigningKeyPrevious))
	_, _ = fmt.Fprintf(out, "link_trust_current_kid: %s\nlink_trust_previous_kid: %s\nlink_trust_seq: %d\n",
		orNone(r.LinkTrustCurrentKID), orNone(r.LinkTrustPreviousKID), r.LinkTrustSeq)
	if r.NeedsMigration {
		_, _ = fmt.Fprintf(out, "migration: schema_version %d -> %d at the first write of the master (backup %s)\n",
			r.SchemaVersion, state.SchemaVersion, state.V1BackupFile)
	}
}

func presence(b bool) string {
	if b {
		return "[SEALED]"
	}
	return "[ABSENT]"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

var stateRestoreCmd = &cobra.Command{
	Use:   "restore --from <file>",
	Short: "Replace relay.state by a verified file (no instance may be running)",
	Long: `Runs 'state verify' on <file> first and refuses any inauthentic or invalid file. Refuses when an
instance holds a FRESH relay.lock (same freshness rule as the lock itself: the content must stay
unchanged for the staleness limit, observed on the local monotonic clock; this can take minutes for
a master lock). --i-know-no-instance-is-running passes over a lock that is not proven stale (orphan
lock on frozen storage): [SECURITY WARNING] and recorded in the journal.

Before replacing, the current relay.state and relay.state.prev are copied to relay.state.bak-<UTC
timestamp> / relay.state.prev.bak-<UTC timestamp> (0600, never reloaded by the server). The
replacement uses the engine's atomic write (temporary file, fsync, link/rename, directory fsync).
The intervention (date, operator, source file, write_seq before/after, backup names) is appended to
state-restore.log in STATE_DIR (no secret).

Afterwards restart the instances. The in-memory write_seq guard of the secondaries (#163) may
refuse a restored state older than what they observed: that is intended; stop ALL instances
before restoring.

Exit codes: those of 'state verify', plus 8 when an instance is alive.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if stateRestoreFrom == "" {
			return &ExitError{Code: 1, Msg: "--from <file> is required"}
		}
		dir := stateRestoreDir
		if dir == "" {
			dir = state.DirFromEnv()
		}
		masterKey, mkErr := masterKeyFromEnv()
		if mkErr != nil {
			return mkErr
		}
		// 1. verify first: nothing else happens for an inauthentic source
		if _, err := state.VerifyFile(stateRestoreFrom, state.VerifyOptions{MasterKey: masterKey}); err != nil {
			code, why := verifyExit(err)
			return &ExitError{Code: code, Msg: "restore refused, nothing modified: " + why}
		}
		// 2. no instance may hold a fresh lock
		overridden, err := checkNoActiveInstance(cmd, dir)
		if err != nil {
			return err
		}
		// 3. back up, replace atomically, journal
		guard := lockUnchangedGuard(dir, overridden)
		if stateRestoreAfterProbe != nil {
			stateRestoreAfterProbe() // test seam
		}
		res, err := state.Restore(state.RestoreOptions{
			Dir: dir, From: stateRestoreFrom, MasterKey: masterKey, MinWriteSeq: stateRestoreMinSeq,
			Now: stateRestoreNowFunc, LockOverride: overridden, BeforeRename: guard,
		})
		if err != nil {
			if errors.Is(err, state.ErrInstanceAppeared) {
				return &ExitError{Code: ExitInstanceAlive, Msg: "restore refused, relay.state NOT replaced: " + err.Error()}
			}
			if res == nil {
				code, why := verifyExit(err)
				return &ExitError{Code: code, Msg: "restore failed, relay.state not replaced: " + why}
			}
			slog.Warn("state restore", "error", err)
		}
		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "state restored in %s (write_seq %d -> %d)\n", dir, res.SeqBefore, res.SeqAfter)
		if res.BackupFile != "" {
			_, _ = fmt.Fprintf(out, "previous relay.state saved as %s\n", res.BackupFile)
		}
		if res.BackupPrev != "" {
			_, _ = fmt.Fprintf(out, "previous relay.state.prev saved as %s\n", res.BackupPrev)
		}
		_, _ = fmt.Fprintln(out, "intervention journaled in "+state.RestoreLogFile)
		_, _ = fmt.Fprintln(out, "Restart the instances. Stop ALL of them before restoring: the in-memory write_seq guard of a secondary may refuse an older state, which is intended.")
		return err
	},
}

// checkNoActiveInstance refuses when relay.lock is held; it reports whether the explicit override
// was used on a lock that is not proven stale.
func checkNoActiveInstance(cmd *cobra.Command, dir string) (overridden bool, err error) {
	p := stateLockParams()
	ctx, cancel := context.WithTimeout(context.Background(), p.MasterStale+10*time.Second)
	defer cancel()
	if _, serr := os.Stat(filepath.Join(dir, lock.FileName)); serr == nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "relay.lock is present: observing it (up to %s) to find out whether an instance is alive...\n", p.MasterStale)
	}
	st, info, perr := lock.Probe(ctx, nil, stateLockClock, dir, p)
	switch st {
	case lock.ProbeAbsent:
		return false, nil
	case lock.ProbeStale:
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "relay.lock is stale (role %s, unchanged for %s): no instance maintains it\n", info.Role, info.Waited.Round(time.Second))
		return false, nil
	}
	detail := fmt.Sprintf("an instance holds a fresh relay.lock (role %s, beat %d)", info.Role, info.Beat)
	if perr != nil {
		detail += ": " + perr.Error()
	}
	if stateRestoreForce {
		slog.Warn("[SECURITY WARNING] state restore: --i-know-no-instance-is-running used over a relay.lock that was NOT proven stale",
			"role", info.Role, "beat", info.Beat)
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "[SECURITY WARNING] proceeding over a relay.lock that was not proven stale (--i-know-no-instance-is-running); this is recorded in the journal")
		return true, nil
	}
	return false, &ExitError{Code: ExitInstanceAlive, Msg: "restore refused, nothing modified: " + detail + ". Stop every instance first (or, for an orphan lock on frozen storage, pass --i-know-no-instance-is-running)"}
}

func init() {
	stateVerifyCmd.Flags().Uint64Var(&stateVerifyMinSeq, "min-write-seq", 0, "fail (exit 7) if the file's write_seq is lower")
	stateRestoreCmd.Flags().StringVar(&stateRestoreFrom, "from", "", "state file to restore (a relay.state.prev, a backup)")
	stateRestoreCmd.Flags().StringVar(&stateRestoreDir, "state-dir", "", "state directory (default $STATE_DIR, else /data)")
	stateRestoreCmd.Flags().Uint64Var(&stateRestoreMinSeq, "min-write-seq", 0, "refuse a source whose write_seq is lower")
	stateRestoreCmd.Flags().BoolVar(&stateRestoreForce, "i-know-no-instance-is-running", false, "pass over a relay.lock that is not proven stale (orphan lock): [SECURITY WARNING], journaled")
	stateCmd.AddCommand(stateVerifyCmd, stateRestoreCmd)
}

// ── state link-trust reset (v3.0.4) ──────────────────────────────────────────

// ExitRefused: the reset is refused for a reason that is not the lock (root node, state from .prev,
// confirmation missing).
const ExitRefused = 9

var (
	stateLTResetDir string
	stateLTResetYes bool
	stateLTStdinTTY = func() bool { // tests replace it
		fi, err := os.Stdin.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
)

var stateLinkTrustCmd = &cobra.Command{
	Use:   "link-trust",
	Short: "Operations on the link trust anchor of a non-root relay (offline)",
}

var stateLinkTrustResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Clear the persisted link trust anchor of a NON-ROOT relay (stopped node only)",
	Long: `Clears ONLY the persisted trust anchor (link_trust: root id, current and previous root public key,
last accepted sequence number) of a non-root relay, so that the next start accepts the anchor given by
REPEATER_ROOT_ID + REPEATER_ROOT_LINK_KEY_FILE. Use it to re-pin a relay that missed a key rotation, or
after a re-root. Without an anchor a relay refuses every incoming link (fail closed).

It touches nothing else: not the agents, the link tokens, the blacklist, nor any key.

Safety:
  - offline: refuses when an instance holds a fresh relay.lock (same rule as 'state restore'; the
    override flag exists for an orphan lock on frozen storage only);
  - needs RSA_MASTER_KEY (or RSA_MASTER_KEY_FILE): the HMAC of the state is verified before and recomputed
    after; relay.state is rewritten atomically with a higher write_seq;
  - refuses on a ROOT (a node that holds a link signing key has no anchor to reset);
  - the exact verified relay.state is first copied to relay.state.linktrust-reset.<UTC timestamp>.bak
    (0600, fsync): if the backup fails, nothing is modified;
  - asks for confirmation (type "reset"); non-interactive use requires --yes;
  - logs "[SECURITY WARNING] link trust anchor reset" and appends the intervention (no key) to
    state-restore.log.

Nothing to clear is not an error (idempotent: nothing is written).

Exit codes: those of 'state verify', plus 8 (an instance is alive) and 9 (refused: root, state not
from relay.state, no confirmation).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := stateLTResetDir
		if dir == "" {
			dir = state.DirFromEnv()
		}
		masterKey, mkErr := masterKeyFromEnv()
		if mkErr != nil {
			return mkErr
		}
		if masterKey == "" {
			return &ExitError{Code: ExitNoMasterKey, Msg: "RSA_MASTER_KEY is not set: it is required (the HMAC key of the state derives from it)"}
		}
		out := cmd.OutOrStdout()
		// 1. verify and look before asking anything (also catches a wrong key, a root, a missing anchor)
		now := stateRestoreNowFunc
		probe, err := state.PeekLinkTrust(dir, masterKey, nil)
		if err != nil {
			return linkTrustResetError(err, "")
		}
		if !probe.Present {
			_, _ = fmt.Fprintln(out, "no link trust anchor is persisted in this state: nothing to reset (nothing written). This is also the normal case of a ROOT, which has no anchor (and no signing key until its first mint or the first link-pubkey export)")
			return nil
		}
		// 2. no instance may hold a fresh lock
		overridden, err := checkNoActiveInstance(cmd, dir)
		if err != nil {
			return err
		}
		guard := lockUnchangedGuard(dir, overridden)
		if stateLTAfterProbe != nil {
			stateLTAfterProbe() // test seam: a node takes the lock between the probe and the replacement
		}
		// 3. confirmation
		_, _ = fmt.Fprintf(out, "This will CLEAR the link trust anchor of this relay (root %q, kid %s, previous %s, seq %d) in %s.\n",
			probe.RootID, orNone(probe.CurrentKID), orNone(probe.PreviousKID), probe.Seq, dir)
		_, _ = fmt.Fprintln(out, "Until a new anchor is given (REPEATER_ROOT_ID + REPEATER_ROOT_LINK_KEY_FILE) this relay refuses every incoming link. A backup is written first.")
		if !stateLTResetYes {
			if !stateLTStdinTTY() {
				return &ExitError{Code: ExitRefused, Msg: "reset refused, nothing modified: confirmation required (pass --yes in non-interactive use)"}
			}
			_, _ = fmt.Fprint(out, `Type "reset" to continue: `)
			var answer string
			_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
			if strings.TrimSpace(answer) != "reset" {
				return &ExitError{Code: ExitRefused, Msg: "reset cancelled, nothing modified"}
			}
		}
		res, err := state.ResetLinkTrust(state.LinkTrustResetOptions{Dir: dir, MasterKey: masterKey, Now: now, BeforeRename: guard})
		if err != nil {
			if errors.Is(err, state.ErrInstanceAppeared) {
				bak := ""
				if res != nil {
					bak = " (the backup " + res.BackupFile + " was kept)"
				}
				return &ExitError{Code: ExitInstanceAlive, Msg: "reset refused, relay.state NOT modified" + bak + ": " + err.Error()}
			}
			if res == nil {
				return linkTrustResetError(err, "reset failed, relay.state not modified: ")
			}
			slog.Warn("state link-trust reset", "error", err)
		}
		_, _ = fmt.Fprintf(out, "link trust anchor cleared in %s (write_seq %d -> %d)\n", dir, res.SeqBefore, res.SeqAfter)
		_, _ = fmt.Fprintf(out, "previous relay.state saved as %s\n", res.BackupFile)
		_, _ = fmt.Fprintln(out, "Start the relay with REPEATER_ROOT_ID and REPEATER_ROOT_LINK_KEY_FILE: it will pin the new anchor.")
		return err
	},
}

// linkTrustResetError maps the errors of ResetLinkTrust / PeekLinkTrust to exit codes.
func linkTrustResetError(err error, prefix string) error {
	switch {
	case errors.Is(err, state.ErrResetOnRoot), errors.Is(err, state.ErrResetFromPrev):
		return &ExitError{Code: ExitRefused, Msg: prefix + "refused, nothing modified: " + err.Error()}
	default:
		code, why := verifyExit(err)
		return &ExitError{Code: code, Msg: prefix + why}
	}
}

func init() {
	stateLinkTrustResetCmd.Flags().StringVar(&stateLTResetDir, "state-dir", "", "state directory (default $STATE_DIR, else /data)")
	stateLinkTrustResetCmd.Flags().BoolVar(&stateLTResetYes, "yes", false, "confirm without prompting (required in non-interactive use)")
	stateLinkTrustResetCmd.Flags().BoolVar(&stateRestoreForce, "i-know-no-instance-is-running", false, "pass over a relay.lock that is not proven stale (orphan lock): [SECURITY WARNING]")
	stateLinkTrustCmd.AddCommand(stateLinkTrustResetCmd)
	stateCmd.AddCommand(stateLinkTrustCmd)
}

// stateLTAfterProbe is a test seam, called after the lock probe and before the replacement.
var stateLTAfterProbe func()

// stateRestoreAfterProbe is the same seam for state restore.
var stateRestoreAfterProbe func()

// lockUnchangedGuard snapshots relay.lock NOW (right after the probe concluded: absent, or stale and
// therefore unchanging) and returns the check run just before relay.state is replaced: if the lock
// appeared or its content changed since, a node is alive (or was just started) and the offline
// operation is abandoned. With the explicit override (an orphan lock not proven stale) the operator
// took the responsibility: no guard.
func lockUnchangedGuard(dir string, overridden bool) func() error {
	if overridden {
		return nil
	}
	path := filepath.Join(dir, lock.FileName)
	read := func() ([]byte, bool) {
		b, err := os.ReadFile(path)
		return b, err == nil
	}
	want, had := read()
	return func() error {
		got, has := read()
		if has != had || string(got) != string(want) {
			return state.ErrInstanceAppeared
		}
		return nil
	}
}
