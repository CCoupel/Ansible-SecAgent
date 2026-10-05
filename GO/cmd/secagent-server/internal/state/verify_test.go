package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #187 — VerifyFile and Restore.

func twoGenerations(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	keyedState(t, dir)
	e, err := openKeyed(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustMutate(t, e, addAgent("a1")) // seq 2, .prev = seq 1 (init)
	mustMutate(t, e, addAgent("a2")) // seq 3, .prev = seq 2
	return dir
}

func TestVerifyFile_ReportsMetadataAndCountsOnly(t *testing.T) {
	dir := twoGenerations(t)
	rep, err := VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: hmKey})
	if err != nil {
		t.Fatal(err)
	}
	if rep.WriteSeq != 3 || rep.SchemaVersion != SchemaVersion || rep.Counts["agents"] != 2 || rep.WriterInstance != "t" {
		t.Errorf("report %+v", rep)
	}
	prev, err := VerifyFile(filepath.Join(dir, PrevFile), VerifyOptions{MasterKey: hmKey})
	if err != nil || prev.WriteSeq != 2 || prev.Counts["agents"] != 1 {
		t.Errorf("prev report %+v err %v", prev, err)
	}
}

func TestVerifyFile_Classification(t *testing.T) {
	dir := twoGenerations(t)
	path := filepath.Join(dir, StateFile)
	if _, err := VerifyFile(path, VerifyOptions{}); !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("no key: %v", err)
	}
	if _, err := VerifyFile(path, VerifyOptions{MasterKey: "wrong"}); !errors.Is(err, ErrAuthentication) || !errors.Is(err, ErrSecurityInvariant) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := VerifyFile(filepath.Join(dir, "absent"), VerifyOptions{MasterKey: hmKey}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
	bad := filepath.Join(dir, "garbage")
	_ = os.WriteFile(bad, []byte("not json"), 0o600)
	if _, err := VerifyFile(bad, VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrAuthentication) {
		t.Errorf("garbage: %v", err)
	}
	// payload edited: authentication, not corruption
	raw := string(mustFile(t, path))
	edited := filepath.Join(dir, "edited")
	_ = os.WriteFile(edited, []byte(strings.Replace(raw, `"a1"`, `"b1"`, 1)), 0o600)
	if _, err := VerifyFile(edited, VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrAuthentication) {
		t.Errorf("edited payload: %v", err)
	}
	// unknown schema
	sch := filepath.Join(dir, "schema")
	_ = os.WriteFile(sch, []byte(strings.Replace(raw, `"schema_version":1`, `"schema_version":9`, 1)), 0o600)
	if _, err := VerifyFile(sch, VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrSchemaVersion) {
		t.Errorf("schema: %v", err)
	}
}

// With a valid HMAC (the test holds the key) but a broken invariant or a clear secret, the verdict
// is an invariant violation, NOT an authentication failure.
func TestVerifyFile_InvariantsAreDistinctFromAuthentication(t *testing.T) {
	c, err := (&Options{MasterKey: hmKey}).codec()
	if err != nil {
		t.Fatal(err)
	}
	write := func(p Payload) string {
		data, err := c.encode(&p, 1, "t", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "f")
		_ = os.WriteFile(path, data, 0o600)
		return path
	}
	clear := newPayload()
	clear.ServerConfig["jwt_secret_current"] = "in-clear"
	if _, err := VerifyFile(write(clear), VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) || errors.Is(err, ErrAuthentication) {
		t.Errorf("clear secret: %v", err)
	}
	if err := func() error { _, e := VerifyFile(write(clear), VerifyOptions{MasterKey: hmKey}); return e }(); err != nil && strings.Contains(err.Error(), "in-clear") {
		t.Error("the error leaks the secret value")
	}
	push := newPayload()
	push.RelayNodes["p"] = RelayNode{ID: "u", RelayID: "p", Mode: ModePush, TokenSecret: "plain", CreatedAt: time.Now()}
	if _, err := VerifyFile(write(push), VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrSecurityInvariant) {
		t.Errorf("push token_secret without enc: %v", err)
	}
	dup := newPayload()
	e1 := EnrollmentToken{ID: "e1", TokenHash: "same-hash", HostnamePattern: "*", CreatedAt: time.Now()}
	e2 := EnrollmentToken{ID: "e2", TokenHash: "same-hash", HostnamePattern: "*", CreatedAt: time.Now()} // same hash
	dup.EnrollmentTokens["e1"], dup.EnrollmentTokens["e2"] = e1, e2
	if _, err := VerifyFile(write(dup), VerifyOptions{MasterKey: hmKey}); !errors.Is(err, ErrStructure) || errors.Is(err, ErrAuthentication) {
		t.Errorf("duplicate jti: %v", err)
	}
}

func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		out[e.Name()] = string(b)
	}
	return out
}

func TestVerifyFile_WritesNothing(t *testing.T) {
	dir := twoGenerations(t)
	before := dirSnapshot(t, dir)
	_, _ = VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: hmKey})
	_, _ = VerifyFile(filepath.Join(dir, StateFile), VerifyOptions{MasterKey: "wrong"})
	after := dirSnapshot(t, dir)
	if len(before) != len(after) {
		t.Fatalf("files before %d after %d", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s changed", k)
		}
	}
}

func TestRestore_ReplacesWithBackupsJournalAndAtomicWrite(t *testing.T) {
	dir := twoGenerations(t)
	prevBytes := mustFile(t, filepath.Join(dir, PrevFile))
	curBytes := mustFile(t, filepath.Join(dir, StateFile))
	fixed := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	res, err := Restore(RestoreOptions{Dir: dir, From: filepath.Join(dir, PrevFile), MasterKey: hmKey, Now: func() time.Time { return fixed }, Operator: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SeqBefore != 3 || res.SeqAfter != 2 {
		t.Errorf("seq %d -> %d", res.SeqBefore, res.SeqAfter)
	}
	if got := mustFile(t, filepath.Join(dir, StateFile)); string(got) != string(prevBytes) {
		t.Error("relay.state must be the restored file, byte for byte (its HMAC stays valid)")
	}
	if m := mode(t, filepath.Join(dir, StateFile)); m != 0o600 {
		t.Errorf("relay.state mode %o", m)
	}
	if res.BackupFile != "relay.state.bak-20261005T120000Z" || res.BackupPrev != "relay.state.prev.bak-20261005T120000Z" {
		t.Errorf("backups %q %q", res.BackupFile, res.BackupPrev)
	}
	if string(mustFile(t, filepath.Join(dir, res.BackupFile))) != string(curBytes) {
		t.Error("the backup of relay.state differs from the replaced file")
	}
	for _, n := range []string{res.BackupFile, res.BackupPrev, RestoreLogFile} {
		if m := mode(t, filepath.Join(dir, n)); m != 0o600 {
			t.Errorf("%s mode %o", n, m)
		}
	}
	log := string(mustFile(t, filepath.Join(dir, RestoreLogFile)))
	for _, want := range []string{`"operator":"ops"`, `"source":"relay.state.prev"`, `"write_seq_before":3`, `"write_seq_after":2`, `"backup":"relay.state.bak-20261005T120000Z"`} {
		if !strings.Contains(log, want) {
			t.Errorf("journal lacks %s:\n%s", want, log)
		}
	}
	if strings.Contains(log, "enc:") || strings.Contains(log, hmKey) {
		t.Error("the journal carries a secret")
	}
	// the server opens the restored state, and ignores backups and the journal
	e, err := openKeyed(dir)
	if err != nil {
		t.Fatalf("open after restore: %v", err)
	}
	if e.Snapshot().WriteSeq() != 2 {
		t.Errorf("write_seq %d", e.Snapshot().WriteSeq())
	}
	if _, ok := e.Snapshot().Agent("a2"); ok {
		t.Error("the restored state must not contain the agent added after it")
	}
	for _, n := range listDir(t, dir) {
		if strings.HasPrefix(n, TmpFile) {
			t.Errorf("temporary file left: %s", n)
		}
	}
}

func TestRestore_RefusesAnInauthenticSourceAndModifiesNothing(t *testing.T) {
	dir := twoGenerations(t)
	raw := string(mustFile(t, filepath.Join(dir, PrevFile)))
	forged := filepath.Join(t.TempDir(), "forged")
	_ = os.WriteFile(forged, []byte(strings.Replace(raw, `"a1"`, `"evil"`, 1)), 0o600)
	before := dirSnapshot(t, dir)
	for name, o := range map[string]RestoreOptions{
		"forged":    {Dir: dir, From: forged, MasterKey: hmKey},
		"wrong key": {Dir: dir, From: filepath.Join(dir, PrevFile), MasterKey: "wrong"},
		"no key":    {Dir: dir, From: filepath.Join(dir, PrevFile)},
		"absent":    {Dir: dir, From: filepath.Join(dir, "absent"), MasterKey: hmKey},
		"too old":   {Dir: dir, From: filepath.Join(dir, PrevFile), MasterKey: hmKey, MinWriteSeq: 3},
	} {
		if _, err := Restore(o); err == nil {
			t.Errorf("%s: must be refused", name)
		}
		after := dirSnapshot(t, dir)
		if len(after) != len(before) {
			t.Fatalf("%s: files changed: %v", name, listDir(t, dir))
		}
		for k, v := range before {
			if after[k] != v {
				t.Errorf("%s: %s modified", name, k)
			}
		}
	}
	if _, err := Restore(RestoreOptions{Dir: dir, From: filepath.Join(dir, PrevFile), MasterKey: hmKey, MinWriteSeq: 3}); !errors.Is(err, ErrWriteSeqTooLow) {
		t.Errorf("min seq: %v", err)
	}
}

func TestRestore_IntoAnEmptyDirectoryHasNothingToBackUp(t *testing.T) {
	src := twoGenerations(t)
	dst := t.TempDir()
	res, err := Restore(RestoreOptions{Dir: dst, From: filepath.Join(src, StateFile), MasterKey: hmKey})
	if err != nil || res.BackupFile != "" || res.BackupPrev != "" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := openKeyed(dst); err != nil {
		t.Fatalf("restored state must open: %v", err)
	}
}

// No direct write/rename in the restore path: it goes through the engine's atomic write.
func TestRestoreUsesTheEnginesAtomicWrite(t *testing.T) {
	src, err := os.ReadFile("verify.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"os.WriteFile", "os.Rename", "ioutil.WriteFile"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("verify.go uses %s: the replacement must go through atomicWrite", forbidden)
		}
	}
	if !strings.Contains(string(src), "atomicWrite(") {
		t.Error("Restore must call atomicWrite")
	}
}

// Golden format of the HMAC input (#159c R1): every field and every length prefix is pinned, so a
// change of the format (a removed prefix, a reordered field) cannot go unnoticed.
func TestMacInputGoldenFormat(t *testing.T) {
	e := envelope{
		SchemaVersion: 1, WriteSeq: 42, WrittenAt: time.Date(2026, 10, 5, 12, 30, 0, 123, time.UTC),
		WriterInstance: "host-1", SHA256: "abcd", Payload: []byte(`{"x":1}`),
	}
	want := "secagent-state-v2\n1\n42\n2026-10-05T12:30:00.000000123Z\n6:host-1\n4:abcd\n{\"x\":1}"
	if got := string(macInput(&e)); got != want {
		t.Errorf("macInput =\n%q\nwant\n%q", got, want)
	}
	// the writer length prefix matters: a writer that looks like the next field does not collide
	a := envelope{SchemaVersion: 1, WriteSeq: 1, WriterInstance: "w\n4:abcd", SHA256: "ef", Payload: []byte("p")}
	b := envelope{SchemaVersion: 1, WriteSeq: 1, WriterInstance: "w", SHA256: "abcd", Payload: []byte("p")}
	if string(macInput(&a)) == string(macInput(&b)) {
		t.Error("two different envelopes produce the same HMAC input")
	}
}
