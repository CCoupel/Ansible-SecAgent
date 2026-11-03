// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #219: two backups taken in the same second keep distinct names, nothing is overwritten.
func TestWriteUniqueBackup_SameInstantNeverCollides(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 2, 12, 0, 0, 123456789, time.UTC)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		name, err := writeUniqueBackup(OSFS{}, dir, "relay.state.rekey.", ".bak", now, []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		if seen[name] {
			t.Fatalf("name %q reused", name)
		}
		seen[name] = true
		if !strings.HasPrefix(name, "relay.state.rekey.20261102T120000.123456789Z") || !strings.HasSuffix(name, ".bak") {
			t.Errorf("unexpected name %q", name)
		}
		got, _ := os.ReadFile(dir + "/" + name)
		if string(got) != string([]byte{byte('a' + i)}) {
			t.Errorf("%s holds %q: an earlier backup was overwritten or mixed", name, got)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("%d distinct names, want 5", len(seen))
	}
}

func TestRekeyTwiceInTheSameInstantKeepsBothBackups(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) }
	dir, _ := rekeyState(t)
	o := rekeyOpts(dir)
	o.Now = now
	r1, err := Rekey(o)
	if err != nil {
		t.Fatal(err)
	}
	o2 := RekeyOptions{Dir: dir, OldKey: rekeyNew, NewKey: "second-rekey-master-key-0123456789abcdefXYZ", Operator: "tester", Now: now}
	r2, err := Rekey(o2)
	if err != nil {
		t.Fatal(err)
	}
	if r1.BackupFile == r2.BackupFile {
		t.Fatalf("both rekeys wrote %q", r1.BackupFile)
	}
}

// #219 (QA): two `state restore` in the same instant both succeed, with distinct backups (they used to be named
// to the second and the second one failed with code 5).
func TestRestoreTwiceInTheSameInstantKeepsAllBackups(t *testing.T) {
	dir := twoGenerations(t)
	fixed := func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }
	from := filepath.Join(dir, PrevFile)
	r1, err := Restore(RestoreOptions{Dir: dir, From: from, MasterKey: hmKey, Now: fixed, Operator: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Restore(RestoreOptions{Dir: dir, From: from, MasterKey: hmKey, Now: fixed, Operator: "ops"})
	if err != nil {
		t.Fatalf("the second restore of the same instant must succeed: %v", err)
	}
	if r1.BackupFile == r2.BackupFile || r1.BackupPrev == r2.BackupPrev {
		t.Fatalf("backups reused: %q %q / %q %q", r1.BackupFile, r2.BackupFile, r1.BackupPrev, r2.BackupPrev)
	}
	for _, n := range []string{r1.BackupFile, r1.BackupPrev, r2.BackupFile, r2.BackupPrev} {
		if n == "" {
			t.Fatal("a backup name is empty")
		}
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("backup %s missing: %v", n, err)
		}
	}
}
