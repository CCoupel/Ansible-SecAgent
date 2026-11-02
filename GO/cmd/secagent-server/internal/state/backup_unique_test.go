package state

import (
	"os"
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
