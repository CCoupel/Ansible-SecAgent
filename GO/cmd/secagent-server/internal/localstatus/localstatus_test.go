package localstatus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteReadRoundTripMode0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run", "status.json")
	in := File{Role: "master", InstanceID: "abc", State: StateReady, Beat: 4, LastBeatAt: 1000, BeatPeriodMS: 30000, CheckPeriodMS: 5000}
	if err := Write(p, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v, want 0600", st.Mode().Perm(), err)
	}
	if d, _ := os.Stat(filepath.Dir(p)); d.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", d.Mode().Perm())
	}
	out, err := Read(p)
	if err != nil || out.Role != "master" || out.InstanceID != "abc" || out.Beat != 4 || out.Pid != os.Getpid() || out.UpdatedAt == 0 {
		t.Fatalf("read back %+v %v", out, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	raw, _ := os.ReadFile(p)
	for _, secret := range []string{"token", "secret", "password", "key"} {
		if strings.Contains(strings.ToLower(string(raw)), secret) {
			t.Errorf("the status file mentions %q", secret)
		}
	}
}

func TestVerdict(t *testing.T) {
	now := time.UnixMilli(10_000_000)
	ms := func(d time.Duration) int64 { return now.Add(-d).UnixMilli() }
	master := func(age time.Duration) File {
		return File{Role: "master", State: StateReady, LastBeatAt: ms(age), BeatPeriodMS: 30000, CheckPeriodMS: 5000}
	}
	sec := func(age time.Duration) File {
		return File{Role: "secondary", State: StateWaiting, LastCheckAt: ms(age), BeatPeriodMS: 30000, CheckPeriodMS: 5000}
	}
	cases := []struct {
		name string
		f    File
		ok   bool
	}{
		{"healthy master", master(10 * time.Second), true},
		{"master beat just under 2 periods", master(59 * time.Second), true},
		{"frozen master", master(61 * time.Second), false},
		{"master without a beat", File{Role: "master", State: StateLoading, BeatPeriodMS: 30000}, false},
		{"healthy secondary", sec(4 * time.Second), true},
		{"frozen secondary", sec(16 * time.Second), false},
		{"secondary never checked", File{Role: "secondary", State: StateWaiting, CheckPeriodMS: 5000}, false},
		{"failed", File{Role: "master", State: StateFailed, Detail: "replay refused", LastBeatAt: ms(time.Second), BeatPeriodMS: 30000}, false},
		{"lost", File{Role: "lost", State: StateLost, LastBeatAt: ms(time.Second), BeatPeriodMS: 30000}, false},
		{"unknown role", File{Role: "weird", State: StateReady}, false},
	}
	for _, c := range cases {
		if ok, reason := Verdict(c.f, now); ok != c.ok || (!ok && reason == "") {
			t.Errorf("%s: ok=%v reason=%q, want ok=%v", c.name, ok, reason, c.ok)
		}
	}
}

func TestCheckOutside(t *testing.T) {
	dir := t.TempDir()
	if err := CheckOutside(filepath.Join(dir, "status.json"), dir); err == nil {
		t.Error("a status file directly in STATE_DIR must be refused")
	}
	if err := CheckOutside(filepath.Join(dir, "sub", "status.json"), dir); err == nil {
		t.Error("a status file under STATE_DIR must be refused")
	}
	if err := CheckOutside(filepath.Join(t.TempDir(), "status.json"), dir); err != nil {
		t.Errorf("outside is fine: %v", err)
	}
	if err := CheckOutside(dir+"-sibling/status.json", dir); err != nil {
		t.Errorf("a sibling directory sharing a prefix is outside: %v", err)
	}
}

func TestPathFromEnv(t *testing.T) {
	t.Setenv(EnvStatusFile, "")
	if PathFromEnv() != DefaultPath {
		t.Error("default path")
	}
	t.Setenv(EnvStatusFile, " /x/y.json ")
	if PathFromEnv() != "/x/y.json" {
		t.Error("override")
	}
}
