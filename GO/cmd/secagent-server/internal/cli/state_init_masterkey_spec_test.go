package cli

// #214 (v3.0.5, D2) — `secagent-server state init` refuses a master key shorter than 32 bytes, with the
// remedy, and never prints the key.

import (
	"os"
	"strings"
	"testing"
)

// (critical) 31 bytes refused: remedy in the error, key absent from error and output, nothing written.
func TestSpec214_StateInitRefusesAShortMasterKeyWithTheRemedy(t *testing.T) {
	short := strings.Repeat("s", 31)
	t.Setenv("RSA_MASTER_KEY", short)
	dir := t.TempDir()
	out, err := runStateInit(t, dir, false)
	if err == nil {
		t.Fatalf("a 31-byte RSA_MASTER_KEY must be refused by state init (output %q)", out)
	}
	for _, want := range []string{"RSA_MASTER_KEY", "32", "openssl rand -base64 48"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must contain %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), short) || strings.Contains(out, short) {
		t.Errorf("the key leaks (error %q, output %q)", err, out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused init must write nothing: %v", entries)
	}
}

func TestSpec214_StateInitAccepts32BytesAndMore(t *testing.T) {
	for _, n := range []int{32, 48} {
		t.Setenv("RSA_MASTER_KEY", strings.Repeat("g", n))
		dir := t.TempDir()
		if out, err := runStateInit(t, dir, false); err != nil || !strings.Contains(out, "state initialized in "+dir) {
			t.Errorf("%d bytes: %q %v", n, out, err)
		}
	}
}
