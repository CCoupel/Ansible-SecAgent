package logsafe

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"plain line\n":                   "plain line\n",
		"a\n[SECURITY WARNING] forged\n": `a\n[SECURITY WARNING] forged` + "\n",
		"cr\rx":                          `cr\rx`,
		"nul\x00x\n":                     `nul\u0000x` + "\n",
		"nel\u0085ls\u2028ps\u2029\n":    "nel" + "\\u0085" + "ls" + "\\u2028" + "ps" + "\\u2029" + "\n",
		"tab\tx":                         `tab\tx`,
		"esc\x1b[31m\n":                  `esc\u001b[31m` + "\n",
		"bad\xffutf8\n":                  `bad\xffutf8` + "\n",
		"unicode é ok\n":                 "unicode é ok\n",
		"":                               "",
	} {
		if got := string(Sanitize([]byte(in))); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstall_OneCallIsOneLineAndIsIdempotent(t *testing.T) {
	var buf bytes.Buffer
	prevW, prevF := log.Writer(), log.Flags()
	defer func() { log.SetOutput(prevW); log.SetFlags(prevF) }()
	log.SetOutput(&buf)
	log.SetFlags(0)
	Install()
	Install()
	log.Printf("Relay deleted: relay_id=%s", "x\n[SECURITY WARNING] forged")
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Errorf("%d lines, want 1: %q", n, buf.String())
	}
	if _, ok := log.Writer().(*writer); !ok || strings.Count(buf.String(), "forged") != 1 {
		t.Error("expected a single wrapper")
	}
}
