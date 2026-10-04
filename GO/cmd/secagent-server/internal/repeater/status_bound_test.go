package repeater

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The reason exposed in the link status is bounded to the LITERAL value 200 (bytes, rune-aligned,
// "…" appended when cut) — asserted against literals, not against maxReasonLen, so that shifting
// the bound or truncating in the middle of a rune is caught.
func TestStatus_ReasonBoundIsLiteral200AndRuneAligned(t *testing.T) {
	const ellipsis = "…"
	tests := []struct {
		name         string
		in           string
		wantPrefixLn int // bytes kept before the ellipsis; -1 = unchanged input
		wantMinLn    int // lower bound for rune-aligned cuts
	}{
		{"exactly 200 bytes is kept as is", strings.Repeat("a", 200), -1, 0},
		{"201 bytes is cut to 200 + ellipsis", strings.Repeat("a", 201), 200, 200},
		{"5000 bytes is cut to 200 + ellipsis", strings.Repeat("x", 5000), 200, 200},
		{"2-byte runes (é): 100 runes = 200 bytes", strings.Repeat("é", 300), 200, 200},
		{"3-byte runes (€): cut aligned on a rune, never mid-sequence", strings.Repeat("€", 300), 198, 198},
		{"4-byte runes (😀): cut aligned on a rune", strings.Repeat("😀", 300), 200, 200},
		{"multi-byte text straddling the limit", strings.Repeat("a", 199) + "€€€", 199, 199},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newLinkTracker()
			tr.set(LinkRetrying, tt.in)
			got := tr.get().Reason
			if !utf8.ValidString(got) {
				t.Fatalf("the reason is not valid UTF-8 (cut inside a rune): %q", got)
			}
			if tt.wantPrefixLn == -1 {
				if got != tt.in {
					t.Errorf("an input of exactly 200 bytes must be kept untouched, got %d bytes", len(got))
				}
				return
			}
			if !strings.HasSuffix(got, ellipsis) {
				t.Fatalf("a truncated reason must end with %q: %q", ellipsis, got)
			}
			kept := len(got) - len(ellipsis)
			if kept != tt.wantPrefixLn {
				t.Errorf("kept %d bytes before the ellipsis, want exactly %d", kept, tt.wantPrefixLn)
			}
			if kept > 200 {
				t.Errorf("more than 200 bytes kept: %d", kept)
			}
			if !strings.HasPrefix(tt.in, strings.TrimSuffix(got, ellipsis)) {
				t.Error("the kept part must be a prefix of the input")
			}
		})
	}
	// the literal the spec documents
	if maxReasonLen != 200 {
		t.Errorf("maxReasonLen = %d: the documented bound is 200 (update the specs and this test together)", maxReasonLen)
	}
}
