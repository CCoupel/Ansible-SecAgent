package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/state"
)

// The exit code of every refusal of `state rekey` is part of the operator contract (STATE_SPEC, SECURITY §11):
// 10 = the rewritten state failed its end-to-end verification (the original was put back), 11 = new key
// shorter than 32 bytes, 9 = refused with nothing modified. The verification failure cannot be provoked from
// the binary (no fault injection on the CLI), so the mapping is tested where it lives. Mutant: 10 -> 1.
func TestRekeyError_MapsEveryRefusalToItsDocumentedExitCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{state.ErrRekeyVerify, 10},
		{fmt.Errorf("wrapped: %w", state.ErrRekeyVerify), 10},
		{state.ErrRekeyKeyTooShort, 11},
		{state.ErrRekeySameKey, ExitRefused},
		{state.ErrRekeyNoNewKey, ExitRefused},
		{state.ErrRekeyUncovered, ExitRefused},
		{state.ErrRekeyFromPrev, ExitRefused},
	} {
		err := rekeyError(tc.err, "state rekey: ")
		if got := exitCodeOf(err); got != tc.code {
			t.Errorf("%v -> exit %d, want %d", tc.err, got, tc.code)
		}
	}
	if ExitRekeyVerify != 10 || ExitRekeyKeyTooShort != 11 || ExitRefused != 9 {
		t.Errorf("documented codes changed: verify=%d too-short=%d refused=%d", ExitRekeyVerify, ExitRekeyKeyTooShort, ExitRefused)
	}
	// the message of a verification failure says the original was restored, and carries no key
	msg := rekeyError(fmt.Errorf("%w: boom; the original state was restored", state.ErrRekeyVerify), "state rekey: ").Error()
	if !strings.Contains(msg, "restored") {
		t.Errorf("message = %q", msg)
	}
	var ee *ExitError
	if !errors.As(rekeyError(state.ErrRekeyVerify, ""), &ee) || ee.Code != 10 {
		t.Error("an *ExitError with code 10 is expected")
	}
}
