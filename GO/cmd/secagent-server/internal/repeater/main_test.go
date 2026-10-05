package repeater

import (
	"os"
	"testing"
)

// The repeater tests dial httptest servers on 127.0.0.1: the SSRF guard is lifted for them. The guard's
// own tests (dialtarget_test.go) switch it back on explicitly.
func TestMain(m *testing.M) {
	UnsafeAllowInternalDialTargets(true)
	os.Exit(m.Run())
}
