package ws

import (
	"os"
	"testing"
)

// mustWriteFile creates or overwrites a file with given content. Fatals the test on error.
func mustWriteFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", path, err)
	}
}
