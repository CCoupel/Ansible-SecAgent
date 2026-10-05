package lock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The protocol must not depend on what NFS makes unreliable: no chmod on a path (fchmod on our
// descriptor only), no file times, no directory listing.
func TestProtocolSourceAvoidsPathChmodMtimeAndReaddir(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, forbidden := range []string{"os.Chmod(", "os.Chtimes(", "ModTime(", "ReadDir(", "Readdir(", "Readdirnames(", "filepath.Glob(", "filepath.Walk", "os.Stat("} {
			if strings.Contains(src, forbidden) {
				t.Errorf("%s uses %s", f, forbidden)
			}
		}
	}
}
