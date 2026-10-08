package secretenv

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretValue = "secagent_enr_SUPERSECRET123"

func writeSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // bypass umask
		t.Fatal(err)
	}
	return p
}

func TestLookup(t *testing.T) {
	t.Run("direct value", func(t *testing.T) {
		t.Setenv("TSEC", secretValue)
		v, found, err := Lookup("TSEC")
		if err != nil || !found || v != secretValue {
			t.Fatalf("got %q %v %v", v, found, err)
		}
	})
	t.Run("file value, trailing whitespace trimmed", func(t *testing.T) {
		t.Setenv("TSEC_FILE", writeSecret(t, secretValue+" \r\n\n", 0o600))
		v, found, err := Lookup("TSEC")
		if err != nil || !found || v != secretValue {
			t.Fatalf("got %q %v %v", v, found, err)
		}
	})
	t.Run("read-only 0400 accepted", func(t *testing.T) {
		t.Setenv("TSEC_FILE", writeSecret(t, secretValue, 0o400))
		if v, err := Get("TSEC"); err != nil || v != secretValue {
			t.Fatalf("got %q %v", v, err)
		}
	})
	t.Run("absent", func(t *testing.T) {
		v, found, err := Lookup("TSEC_NOT_SET")
		if err != nil || found || v != "" {
			t.Fatalf("got %q %v %v", v, found, err)
		}
	})
	t.Run("empty variables count as unset", func(t *testing.T) {
		t.Setenv("TSEC", "")
		t.Setenv("TSEC_FILE", "")
		if _, found, err := Lookup("TSEC"); err != nil || found {
			t.Fatalf("found=%v err=%v", found, err)
		}
	})
	t.Run("empty direct + file set uses the file", func(t *testing.T) {
		t.Setenv("TSEC", "")
		t.Setenv("TSEC_FILE", writeSecret(t, secretValue, 0o600))
		if v, err := Get("TSEC"); err != nil || v != secretValue {
			t.Fatalf("got %q %v", v, err)
		}
	})
	t.Run("both set refuses", func(t *testing.T) {
		t.Setenv("TSEC", secretValue)
		t.Setenv("TSEC_FILE", writeSecret(t, secretValue, 0o600))
		v, _, err := Lookup("TSEC")
		if !errors.Is(err, ErrBothSet) || v != "" {
			t.Fatalf("got %q %v", v, err)
		}
		if strings.Contains(err.Error(), secretValue) {
			t.Fatal("error leaks the value")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		t.Setenv("TSEC_FILE", filepath.Join(t.TempDir(), "nope"))
		if _, _, err := Lookup("TSEC"); !errors.Is(err, ErrFileUnreadable) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		target := writeSecret(t, secretValue, 0o600)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlink unsupported:", err)
		}
		t.Setenv("TSEC_FILE", link)
		if _, _, err := Lookup("TSEC"); !errors.Is(err, ErrSymlink) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("directory refused", func(t *testing.T) {
		t.Setenv("TSEC_FILE", t.TempDir())
		if _, _, err := Lookup("TSEC"); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("too open permissions refused", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o700 | 0o010} {
			t.Setenv("TSEC_FILE", writeSecret(t, secretValue, mode))
			v, _, err := Lookup("TSEC")
			if !errors.Is(err, ErrPermissions) || v != "" {
				t.Fatalf("mode %04o: got %q %v", mode, v, err)
			}
			if strings.Contains(err.Error(), secretValue) {
				t.Fatal("error leaks the value")
			}
		}
	})
	t.Run("empty file refused", func(t *testing.T) {
		for _, c := range []string{"", " \n\t\r\n"} {
			t.Setenv("TSEC_FILE", writeSecret(t, c, 0o600))
			if _, _, err := Lookup("TSEC"); !errors.Is(err, ErrEmpty) {
				t.Fatalf("content %q: got %v", c, err)
			}
		}
	})
	t.Run("oversized file refused", func(t *testing.T) {
		t.Setenv("TSEC_FILE", writeSecret(t, strings.Repeat("a", maxSecretSize+1), 0o600))
		if _, _, err := Lookup("TSEC"); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
}

// The secret value must never reach the logs, whatever the path taken.
func TestLogsNeverContainTheValue(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	t.Setenv("TSEC_FILE", writeSecret(t, secretValue, 0o600))
	if v, err := Get("TSEC"); err != nil || v != secretValue {
		t.Fatalf("got %q %v", v, err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected a debug trace of the file load")
	}
	if strings.Contains(buf.String(), secretValue) {
		t.Fatalf("log leaks the secret: %s", buf.String())
	}
}
