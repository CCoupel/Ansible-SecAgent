// Package secretenv reads a secret from the environment either directly (X)
// or from a file (X_FILE), the convention used by Docker/Compose secrets.
//
// Rules (fail closed, #196):
//   - X and X_FILE both set (non-empty): error, the caller must refuse to start.
//   - X_FILE must designate a regular file (no symlink, no device/pipe/dir)
//     whose permissions grant nothing to group/others (mode & 0077 == 0).
//   - Trailing whitespace is trimmed; an empty secret is an error.
//   - The secret value is NEVER logged nor included in an error; the file path may be.
package secretenv

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// maxSecretSize bounds the bytes read from a secret file (tokens and keys are far smaller).
const maxSecretSize = 64 * 1024

// Sentinel errors (wrapped with the variable name and, when relevant, the path).
var (
	ErrBothSet        = errors.New("both the variable and its _FILE variant are set")
	ErrNotRegular     = errors.New("secret file is not a regular file")
	ErrSymlink        = errors.New("secret file is a symbolic link")
	ErrPermissions    = errors.New("secret file permissions are too open (must be 0600 or stricter)")
	ErrEmpty          = errors.New("secret file is empty")
	ErrTooLarge       = errors.New("secret file is too large")
	ErrFileUnreadable = errors.New("secret file cannot be read")
)

// Lookup returns the secret named name. It reads name, or name+"_FILE" when
// that one is set. found is false (with a nil error) when neither is set.
// An empty variable counts as unset.
func Lookup(name string) (value string, found bool, err error) {
	return LookupFrom(os.Getenv, name)
}

// LookupFrom is Lookup over an arbitrary environment accessor (tests, injected getenv).
func LookupFrom(getenv func(string) string, name string) (value string, found bool, err error) {
	direct := getenv(name)
	path := getenv(name + "_FILE")
	switch {
	case direct != "" && path != "":
		return "", false, fmt.Errorf("%s: %w", name, ErrBothSet)
	case path != "":
		v, err := readFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s_FILE (%s): %w", name, path, err)
		}
		slog.Debug("secretenv: secret loaded from file", "variable", name+"_FILE", "path", path)
		return v, true, nil
	case direct != "":
		return direct, true, nil
	}
	return "", false, nil
}

// GetFrom is LookupFrom returning "" when the secret is not set.
func GetFrom(getenv func(string) string, name string) (string, error) {
	v, _, err := LookupFrom(getenv, name)
	return v, err
}

// Get is Lookup returning "" when the secret is not set.
func Get(name string) (string, error) {
	v, _, err := Lookup(name)
	return v, err
}

// readFile reads and validates a secret file. The check is done on the opened
// descriptor (no TOCTOU), after an Lstat that rejects symbolic links.
func readFile(path string) (string, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileUnreadable, errKind(err))
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return "", ErrSymlink
	}
	if !li.Mode().IsRegular() {
		return "", ErrNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileUnreadable, errKind(err))
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileUnreadable, errKind(err))
	}
	if !os.SameFile(li, fi) || !fi.Mode().IsRegular() {
		return "", ErrNotRegular // swapped between Lstat and Open
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w (mode %04o)", ErrPermissions, fi.Mode().Perm())
	}
	if fi.Size() > maxSecretSize {
		return "", ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretSize+1))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrFileUnreadable, errKind(err))
	}
	if len(data) > maxSecretSize {
		return "", ErrTooLarge
	}
	v := strings.TrimRight(string(data), " \t\r\n")
	if v == "" {
		return "", ErrEmpty
	}
	return v, nil
}

// errKind gives a short reason without echoing anything but OS error text
// (which contains the path, not the content).
func errKind(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "does not exist"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	}
	return "i/o error"
}
