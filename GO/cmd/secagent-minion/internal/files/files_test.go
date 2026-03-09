package files

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// tempAllowedDir returns a temp dir that is inside an allowed prefix.
// On Linux/Mac: /tmp/test-xxx, on Windows: uses t.TempDir() under /tmp prefix via AllowedWritePrefixes override.
func tempAllowedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// setupAllowedPrefixes temporarily adds t.TempDir() to AllowedWritePrefixes and AllowedReadPrefixes.
func setupAllowedPrefixes(t *testing.T, dir string) func() {
	t.Helper()
	origWrite := AllowedWritePrefixes
	origRead := AllowedReadPrefixes

	// Normalize to forward slashes
	normalized := filepath.ToSlash(dir) + "/"
	AllowedWritePrefixes = append([]string{normalized}, origWrite...)
	AllowedReadPrefixes = append([]string{normalized}, origRead...)

	return func() {
		AllowedWritePrefixes = origWrite
		AllowedReadPrefixes = origRead
	}
}

// ========================================================================
// PutFile — success
// ========================================================================

func TestPutFileSuccess(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	content := "hello from PutFile"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	dest := filepath.Join(dir, "test.txt")

	err := PutFile(PutFileRequest{
		TaskID:  "task-1",
		Dest:    dest,
		DataB64: encoded,
		Mode:    "0644",
	})
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != content {
		t.Errorf("file content: got %q, want %q", data, content)
	}
}

func TestPutFileDefaultMode(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	dest := filepath.Join(dir, "mode-test.txt")
	err := PutFile(PutFileRequest{
		TaskID:  "task-mode",
		Dest:    dest,
		DataB64: base64.StdEncoding.EncodeToString([]byte("content")),
		Mode:    "", // default 0644
	})
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}
}

func TestPutFileCustomMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod not fully supported on Windows")
	}
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	dest := filepath.Join(dir, "exec.sh")
	err := PutFile(PutFileRequest{
		TaskID:  "task-chmod",
		Dest:    dest,
		DataB64: base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\necho hi")),
		Mode:    "0700",
	})
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode: got %o, want 0700", info.Mode().Perm())
	}
}

func TestPutFileCreatesParentDirs(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	dest := filepath.Join(dir, "subdir", "nested", "file.txt")
	err := PutFile(PutFileRequest{
		TaskID:  "task-nested",
		Dest:    dest,
		DataB64: base64.StdEncoding.EncodeToString([]byte("nested content")),
		Mode:    "0644",
	})
	if err != nil {
		t.Fatalf("PutFile with nested dirs: %v", err)
	}

	if _, err := os.Stat(dest); err != nil {
		t.Errorf("file not created at nested path: %v", err)
	}
}

func TestPutFileRawBase64(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	content := "raw base64 content"
	// RawStdEncoding (no padding)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(content))
	dest := filepath.Join(dir, "raw.txt")

	err := PutFile(PutFileRequest{
		TaskID:  "task-raw",
		Dest:    dest,
		DataB64: encoded,
		Mode:    "0644",
	})
	if err != nil {
		t.Fatalf("PutFile with raw base64: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != content {
		t.Errorf("content: got %q, want %q", data, content)
	}
}

// ========================================================================
// PutFile — errors
// ========================================================================

func TestPutFilePathTraversal(t *testing.T) {
	err := PutFile(PutFileRequest{
		TaskID:  "task-traversal",
		Dest:    "/etc/passwd",
		DataB64: base64.StdEncoding.EncodeToString([]byte("hack")),
	})
	if err == nil {
		t.Error("expected path traversal error for /etc/passwd")
	}
	if !IsPathTraversalError(err) {
		t.Errorf("expected PathTraversalError, got: %v", err)
	}
}

func TestPutFilePathTraversalDotDot(t *testing.T) {
	err := PutFile(PutFileRequest{
		TaskID:  "task-dotdot",
		Dest:    "/tmp/../etc/passwd",
		DataB64: base64.StdEncoding.EncodeToString([]byte("hack")),
	})
	if err == nil {
		t.Error("expected path traversal error for ../etc/passwd")
	}
	if !IsPathTraversalError(err) {
		t.Errorf("expected PathTraversalError, got: %v", err)
	}
}

func TestPutFileEmptyDest(t *testing.T) {
	err := PutFile(PutFileRequest{
		TaskID:  "task-empty-dest",
		Dest:    "",
		DataB64: base64.StdEncoding.EncodeToString([]byte("data")),
	})
	if err == nil {
		t.Error("expected error for empty dest")
	}
}

func TestPutFileInvalidBase64(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	err := PutFile(PutFileRequest{
		TaskID:  "task-bad-b64",
		Dest:    filepath.Join(dir, "bad.txt"),
		DataB64: "not-valid-base64!!!",
	})
	if err == nil {
		t.Error("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "decode base64") {
		t.Errorf("error message: got %q, want 'decode base64'", err.Error())
	}
}

func TestPutFileTooLarge(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	// 501 KB — just over the 500KB limit
	large := make([]byte, MaxFileSize+1024)
	for i := range large {
		large[i] = 'x'
	}
	encoded := base64.StdEncoding.EncodeToString(large)

	err := PutFile(PutFileRequest{
		TaskID:  "task-too-large",
		Dest:    filepath.Join(dir, "large.bin"),
		DataB64: encoded,
	})
	if err == nil {
		t.Error("expected error for file too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error message: got %q, want 'too large'", err.Error())
	}
}

func TestPutFileExactlyMaxSize(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	// Exactly MaxFileSize — should succeed
	exact := make([]byte, MaxFileSize)
	for i := range exact {
		exact[i] = 'a'
	}
	encoded := base64.StdEncoding.EncodeToString(exact)

	err := PutFile(PutFileRequest{
		TaskID:  "task-exact",
		Dest:    filepath.Join(dir, "exact.bin"),
		DataB64: encoded,
		Mode:    "0644",
	})
	if err != nil {
		t.Fatalf("PutFile exact max size: %v", err)
	}
}

// ========================================================================
// FetchFile — success
// ========================================================================

func TestFetchFileSuccess(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	content := "file to fetch"
	src := filepath.Join(dir, "fetch.txt")
	if err := os.WriteFile(src, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	b64, err := FetchFile(FetchFileRequest{TaskID: "task-fetch", Src: src})
	if err != nil {
		t.Fatalf("FetchFile: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(decoded) != content {
		t.Errorf("content: got %q, want %q", decoded, content)
	}
}

func TestFetchFileEmptyFile(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	src := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(src, []byte{}, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	b64, err := FetchFile(FetchFileRequest{TaskID: "task-empty", Src: src})
	if err != nil {
		t.Fatalf("FetchFile empty: %v", err)
	}
	// Empty file → empty base64 string
	decoded, _ := base64.StdEncoding.DecodeString(b64)
	if len(decoded) != 0 {
		t.Errorf("expected empty decoded content, got %d bytes", len(decoded))
	}
}

// ========================================================================
// FetchFile — errors
// ========================================================================

func TestFetchFilePathTraversal(t *testing.T) {
	_, err := FetchFile(FetchFileRequest{
		TaskID: "task-traversal-fetch",
		Src:    "/usr/local/secret",
	})
	if err == nil {
		t.Error("expected path traversal error")
	}
	if !IsPathTraversalError(err) {
		t.Errorf("expected PathTraversalError, got: %v", err)
	}
}

func TestFetchFileNotFound(t *testing.T) {
	dir := tempAllowedDir(t)
	restore := setupAllowedPrefixes(t, dir)
	defer restore()

	_, err := FetchFile(FetchFileRequest{
		TaskID: "task-notfound",
		Src:    filepath.Join(dir, "nonexistent.txt"),
	})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "fetch_file") {
		t.Errorf("error message: got %q", err.Error())
	}
}

func TestFetchFileEmptySrc(t *testing.T) {
	_, err := FetchFile(FetchFileRequest{
		TaskID: "task-empty-src",
		Src:    "",
	})
	if err == nil {
		t.Error("expected error for empty src")
	}
}

// ========================================================================
// validatePath
// ========================================================================

func TestValidatePathAllowed(t *testing.T) {
	tests := []struct {
		path    string
		allowed []string
	}{
		{"/tmp/file.txt", []string{"/tmp/"}},
		{"/tmp/subdir/file.txt", []string{"/tmp/"}},
		{"/home/user/file.txt", []string{"/home/"}},
		{"/opt/app/config", []string{"/opt/"}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, err := validatePath(tt.path, tt.allowed, "path")
			if err != nil {
				t.Errorf("validatePath(%q) unexpected error: %v", tt.path, err)
			}
		})
	}
}

func TestValidatePathNotAllowed(t *testing.T) {
	tests := []string{
		"/etc/passwd",
		"/bin/sh",
		"/usr/bin/env",
		"/proc/meminfo",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			_, err := validatePath(path, []string{"/tmp/"}, "path")
			if err == nil {
				t.Errorf("expected error for %q", path)
			}
			if !IsPathTraversalError(err) {
				t.Errorf("expected PathTraversalError for %q, got: %v", path, err)
			}
		})
	}
}

func TestValidatePathDotDot(t *testing.T) {
	// /tmp/../etc/passwd → resolves to /etc/passwd → not allowed
	_, err := validatePath("/tmp/../etc/passwd", []string{"/tmp/"}, "dest")
	if err == nil {
		t.Error("expected error for /tmp/../etc/passwd")
	}
}

func TestValidatePathEmpty(t *testing.T) {
	_, err := validatePath("", []string{"/tmp/"}, "dest")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestValidatePathWhitespaceOnly(t *testing.T) {
	_, err := validatePath("   ", []string{"/tmp/"}, "dest")
	if err == nil {
		t.Error("expected error for whitespace-only path")
	}
}

// ========================================================================
// PathTraversalError
// ========================================================================

func TestPathTraversalError(t *testing.T) {
	e := &PathTraversalError{
		Path:     "/etc/passwd",
		Param:    "dest",
		Resolved: "/etc/passwd",
	}
	msg := e.Error()
	if !strings.Contains(msg, "path traversal") {
		t.Errorf("error message: got %q", msg)
	}
	if !strings.Contains(msg, "dest") {
		t.Errorf("error message missing param: %q", msg)
	}
}

func TestIsPathTraversalError(t *testing.T) {
	e := &PathTraversalError{Path: "/x", Param: "p", Resolved: "/x"}
	if !IsPathTraversalError(e) {
		t.Error("expected true for PathTraversalError")
	}

	otherErr := errors.New("other error")
	if IsPathTraversalError(otherErr) {
		t.Error("expected false for non-PathTraversalError")
	}
}

// ========================================================================
// Constants
// ========================================================================

func TestMaxFileSize(t *testing.T) {
	if MaxFileSize != 500*1024 {
		t.Errorf("MaxFileSize: got %d, want %d", MaxFileSize, 500*1024)
	}
}

func TestAllowedPrefixesDefined(t *testing.T) {
	if len(AllowedWritePrefixes) == 0 {
		t.Error("AllowedWritePrefixes should not be empty")
	}
	if len(AllowedReadPrefixes) == 0 {
		t.Error("AllowedReadPrefixes should not be empty")
	}
}
