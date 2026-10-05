package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/localstatus"
)

func runStatusLocal(t *testing.T, now time.Time, args ...string) (string, error) {
	t.Helper()
	statusNow = func() time.Time { return now }
	t.Cleanup(func() { statusNow = time.Now })
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs(append([]string{"status"}, args...))
	defer func() { statusLocal = false; rootCmd.SetArgs(nil) }()
	err := rootCmd.Execute()
	return out.String(), err
}

func TestStatusLocal_Verdicts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	t.Setenv(localstatus.EnvStatusFile, p)
	now := time.UnixMilli(50_000_000)
	code := func(err error) int {
		var ee *ExitError
		if errors.As(err, &ee) {
			return ee.Code
		}
		if err != nil {
			return -1
		}
		return 0
	}

	if _, err := runStatusLocal(t, now, "--local"); code(err) != 1 || !strings.Contains(err.Error(), "no status file") {
		t.Fatalf("absent file: %v", err)
	}
	write := func(f localstatus.File) {
		t.Helper()
		f.UpdatedAt = now.UnixMilli()
		if err := localstatus.Write(p, f); err != nil {
			t.Fatal(err)
		}
	}
	write(localstatus.File{Role: "master", InstanceID: "m1", State: localstatus.StateReady, LastBeatAt: now.Add(-5 * time.Second).UnixMilli(), BeatPeriodMS: 30000, CheckPeriodMS: 5000})
	if out, err := runStatusLocal(t, now, "--local"); err != nil || !strings.Contains(out, "m1") || !strings.Contains(out, "master") || !strings.Contains(out, "healthy") || !strings.Contains(out, "state_mode") {
		t.Fatalf("healthy master: %q %v", out, err)
	}
	write(localstatus.File{Role: "secondary", InstanceID: "s1", State: localstatus.StateWaiting, LastCheckAt: now.Add(-2 * time.Second).UnixMilli(), BeatPeriodMS: 30000, CheckPeriodMS: 5000})
	if _, err := runStatusLocal(t, now, "--local"); err != nil {
		t.Fatalf("healthy secondary: %v", err)
	}
	if _, err := runStatusLocal(t, now.Add(time.Minute), "--local"); code(err) != 1 {
		t.Fatalf("frozen secondary (old check): %v", err)
	}
	write(localstatus.File{Role: "lost", InstanceID: "m1", State: localstatus.StateLost, Detail: "lock lost", LastBeatAt: now.UnixMilli(), BeatPeriodMS: 30000})
	if _, err := runStatusLocal(t, now, "--local"); code(err) != 1 {
		t.Fatalf("lost: %v", err)
	}
	if _, err := runStatusLocal(t, now); err == nil {
		t.Fatal("without --local the command must explain itself")
	}
}

func TestCheckHTTPS_LoopbackOnly(t *testing.T) {
	for _, ok := range []string{"http://localhost:7771", "http://127.0.0.1:7771", "http://127.1.2.3:7771", "http://[::1]:7771", "https://anything.example.com"} {
		if err := checkHTTPS(ok); err != nil {
			t.Errorf("%s must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://localhost.evil.example.com:7771", "http://127.0.0.1.evil.example.com", "http://10.0.0.5:7771", "http://relay.internal:7771", "http://evil.example.com/localhost"} {
		if err := checkHTTPS(bad); err == nil {
			t.Errorf("%s must be refused (cleartext admin token)", bad)
		}
	}
}

// `status --local` opens no port and calls no API: a counting admin API receives nothing.
func TestStatusLocal_DoesNoNetworkCall(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	t.Setenv("RELAY_API_URL", srv.URL)
	p := filepath.Join(t.TempDir(), "status.json")
	t.Setenv(localstatus.EnvStatusFile, p)
	now := time.UnixMilli(70_000_000)
	_ = localstatus.Write(p, localstatus.File{Role: "secondary", InstanceID: "s", State: localstatus.StateWaiting, LastCheckAt: now.UnixMilli(), BeatPeriodMS: 30000, CheckPeriodMS: 5000, UpdatedAt: now.UnixMilli()})
	if _, err := runStatusLocal(t, now, "--local"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("status --local called the API %d time(s)", hits.Load())
	}
}
