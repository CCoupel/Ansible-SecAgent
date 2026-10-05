package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// deadAPI is a loopback address that refuses connections.
func deadAPI(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	u := s.URL
	s.Close()
	return u
}

// resetServer reads the request then closes the connection without answering: a write sent to it
// "may have been applied".
func resetServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	n := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		_ = c.Close()
	}))
	t.Cleanup(s.Close)
	return s, n
}

func okServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	n := new(atomic.Int32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.Close)
	return s, n
}

func TestAPIURLs_Parsing(t *testing.T) {
	t.Setenv("RELAY_API_URL", "")
	if l, err := apiURLs(); err != nil || len(l) != 1 || l[0] != "http://localhost:7771" {
		t.Errorf("default: %v %v", l, err)
	}
	t.Setenv("RELAY_API_URL", "https://a:7771/, https://b:7771")
	if l, err := apiURLs(); err != nil || len(l) != 2 || l[0] != "https://a:7771" || l[1] != "https://b:7771" {
		t.Errorf("list: %v %v", l, err)
	}
	for _, bad := range []string{"https://a,,https://b", "ftp://a", "https://u:p@a", "https://a,https://a", "a:7771"} {
		t.Setenv("RELAY_API_URL", bad)
		_, err := apiURLs()
		if err == nil {
			t.Errorf("%q must be refused", bad)
		} else if strings.Contains(err.Error(), "u:p") {
			t.Errorf("userinfo leaked: %v", err)
		}
	}
}

func TestAPIRequest_ReadSwitchesAddressOnAnyFailure(t *testing.T) {
	reset, _ := resetServer(t)
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", deadAPI(t)+","+reset.URL+","+ok.URL)
	data, status, err := apiRequest("GET", "/api/admin/relays", nil)
	if err != nil || status != 200 || !strings.Contains(string(data), "ok") {
		t.Fatalf("read: %s %d %v", data, status, err)
	}
	if okHits.Load() != 1 {
		t.Errorf("hits on the good address = %d", okHits.Load())
	}
}

func TestAPIRequest_WriteSwitchesOnlyWhenNothingWasSent(t *testing.T) {
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", deadAPI(t)+","+ok.URL)
	if _, status, err := apiRequest("POST", "/api/admin/relays", map[string]string{"a": "b"}); err != nil || status != 200 {
		t.Fatalf("a refused connection is before send, the next address is used: %d %v", status, err)
	}
	if okHits.Load() != 1 {
		t.Errorf("hits = %d, want 1", okHits.Load())
	}
}

func TestAPIRequest_WriteIsNotReplayedAfterItLeft(t *testing.T) {
	reset, resetHits := resetServer(t)
	ok, okHits := okServer(t)
	t.Setenv("RELAY_API_URL", reset.URL+","+ok.URL)
	_, _, err := apiRequest("POST", "/api/admin/relays", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("the failed write must be reported")
	}
	if resetHits.Load() != 1 || okHits.Load() != 0 {
		t.Fatalf("hits: first=%d second=%d, want 1 and 0 (the write may have been applied)", resetHits.Load(), okHits.Load())
	}
}
