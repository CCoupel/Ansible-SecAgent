//go:build slow

// Regression (#179, slow suite: the subject IS a 17 s task): the API listener has a 15 s WriteTimeout meant
// for ordinary requests. A blocking exec that lasts longer was executed, but its answer was cut — the TLS
// record was truncated and the client saw "bad record MAC". The handler now extends the write deadline to
// the task's own timeout; this test would fail with the old behaviour (mutation checked, see the report).

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestExec_AnAnswerLongerThanTheAPIWriteTimeoutArrivesIntact(t *testing.T) {
	n := startNode(t, nodeSpec{ID: "root"})
	m := heldMinions(t, n, "slow-host")["slow-host"]

	// a payload large enough to span several TLS records: a cut answer cannot go unnoticed
	payload := strings.Repeat("0123456789abcdef", 16<<10) // 256 KiB
	body, _ := json.Marshal(map[string]any{"cmd": "sleep 17", "timeout": 40})
	type reply struct {
		code int
		raw  []byte
		err  error
	}
	got := make(chan reply, 1)
	start := time.Now()
	go func() {
		req, _ := http.NewRequest("POST", n.apiURL()+"/api/exec/slow-host", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+n.pluginToken())
		req.Header.Set("Content-Type", "application/json")
		resp, err := longHTTP().Do(req)
		if err != nil {
			got <- reply{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		got <- reply{code: resp.StatusCode, raw: raw, err: err}
	}()

	waitReceived(t, m, 1)
	time.Sleep(17 * time.Second) // longer than the 15 s WriteTimeout of the API listener
	m.write(map[string]any{"task_id": m.received()[0], "type": "result", "rc": 0, "stdout": payload})

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("the answer of a task that lasted %s did not arrive: %v (the write deadline of the API listener cut it)", time.Since(start).Round(time.Second), r.err)
		}
		if r.code != http.StatusOK {
			t.Fatalf("status %d: %.200s", r.code, r.raw)
		}
		var out struct {
			RC     int    `json:"rc"`
			Stdout string `json:"stdout"`
		}
		if err := json.Unmarshal(r.raw, &out); err != nil {
			t.Fatalf("the answer is not valid JSON (truncated?): %v", err)
		}
		if out.RC != 0 || out.Stdout != payload {
			t.Errorf("answer altered: rc=%d stdout %d bytes, want %d identical bytes", out.RC, len(out.Stdout), len(payload))
		}
	case <-time.After(60 * time.Second):
		t.Fatal("no answer within 60 s")
	}
}
