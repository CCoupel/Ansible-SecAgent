package integration

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// requireHealthyAfter is the final "the node is healthy" check of the load test (M11): a harness delay may cost an
// attempt, never the check. It returns true only when one of the `attempts` spaced probes answers exactly 200 with no
// transport error; a timeout, a 504, a 429 or any other answer on every attempt is a failure.
func requireHealthyAfter(probe func() execReply, attempts int, gap time.Duration, logf func(string, ...any)) (execReply, bool) {
	var last execReply
	for i := 1; i <= attempts; i++ {
		if i > 1 {
			time.Sleep(gap)
		}
		if last = probe(); last.Err == nil && last.Code == http.StatusOK {
			return last, true
		}
		logf("health probe %d/%d: %+v", i, attempts, last)
	}
	return last, false
}

func TestRequireHealthyAfter(t *testing.T) {
	seq := func(rs ...execReply) func() execReply {
		i := 0
		return func() execReply { r := rs[min(i, len(rs)-1)]; i++; return r }
	}
	timeout := execReply{Err: errors.New("context deadline exceeded")}
	gw := execReply{Code: http.StatusGatewayTimeout, Error: "task_timeout"}
	ok := execReply{Code: http.StatusOK}
	cases := []struct {
		name  string
		probe func() execReply
		want  bool
	}{
		{"200 at once", seq(ok), true},
		{"timeout then 200 (slow harness, retried)", seq(timeout, gw, ok), true},
		{"timeouts only: a blocked node must fail", seq(timeout), false},
		{"504 only must fail", seq(gw), false},
		{"429 only (slot not given back) must fail", seq(execReply{Code: http.StatusTooManyRequests}), false},
		{"200 with a transport error is not a success", seq(execReply{Code: http.StatusOK, Err: errors.New("EOF")}), false},
	}
	for _, c := range cases {
		if _, got := requireHealthyAfter(c.probe, 4, time.Millisecond, t.Logf); got != c.want {
			t.Errorf("%s: healthy = %v, want %v", c.name, got, c.want)
		}
	}
}
