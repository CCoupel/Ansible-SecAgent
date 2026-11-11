// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package dropreport

import (
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu    sync.Mutex
	calls []int64
}

func (r *recorder) add(n int64) { r.mu.Lock(); r.calls = append(r.calls, n); r.mu.Unlock() }
func (r *recorder) get() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.calls...)
}

func TestAggregator_ManyLossesOneReport(t *testing.T) {
	r := &recorder{}
	a := New(40*time.Millisecond, r.add)
	for i := 0; i < 44; i++ {
		a.Add(1)
	}
	time.Sleep(150 * time.Millisecond)
	if got := r.get(); len(got) != 1 || got[0] != 44 {
		t.Fatalf("reports = %v, want [44]", got)
	}
	a.Add(2) // a new period arms a new timer
	time.Sleep(150 * time.Millisecond)
	if got := r.get(); len(got) != 2 || got[1] != 2 {
		t.Fatalf("reports = %v, want [44 2]", got)
	}
	a.Stop()
}

func TestAggregator_NothingLostNothingReported(t *testing.T) {
	r := &recorder{}
	a := New(10*time.Millisecond, r.add)
	a.Add(0)
	a.Add(-3)
	time.Sleep(50 * time.Millisecond)
	a.Stop()
	if got := r.get(); len(got) != 0 {
		t.Fatalf("reports = %v, want none", got)
	}
}

func TestAggregator_StopFlushesOnceAndDisarms(t *testing.T) {
	r := &recorder{}
	a := New(time.Hour, r.add)
	a.Add(5)
	a.Stop()
	a.Add(1) // after Stop: counted nowhere, no timer
	a.Stop()
	if got := r.get(); len(got) != 1 || got[0] != 5 {
		t.Fatalf("reports = %v, want [5]", got)
	}
}

func TestAggregator_FlushKeepsItArmed(t *testing.T) {
	r := &recorder{}
	a := New(time.Hour, r.add)
	a.Add(2)
	a.Flush()
	a.Add(3)
	a.Flush()
	a.Stop()
	if got := r.get(); len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Fatalf("reports = %v, want [2 3]", got)
	}
}
