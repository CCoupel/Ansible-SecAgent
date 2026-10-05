package storage

import (
	"context"
	"sync"
	"testing"
)

// SetOnWrite publishes the state write_seq after every successful write, and only then (#163).
func TestStore_OnWriteReportsTheWriteSeqAfterEachSuccessfulWrite(t *testing.T) {
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var mu sync.Mutex
	var seqs []uint64
	s.SetOnWrite(func(seq uint64) { mu.Lock(); seqs = append(seqs, seq); mu.Unlock() })

	before := s.WriteSeq()
	for _, h := range []string{"h1", "h2"} {
		if err := s.AddAuthorizedKey(context.Background(), h, "pem", "ci"); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seqs) != 2 || seqs[0] <= before || seqs[1] <= seqs[0] || seqs[1] != s.WriteSeq() {
		t.Fatalf("seqs = %v (before %d, now %d)", seqs, before, s.WriteSeq())
	}
	// a refused write reports nothing
	s.SetWriteGuard(func() error { return ErrReadOnly })
	n := len(seqs)
	mu.Unlock()
	err = s.AddAuthorizedKey(context.Background(), "h3", "pem", "ci")
	mu.Lock()
	if err == nil || len(seqs) != n {
		t.Fatalf("a refused write must not report a seq: err=%v seqs=%v", err, seqs)
	}
}
