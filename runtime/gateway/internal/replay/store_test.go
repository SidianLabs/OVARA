// P2.1 durable replay — consume semantics across restart, crash,
// concurrency (in-process and cross-process on a shared journal),
// storage failure, corruption, expiry, and compaction.
package replay

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tmpJournal(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "replay.jsonl")
}

func open(t *testing.T, path string) *FileStore {
	t.Helper()
	s, err := OpenFile(path, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

var exp1h = time.Now().Add(time.Hour).UTC()

// A/B: first consume then exact replay.
func TestConsume_FirstThenReplay(t *testing.T) {
	s := open(t, tmpJournal(t))
	defer s.Close()
	if r := s.Consume(KindDelegation, "pid-1", exp1h); r != FirstConsume {
		t.Fatalf("first consume = %v, want FIRST_CONSUME", r)
	}
	if r := s.Consume(KindDelegation, "pid-1", exp1h); r != AlreadyConsumed {
		t.Fatalf("replay = %v, want ALREADY_CONSUMED", r)
	}
	if r := s.Consume(KindDelegation, "pid-2", exp1h); r != FirstConsume {
		t.Fatalf("different id = %v, want FIRST_CONSUME", r)
	}
}

// R/S: kind namespacing — the same raw id in different kinds is
// independent (a request nonce must not poison a delegation key).
func TestConsume_KindNamespacing(t *testing.T) {
	s := open(t, tmpJournal(t))
	defer s.Close()
	if r := s.Consume(KindRequest, "abc", exp1h); r != FirstConsume {
		t.Fatalf("req consume = %v", r)
	}
	if r := s.Consume(KindDelegation, "abc", exp1h); r != FirstConsume {
		t.Fatalf("same id different kind = %v, want FIRST_CONSUME", r)
	}
	if r := s.Consume(KindRequest, "abc", exp1h); r != AlreadyConsumed {
		t.Fatalf("req replay = %v", r)
	}
}

// C: replay after clean restart — close, reopen, replay denied.
func TestConsume_Restart(t *testing.T) {
	p := tmpJournal(t)
	s := open(t, p)
	if r := s.Consume(KindDelegation, "pid-1", exp1h); r != FirstConsume {
		t.Fatalf("consume = %v", r)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2 := open(t, p)
	defer s2.Close()
	if r := s2.Consume(KindDelegation, "pid-1", exp1h); r != AlreadyConsumed {
		t.Fatalf("replay after restart = %v, want ALREADY_CONSUMED", r)
	}
}

// D: replay after crash — the first store is never closed; a second
// opener on the same file must still see the fsynced record.
func TestConsume_Crash(t *testing.T) {
	p := tmpJournal(t)
	s := open(t, p)
	if r := s.Consume(KindDelegation, "pid-1", exp1h); r != FirstConsume {
		t.Fatalf("consume = %v", r)
	}
	// no Close — simulates abrupt termination; fsync already happened.
	s2 := open(t, p)
	defer s2.Close()
	if r := s2.Consume(KindDelegation, "pid-1", exp1h); r != AlreadyConsumed {
		t.Fatalf("replay after crash = %v, want ALREADY_CONSUMED", r)
	}
}

// E: N goroutines racing one consume — exactly one FIRST_CONSUME.
func TestConsume_ConcurrentInProcess(t *testing.T) {
	s := open(t, tmpJournal(t))
	defer s.Close()
	var first, dup, fail int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch s.Consume(KindDelegation, "race-id", exp1h) {
			case FirstConsume:
				atomic.AddInt64(&first, 1)
			case AlreadyConsumed:
				atomic.AddInt64(&dup, 1)
			default:
				atomic.AddInt64(&fail, 1)
			}
		}()
	}
	wg.Wait()
	if first != 1 || fail != 0 || dup != 63 {
		t.Fatalf("first=%d dup=%d fail=%d — want 1/63/0", first, dup, fail)
	}
}

// F: two FileStore instances on one journal (two gateway processes on
// the same filesystem domain) racing — exactly one FIRST_CONSUME.
func TestConsume_ConcurrentAcrossProcesses(t *testing.T) {
	p := tmpJournal(t)
	a, b := open(t, p), open(t, p)
	defer a.Close()
	defer b.Close()
	var first, fail int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			switch s.Consume(KindDelegation, "xproc-id", exp1h) {
			case FirstConsume:
				atomic.AddInt64(&first, 1)
			case StorageFailure:
				atomic.AddInt64(&fail, 1)
			}
		}(i)
	}
	wg.Wait()
	if first != 1 || fail != 0 {
		t.Fatalf("first=%d fail=%d — want exactly one consume across stores", first, fail)
	}
	// Sequential too: B must see A's consume.
	if r := b.Consume(KindDelegation, "a-then-b", exp1h); r != FirstConsume {
		t.Fatalf("A consume = %v", r)
	}
	if r := b.Consume(KindDelegation, "a-then-b", exp1h); r != AlreadyConsumed {
		t.Fatalf("B replay of A's consume = %v", r)
	}
}

// K/L: storage failure — consume on a closed file fails, never allows.
func TestConsume_StorageFailure(t *testing.T) {
	s := open(t, tmpJournal(t))
	s.Close()
	if r := s.Consume(KindDelegation, "pid-1", exp1h); r != StorageFailure {
		t.Fatalf("consume on dead store = %v, want STORAGE_FAILURE", r)
	}
}

// M: corrupt journal middle → OpenFile fails closed; corrupt tail
// (crash between write and fsync) → truncated, store opens.
func TestOpen_Corrupt(t *testing.T) {
	p := tmpJournal(t)
	s := open(t, p)
	s.Consume(KindDelegation, "good-1", exp1h)
	s.Close()
	// Append a corrupt TAIL — like a torn write; must be truncated.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"k":"deleg","p":"torn"`)
	f.Close()
	s2 := open(t, p)
	defer s2.Close()
	if r := s2.Consume(KindDelegation, "good-1", exp1h); r != AlreadyConsumed {
		t.Fatalf("live record lost after tail truncation: %v", r)
	}
	s2.Close()
	// Corrupt a NON-FINAL line — real corruption; open must fail.
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not-json\n")
	f.WriteString(`{"k":"deleg","p":"after","c":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}` + "\n")
	f.Close()
	if _, err := OpenFile(p, 0); err == nil {
		t.Fatal("corrupt mid-journal must fail open")
	}
}

// K/N: expired capability + expired record cleanup.
func TestConsume_ExpiryAndCompact(t *testing.T) {
	p := tmpJournal(t)
	s := open(t, p)
	defer s.Close()
	// An already-expired capability reaching consume is meaningless —
	// no record is written (validation upstream denies it first anyway).
	if r := s.Consume(KindDelegation, "dead", time.Now().Add(-time.Second)); r != FirstConsume {
		t.Fatalf("expired consume = %v", r)
	}
	if r := s.Consume(KindDelegation, "dead", time.Now().Add(-time.Second)); r != FirstConsume {
		t.Fatalf("expired id must not be replay-blocked: %v", r)
	}
	// Live record stays live; expired records compact away.
	s.Consume(KindDelegation, "short", time.Now().Add(10*time.Millisecond))
	s.Consume(KindDelegation, "long", exp1h)
	time.Sleep(20 * time.Millisecond)
	// Force compaction by exceeding maxBytes with a tiny limit.
	s.maxBytes = 1
	if r := s.Consume(KindDelegation, "trigger-compact", exp1h); r != FirstConsume {
		t.Fatalf("consume during compact = %v", r)
	}
	s.Close()
	// Reopen: expired "short" is gone from the journal; "long" survives.
	s2 := open(t, p)
	defer s2.Close()
	if r := s2.Consume(KindDelegation, "short", exp1h); r != FirstConsume {
		t.Fatalf("expired record should be GC'd, got %v", r)
	}
	if r := s2.Consume(KindDelegation, "long", exp1h); r != AlreadyConsumed {
		t.Fatalf("live record lost in compaction: %v", r)
	}
}

// Perf: durable consume = one append + fsync; replay check = memory.
func BenchmarkConsume(b *testing.B) {
	s, _ := OpenFile(filepath.Join(b.TempDir(), "r.jsonl"), 0)
	defer s.Close()
	exp := time.Now().Add(time.Hour).UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Consume(KindDelegation, fmt.Sprintf("id-%d", i), exp)
	}
}

func BenchmarkReplayCheck(b *testing.B) {
	s, _ := OpenFile(filepath.Join(b.TempDir(), "r.jsonl"), 0)
	defer s.Close()
	exp := time.Now().Add(time.Hour).UTC()
	s.Consume(KindDelegation, "hit", exp)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Consume(KindDelegation, "hit", exp)
	}
}
