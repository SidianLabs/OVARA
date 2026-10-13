package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/anchor"
)

// flakyOracle is unreachable until up is set, and remembers the highest
// seq it took.
type flakyOracle struct {
	mu   sync.Mutex
	up   bool
	took uint64
}

func (o *flakyOracle) Commit(_ context.Context, _ string, cp *anchor.Checkpoint) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.up {
		return anchor.ErrUnavailable
	}
	if cp.Seq < o.took {
		return anchor.ErrRegression
	}
	o.took = cp.Seq
	return nil
}

func (o *flakyOracle) tookSeq() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.took
}

// G-10: one outage does not leave the run's tail unanchored. When the
// oracle comes back, the newest checkpoint it missed is pushed without
// waiting for another mutation or a restart.
func TestDegradedAnchorRetriesAfterOutage(t *testing.T) {
	o := &flakyOracle{}
	w := &warnPusher{inner: o, minBackoff: time.Millisecond, maxBackoff: 5 * time.Millisecond}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := w.Commit(context.Background(), "d", &anchor.Checkpoint{Seq: seq}); err != nil {
			t.Fatalf("degraded push must not fail the mutation: %v", err)
		}
	}
	if w.Unanchored() != 3 {
		t.Fatalf("pending seq %d, want 3", w.Unanchored())
	}
	time.Sleep(10 * time.Millisecond)
	o.mu.Lock()
	o.up = true
	o.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if took := o.tookSeq(); took == 3 && w.Unanchored() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	took := o.tookSeq()
	t.Fatalf("tail not re-anchored after the oracle came back: oracle seq %d, pending %d", took, w.Unanchored())
}

// A later push from the mutation path supersedes the pending one.
func TestDegradedAnchorLaterPushSupersedes(t *testing.T) {
	o := &flakyOracle{}
	w := &warnPusher{inner: o, minBackoff: time.Hour}
	_ = w.Commit(context.Background(), "d", &anchor.Checkpoint{Seq: 1})
	o.mu.Lock()
	o.up = true
	o.mu.Unlock()
	if err := w.Commit(context.Background(), "d", &anchor.Checkpoint{Seq: 2}); err != nil {
		t.Fatal(err)
	}
	if w.Unanchored() != 0 {
		t.Fatalf("pending %d after a later push was taken", w.Unanchored())
	}
}
