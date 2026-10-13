package server

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/anchor"
)

// warnPusher degrades oracle UNAVAILABILITY to warnings — the local
// mutation is already durable (fsync before push), so an offline oracle
// leaves the same unanchored tail either way. F-D1 remediation: only
// availability errors are swallowed; integrity signals (equivocation,
// bad key, malformed response) propagate and fail the mutation — a fork
// is never masked as "oracle offline".
//
// An outage does not switch anchoring off for the rest of the run: the
// newest checkpoint the oracle could not take is retried in the
// background, with backoff, until it is taken or a later push supersedes
// it. That tail was written by this process itself, so pushing it is the
// same act as the push that failed (unlike a tail found at boot, which
// only the operator's catch-up may anchor).
type warnPusher struct {
	inner anchor.Pusher

	// Retry backoff bounds; zero means the defaults (1s, 1m).
	minBackoff, maxBackoff time.Duration

	mu       sync.Mutex
	pending  *anchor.Checkpoint // newest checkpoint the oracle has not taken
	domain   string
	anchored uint64 // highest seq the oracle has taken in this run
	retrying bool
}

func (w *warnPusher) Commit(ctx context.Context, domain string, cp *anchor.Checkpoint) error {
	err := w.inner.Commit(ctx, domain, cp)
	if err == nil {
		w.taken(cp.Seq)
		return nil
	}
	if errors.Is(err, anchor.ErrUnavailable) {
		log.Printf("anchor: checkpoint push failed (degraded — unanchored tail at seq %d; retrying in the background): %v", cp.Seq, err)
		w.keep(domain, cp)
		return nil
	}
	log.Printf("anchor: INTEGRITY failure on checkpoint push — refusing to mask it: %v", err)
	return err
}

// taken records that the oracle holds seq, clearing a pending checkpoint
// it supersedes.
func (w *warnPusher) taken(seq uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq > w.anchored {
		w.anchored = seq
	}
	if w.pending != nil && w.pending.Seq <= w.anchored {
		w.pending = nil
	}
}

// keep holds cp for retry and starts the retry loop if it is not running.
func (w *warnPusher) keep(domain string, cp *anchor.Checkpoint) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil || cp.Seq > w.pending.Seq {
		c := *cp
		w.pending, w.domain = &c, domain
	}
	if !w.retrying {
		w.retrying = true
		go w.retry()
	}
}

// Unanchored reports the newest checkpoint seq the oracle has not taken
// yet (0 when the oracle is up to date).
func (w *warnPusher) Unanchored() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil {
		return 0
	}
	return w.pending.Seq
}

func (w *warnPusher) retry() {
	backoff, maxB := w.minBackoff, w.maxBackoff
	if backoff <= 0 {
		backoff = time.Second
	}
	if maxB <= 0 {
		maxB = time.Minute
	}
	for {
		time.Sleep(backoff)
		w.mu.Lock()
		cp, domain := w.pending, w.domain
		if cp == nil {
			w.retrying = false
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := w.inner.Commit(ctx, domain, cp)
		cancel()
		switch {
		case err == nil:
			log.Printf("anchor: oracle reachable again; tail anchored at seq %d", cp.Seq)
			w.taken(cp.Seq)
			backoff = w.minBackoff
			if backoff <= 0 {
				backoff = time.Second
			}
		case errors.Is(err, anchor.ErrUnavailable):
			backoff *= 2
			if backoff > maxB {
				backoff = maxB
			}
		case errors.Is(err, anchor.ErrRegression) && w.superseded(cp.Seq):
			// A later push from the mutation path got there first.
			w.taken(cp.Seq)
		default:
			log.Printf("anchor: INTEGRITY failure re-anchoring seq %d — not retrying; investigate before trusting this journal: %v", cp.Seq, err)
			w.mu.Lock()
			w.retrying = false
			w.mu.Unlock()
			return
		}
	}
}

func (w *warnPusher) superseded(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.anchored >= seq
}
