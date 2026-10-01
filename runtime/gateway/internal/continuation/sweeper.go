package continuation

import (
	"log"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type Sweeper struct {
	store      Store
	eventStore events.Store
	gatewayID  string
	mu         sync.Mutex
	stopChan   chan struct{}
	running    bool
}

func NewSweeper(store Store) *Sweeper {
	return &Sweeper{
		store:    store,
		stopChan: make(chan struct{}),
	}
}

func (s *Sweeper) SetEventStore(es events.Store) {
	s.eventStore = es
}

func (s *Sweeper) SetGatewayID(id string) {
	s.gatewayID = id
}

func (s *Sweeper) Start(intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 60
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	// stopChan is closed by Stop; recreate it so Start-after-Stop works and
	// a second Stop does not panic on a closed channel.
	s.stopChan = make(chan struct{})
	s.running = true
	s.mu.Unlock()

	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.runSweep()
			case <-s.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Sweeper) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
}

func (s *Sweeper) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// expireDue scans non-terminal candidates and expires those that are due via
// the atomic ExpireIfDue store method. The store rechecks the live state
// under its lock, so a continuation claimed between the scan and the expiry
// can never be flipped to expired mid-run.
func (s *Sweeper) expireDue(now time.Time) (scanned, expired int) {
	candidates := s.store.ListNonTerminal()
	for _, cnt := range candidates {
		if !cnt.ShouldExpire(now) {
			continue
		}
		exp, ok := s.store.ExpireIfDue(cnt.ContinuationID, now)
		if !ok {
			continue
		}
		expired++

		if s.eventStore != nil {
			evt := events.NewEvent(events.EventTypeContinuationExpired).
				WithGatewayID(s.gatewayID).
				WithDecisionID(exp.DecisionID).
				WithApprovalID(exp.ApprovalID).
				WithAgentID(exp.AgentID).
				WithContinuationID(exp.ContinuationID).
				WithPayload(map[string]any{
					"continuation_id": exp.ContinuationID,
					"state":           string(exp.State),
					"reason":          "expired",
				})
			s.eventStore.Append(evt)
		}
	}
	return len(candidates), expired
}

func (s *Sweeper) runSweep() {
	now := time.Now().UTC()
	scanned, expiredCount := s.expireDue(now)

	if expiredCount > 0 && s.eventStore != nil {
		evt := events.NewEvent("continuation.sweep_completed").
			WithGatewayID(s.gatewayID).
			WithPayload(map[string]any{
				"expired_count": expiredCount,
				"scanned_count": scanned,
			})
		s.eventStore.Append(evt)
	}

	log.Printf("SWEEP continuations scanned=%d expired=%d", scanned, expiredCount)
}

func (s *Sweeper) SweepNow() int {
	_, expired := s.expireDue(time.Now().UTC())
	return expired
}

func (s *Sweeper) ReconcileOnStartup() int {
	_, expired := s.expireDue(time.Now().UTC())
	return expired
}
