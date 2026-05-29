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

func (s *Sweeper) runSweep() {
	now := time.Now().UTC()
	candidates := s.store.ListNonTerminal()

	expiredCount := 0
	for _, cnt := range candidates {
		if cnt.ShouldExpire(now) {
			cnt.MarkExpired()
			s.store.Update(cnt)
			expiredCount++

			if s.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationExpired).
					WithGatewayID(s.gatewayID).
					WithDecisionID(cnt.DecisionID).
					WithApprovalID(cnt.ApprovalID).
					WithAgentID(cnt.AgentID).
					WithContinuationID(cnt.ContinuationID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"state":           string(cnt.State),
						"reason":          "expired",
					})
				s.eventStore.Append(evt)
			}
		}
	}

	if expiredCount > 0 && s.eventStore != nil {
		evt := events.NewEvent("continuation.sweep_completed").
			WithGatewayID(s.gatewayID).
			WithPayload(map[string]any{
				"expired_count": expiredCount,
				"scanned_count": len(candidates),
			})
		s.eventStore.Append(evt)
	}

	log.Printf("SWEEP continuations scanned=%d expired=%d", len(candidates), expiredCount)
}

func (s *Sweeper) SweepNow() int {
	now := time.Now().UTC()
	candidates := s.store.ListNonTerminal()
	expired := 0
	for _, cnt := range candidates {
		if cnt.ShouldExpire(now) {
			cnt.MarkExpired()
			s.store.Update(cnt)
			expired++
			if s.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationExpired).
					WithGatewayID(s.gatewayID).
					WithDecisionID(cnt.DecisionID).
					WithApprovalID(cnt.ApprovalID).
					WithAgentID(cnt.AgentID).
					WithContinuationID(cnt.ContinuationID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"state":           string(cnt.State),
						"reason":          "expired",
					})
				s.eventStore.Append(evt)
			}
		}
	}
	return expired
}

func (s *Sweeper) ReconcileOnStartup() int {
	now := time.Now().UTC()
	candidates := s.store.ListNonTerminal()
	expired := 0
	for _, cnt := range candidates {
		if cnt.ShouldExpire(now) {
			cnt.MarkExpired()
			s.store.Update(cnt)
			expired++
			if s.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationExpired).
					WithGatewayID(s.gatewayID).
					WithDecisionID(cnt.DecisionID).
					WithApprovalID(cnt.ApprovalID).
					WithAgentID(cnt.AgentID).
					WithContinuationID(cnt.ContinuationID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"state":           string(cnt.State),
						"reason":          "expired",
					})
				s.eventStore.Append(evt)
			}
		}
	}
	return expired
}