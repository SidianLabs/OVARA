package continuation

import (
	"context"
	"log"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type Orchestrator struct {
	store        Store
	execStore   execution.Store
	registry    *execution.ExecutorRegistry
	eventStore  events.Store
	gatewayID   string
	pollInterval time.Duration
	paused      bool
	pausedMu    sync.RWMutex
	stopChan    chan struct{}
	running     bool
	runMu       sync.Mutex
	wg          sync.WaitGroup
	logger      *log.Logger

	stuckSweepInterval     time.Duration
	stuckRecoveryThreshold time.Duration
}

func NewOrchestrator(store Store, execStore execution.Store, registry *execution.ExecutorRegistry) *Orchestrator {
	return &Orchestrator{
		store:        store,
		execStore:    execStore,
		registry:     registry,
		pollInterval: 2 * time.Second,
		stopChan:    make(chan struct{}),
		logger:      log.Default(),
	}
}

func (o *Orchestrator) SetRegistry(reg *execution.ExecutorRegistry) {
	o.registry = reg
}

func (o *Orchestrator) SetEventStore(es events.Store) {
	o.eventStore = es
}

func (o *Orchestrator) SetGatewayID(id string) {
	o.gatewayID = id
}

func (o *Orchestrator) Start() {
	o.runMu.Lock()
	defer o.runMu.Unlock()
	if o.running {
		return
	}
	o.sweepStuckExecuting()
	o.running = true
	o.wg.Add(1)
	go o.run()
}

func (o *Orchestrator) Stop() {
	o.runMu.Lock()
	defer o.runMu.Unlock()
	if !o.running {
		return
	}
	close(o.stopChan)
	o.wg.Wait()
	o.running = false
}

func (o *Orchestrator) IsRunning() bool {
	o.runMu.Lock()
	defer o.runMu.Unlock()
	return o.running
}

func (o *Orchestrator) IsPaused() bool {
	o.pausedMu.RLock()
	defer o.pausedMu.RUnlock()
	return o.paused
}

func (o *Orchestrator) Pause() {
	o.pausedMu.Lock()
	defer o.pausedMu.Unlock()
	o.paused = true
}

func (o *Orchestrator) Resume() {
	o.pausedMu.Lock()
	defer o.pausedMu.Unlock()
	o.paused = false
}

func (o *Orchestrator) run() {
	defer o.wg.Done()
	pollTicker := time.NewTicker(o.pollInterval)
	defer pollTicker.Stop()

	var stuckTicker *time.Ticker
	if o.stuckSweepInterval > 0 {
		stuckTicker = time.NewTicker(o.stuckSweepInterval)
		defer stuckTicker.Stop()
	}

	for {
		select {
		case <-pollTicker.C:
			o.drainQueue()
		case <-o.stopChan:
			return
		default:
			if stuckTicker != nil {
				select {
				case <-stuckTicker.C:
					o.sweepStuckExecutingThreshold()
				case <-o.stopChan:
					return
				case <-pollTicker.C:
					o.drainQueue()
				}
			} else {
				select {
				case <-pollTicker.C:
					o.drainQueue()
				case <-o.stopChan:
					return
				}
			}
		}
	}
}

func (o *Orchestrator) drainQueue() {
	o.pausedMu.RLock()
	if o.paused {
		o.pausedMu.RUnlock()
		return
	}
	o.pausedMu.RUnlock()

	candidates := o.store.ListByState(StateQueued)
	for _, cnt := range candidates {
		go o.executeOne(cnt)
	}
}

func (o *Orchestrator) executeOne(cnt *Continuation) {
	if cnt.LastSkippedAt != nil && !cnt.LastSkippedAt.IsZero() {
		if time.Since(*cnt.LastSkippedAt) < o.pollInterval {
			return
		}
	}
	cnt.LastSkippedAt = nil

	c, claimed := o.store.ClaimForExecution(cnt.ContinuationID)
	if !claimed {
		return
	}
	cnt = c

	if o.registry != nil {
		if _, ok := o.registry.Get(cnt.ActionType); !ok {
			// Requeue via the disciplined transition helper so the
			// claimed StateExecuting → StateQueued transition is
			// observable and consistent with other state changes.
			now := time.Now().UTC()
			cnt.LastSkippedAt = &now
			cnt.MarkRequeue()
			o.store.Update(cnt)
			o.logf("SKIP no executor registered for action_type=%s continuation_id=%s", cnt.ActionType, cnt.ContinuationID)
			return
		}
	}

	o.logf("EXEC pickup action_type=%s continuation_id=%s resource=%q", cnt.ActionType, cnt.ContinuationID, cnt.Resource)

	timeout := 60
	if cnt.ExpiresAt != nil {
		remaining := time.Until(*cnt.ExpiresAt)
		if remaining > 0 && remaining < time.Duration(timeout)*time.Second {
			timeout = int(remaining.Seconds())
			if timeout < 5 {
				timeout = 5
			}
		}
	}

	exe := execution.NewExecution(
		cnt.ContinuationID,
		cnt.DecisionID,
		cnt.ApprovalID,
		cnt.AgentID,
		cnt.ActionType,
		cnt.Resource,
		timeout,
	)

	ctx := context.Background()
	if o.registry != nil {
		if exec, ok := o.registry.Get(cnt.ActionType); ok {
			exec.Execute(ctx, exe)
		}
	}

	if o.execStore != nil {
		o.execStore.Create(exe)
	}

	var evtType string
	switch exe.State {
	case execution.StateSucceeded:
		evtType = events.EventTypeExecutionSucceeded
		cnt.MarkExecuted()
		o.logf("EXEC completed=success action_type=%s continuation_id=%s execution_id=%s exit_code=%d",
			cnt.ActionType, cnt.ContinuationID, exe.ExecutionID, exe.ExitCode)
	case execution.StateTimedOut:
		evtType = events.EventTypeExecutionTimedOut
		cnt.MarkExecutionFailed()
		o.logf("EXEC completed=timeout action_type=%s continuation_id=%s execution_id=%s timeout_s=%d",
			cnt.ActionType, cnt.ContinuationID, exe.ExecutionID, exe.TimeoutSeconds)
	case execution.StateFailed:
		evtType = events.EventTypeExecutionFailed
		cnt.MarkExecutionFailed()
		o.logf("EXEC completed=failed action_type=%s continuation_id=%s execution_id=%s exit_code=%d error=%q",
			cnt.ActionType, cnt.ContinuationID, exe.ExecutionID, exe.ExitCode, exe.Error)
	default:
		evtType = "execution.completed"
		cnt.MarkExecutionFailed()
		o.logf("EXEC completed=%s action_type=%s continuation_id=%s execution_id=%s",
			exe.State, cnt.ActionType, cnt.ContinuationID, exe.ExecutionID)
	}

	o.store.Update(cnt)

	if o.eventStore != nil {
		evt := events.NewEvent(evtType).
			WithGatewayID(o.gatewayID).
			WithApprovalID(cnt.ApprovalID).
			WithDecisionID(cnt.DecisionID).
			WithAgentID(cnt.AgentID).
			WithContinuationID(cnt.ContinuationID).
			WithPayload(map[string]any{
				"execution_id":  exe.ExecutionID,
				"continuation_id": cnt.ContinuationID,
				"exit_code":    exe.ExitCode,
				"error":        exe.Error,
				"state":        string(exe.State),
				"retry_count":  cnt.RetryCount,
			})
		o.eventStore.Append(evt)
	}
}

func (o *Orchestrator) QueueStats() (queued, running int) {
	queued = len(o.store.ListByState(StateQueued))
	if o.execStore != nil {
		running = len(o.execStore.ListByState(execution.StateRunning))
	}
	return
}

func (o *Orchestrator) SetLogger(l *log.Logger) {
	o.logger = l
}

func (o *Orchestrator) SetStuckExecutingSweep(intervalSec int, recoveryThresholdMin int) {
	if intervalSec <= 0 {
		o.stuckSweepInterval = 0
		return
	}
	o.stuckSweepInterval = time.Duration(intervalSec) * time.Second
	if recoveryThresholdMin <= 0 {
		recoveryThresholdMin = 30
	}
	o.stuckRecoveryThreshold = time.Duration(recoveryThresholdMin) * time.Minute
}

func (o *Orchestrator) logf(format string, args ...any) {
	if o.logger != nil {
		o.logger.Printf(format, args...)
	}
}

// RecoverAllExecuting transitions every continuation currently in
// StateExecuting back to StateExecuted so they become retryable. Returns the
// number of items recovered. Used by the operator recovery endpoint to clear
// stuck executions without restarting the gateway.
func (o *Orchestrator) RecoverAllExecuting() int {
	ids := o.store.ListExecutingIDs()
	recovered := 0
	for _, id := range ids {
		rec, ok := o.store.RecoverFromExecuting(id)
		if !ok {
			continue
		}
		recovered++
		o.logf("RECOVER executing continuation_id=%s action_type=%s — marked executed for retry",
			rec.ContinuationID, rec.ActionType)
	}
	return recovered
}

// ExecutingCount returns the number of continuations currently in
// StateExecuting. Used by runtime status to expose in-flight claim depth.
func (o *Orchestrator) ExecutingCount() int {
	return len(o.store.ListExecutingIDs())
}

// OldestExecutingAt returns the CreatedAt timestamp of the oldest continuation
// currently in StateExecuting, or the zero time if none are executing. Used
// by runtime status to surface how long the longest-running claim has been
// in flight.
func (o *Orchestrator) OldestExecutingAt() time.Time {
	var oldest time.Time
	for _, c := range o.store.ListByState(StateExecuting) {
		if c.CreatedAt.IsZero() {
			continue
		}
		if oldest.IsZero() || c.CreatedAt.Before(oldest) {
			oldest = c.CreatedAt
		}
	}
	return oldest
}

// sweepStuckExecuting recovers continuations orphaned in StateExecuting after
// a gateway crash or restart. Any continuation left in executing was claimed
// by a previous process that is no longer running, so we transition them to
// StateExecuted so they become retryable. Uses the atomic RecoverFromExecuting
// store method so each transition is independent and any items that have
// already moved on (e.g. concurrent live executor finishing) are skipped.
func (o *Orchestrator) sweepStuckExecuting() {
	ids := o.store.ListExecutingIDs()
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		rec, ok := o.store.RecoverFromExecuting(id)
		if !ok {
			continue
		}
		o.logf("RECOVER stuck-executing continuation_id=%s action_type=%s — marked executed for retry",
			rec.ContinuationID, rec.ActionType)
	}
}

// sweepStuckExecutingThreshold recovers continuations in StateExecuting that
// have been stuck for longer than the configured recovery threshold. Unlike
// the startup sweep (which unconditionally recovers all stuck items), this
// periodic sweep is age-gated to avoid recovering items that are still young
// (e.g. a slow but valid execution). Only recovers items older than
// stuckRecoveryThreshold. Uses the atomic RecoverFromExecuting store method
// so each transition is independent.
func (o *Orchestrator) sweepStuckExecutingThreshold() {
	if o.stuckRecoveryThreshold <= 0 {
		return
	}
	ids := o.store.ListExecutingIDs()
	if len(ids) == 0 {
		return
	}
	now := time.Now().UTC()
	recovered := 0
	for _, id := range ids {
		snap, ok := o.store.Get(id)
		if !ok {
			continue
		}
		if snap.CreatedAt.IsZero() {
			continue
		}
		age := now.Sub(snap.CreatedAt)
		if age < o.stuckRecoveryThreshold {
			continue
		}
		rec, ok := o.store.RecoverFromExecuting(id)
		if !ok {
			continue
		}
		recovered++
		o.logf("RECOVER stale-executing continuation_id=%s action_type=%s age=%s — marked executed for retry",
			rec.ContinuationID, rec.ActionType, age.Round(time.Second))
	}
	if recovered > 0 {
		o.logf("RECOVER stale-executing sweep completed recovered=%d threshold=%s",
			recovered, o.stuckRecoveryThreshold.Round(time.Minute))
	}
}
