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
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			o.drainQueue()
		case <-o.stopChan:
			return
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
	if !cnt.CanExecute() {
		return
	}

	if o.registry != nil {
		if _, ok := o.registry.Get(cnt.ActionType); !ok {
			o.logf("SKIP no executor registered for action_type=%s continuation_id=%s", cnt.ActionType, cnt.ContinuationID)
			return
		}
	}

	o.logf("EXEC pickup action_type=%s continuation_id=%s resource=%q", cnt.ActionType, cnt.ContinuationID, cnt.Resource)

	cnt.State = StateReady
	o.store.Update(cnt)

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
		cnt.State = StateExecuted
		o.logf("EXEC completed=timeout action_type=%s continuation_id=%s execution_id=%s timeout_s=%d",
			cnt.ActionType, cnt.ContinuationID, exe.ExecutionID, exe.TimeoutSeconds)
	case execution.StateFailed:
		evtType = events.EventTypeExecutionFailed
		cnt.State = StateExecuted
		o.logf("EXEC completed=failed action_type=%s continuation_id=%s execution_id=%s exit_code=%d error=%q",
			cnt.ActionType, cnt.ContinuationID, exe.ExecutionID, exe.ExitCode, exe.Error)
	default:
		evtType = "execution.completed"
		cnt.State = StateExecuted
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

func (o *Orchestrator) logf(format string, args ...any) {
	if o.logger != nil {
		o.logger.Printf(format, args...)
	}
}
