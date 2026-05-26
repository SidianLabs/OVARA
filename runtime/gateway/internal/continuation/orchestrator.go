package continuation

import (
	"context"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type Orchestrator struct {
	store        Store
	execStore   execution.Store
	executor    execution.Executor
	eventStore  events.Store
	gatewayID   string
	pollInterval time.Duration
	paused      bool
	pausedMu    sync.RWMutex
	stopChan    chan struct{}
	running     bool
	runMu       sync.Mutex
	wg          sync.WaitGroup
}

func NewOrchestrator(store Store, execStore execution.Store, executor execution.Executor) *Orchestrator {
	return &Orchestrator{
		store:        store,
		execStore:    execStore,
		executor:    executor,
		pollInterval: 2 * time.Second,
		stopChan:    make(chan struct{}),
	}
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
	if o.executor != nil {
		o.executor.Execute(ctx, exe)
	}

	if o.execStore != nil {
		o.execStore.Create(exe)
	}

	var evtType string
	switch exe.State {
	case execution.StateSucceeded:
		evtType = events.EventTypeExecutionSucceeded
		cnt.MarkExecuted()
	case execution.StateTimedOut:
		evtType = events.EventTypeExecutionTimedOut
		cnt.State = StateExecuted
	case execution.StateFailed:
		evtType = events.EventTypeExecutionFailed
		cnt.State = StateExecuted
	default:
		evtType = "execution.completed"
		cnt.State = StateExecuted
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
