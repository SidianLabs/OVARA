package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type ContinuationHandler struct {
	store        continuation.Store
	execStore    execution.Store
	executor     execution.Executor
	eventStore   events.Store
	gatewayID    string
	orchestrator *continuation.Orchestrator
}

func NewContinuationHandler(store continuation.Store) *ContinuationHandler {
	return &ContinuationHandler{store: store}
}

func (h *ContinuationHandler) SetExecutionStore(store execution.Store) {
	h.execStore = store
}

func (h *ContinuationHandler) SetExecutor(exec execution.Executor) {
	h.executor = exec
}

func (h *ContinuationHandler) SetEventStore(es events.Store) {
	h.eventStore = es
}

func (h *ContinuationHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

func (h *ContinuationHandler) SetOrchestrator(orch *continuation.Orchestrator) {
	h.orchestrator = orch
}

func (h *ContinuationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/continuations", h.handleList)
	mux.HandleFunc("GET /v1/continuations/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/continuations/stats", h.handleStats)
	mux.HandleFunc("GET /v1/continuations/queue", h.handleQueue)
	mux.HandleFunc("POST /v1/continuations/sweep", h.handleSweep)
	mux.HandleFunc("POST /v1/continuations/queue/pause", h.handleQueuePause)
	mux.HandleFunc("POST /v1/continuations/queue/resume", h.handleQueueResume)
	mux.HandleFunc("POST /v1/continuations/{id}/enqueue", h.handleEnqueue)
	mux.HandleFunc("POST /v1/continuations/{id}/cancel", h.handleCancel)
	mux.HandleFunc("POST /v1/continuations/{id}/execute", h.handleExecute)
}

func (h *ContinuationHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
			if limit > 1000 {
				limit = 1000
			}
		}
	}

	stateFilter := r.URL.Query().Get("state")
	agentFilter := r.URL.Query().Get("agent_id")
	decisionFilter := r.URL.Query().Get("decision_id")

	var continuations []*continuation.Continuation

	if decisionFilter != "" {
		continuations = h.store.ListByDecision(decisionFilter)
	} else if agentFilter != "" {
		continuations = h.store.ListByAgent(agentFilter)
	} else if stateFilter != "" {
		continuations = h.store.ListByState(continuation.State(stateFilter))
	} else {
		continuations = h.store.ListAll()
	}

	if limit > 0 && len(continuations) > limit {
		continuations = continuations[len(continuations)-limit:]
	}

	enriched := make([]map[string]any, 0, len(continuations))
	for _, c := range continuations {
		m := map[string]any{
			"continuation_id": c.ContinuationID,
			"decision_id":     c.DecisionID,
			"approval_id":     c.ApprovalID,
			"agent_id":        c.AgentID,
			"action_type":     c.ActionType,
			"resource":        c.Resource,
			"state":           string(c.State),
			"created_at":      c.CreatedAt,
			"is_executable":   c.IsExecutable(),
			"time_to_expiry":   c.TimeToExpiry().Seconds(),
		}
		if c.ApprovedAt != nil {
			m["approved_at"] = c.ApprovedAt
		}
		if c.ResumedAt != nil {
			m["resumed_at"] = c.ResumedAt
		}
		if c.ExpiresAt != nil {
			m["expires_at"] = c.ExpiresAt
		}
		if c.ResolvedBy != "" {
			m["resolved_by"] = c.ResolvedBy
		}
		enriched = append(enriched, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"continuations": enriched,
		"count":          len(enriched),
		"executable":     executableCount(continuations),
	})
}

func executableCount(continuations []*continuation.Continuation) int {
	n := 0
	for _, c := range continuations {
		if c.IsExecutable() {
			n++
		}
	}
	return n
}

func (h *ContinuationHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	cnt, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "continuation not found: "+id)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cnt)
}

func (h *ContinuationHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	all := h.store.ListAll()
	counts := make(map[string]int)
	var total, executable, expired int
	for _, c := range all {
		counts[string(c.State)]++
		total++
		if c.IsExecutable() {
			executable++
		}
		if c.State == continuation.StateExpired {
			expired++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"total":        total,
		"by_state":     counts,
		"executable":   executable,
		"expired":      expired,
		"queued":       counts[string(continuation.StateQueued)],
	}
	if h.orchestrator != nil {
		resp["queue_paused"] = h.orchestrator.IsPaused()
		_, running := h.orchestrator.QueueStats()
		resp["running"] = running
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *ContinuationHandler) handleSweep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	now := time.Now().UTC()
	candidates := h.store.ListNonTerminal()
	expired := 0
	for _, cnt := range candidates {
		if cnt.ShouldExpire(now) {
			cnt.MarkExpired()
			h.store.Update(cnt)
			expired++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"expired":    expired,
		"scanned":    len(candidates),
	})
}

func (h *ContinuationHandler) handleEnqueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	cnt, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "continuation not found: "+id)
		return
	}

	if !cnt.CanEnqueue() {
		api.JSONBadRequest(w, "continuation cannot be enqueued: state="+string(cnt.State))
		return
	}

	cnt.MarkQueued()
	h.store.Update(cnt)

	if h.eventStore != nil {
		evt := events.NewEvent("continuation.enqueued").
			WithGatewayID(h.gatewayID).
			WithDecisionID(cnt.DecisionID).
			WithApprovalID(cnt.ApprovalID).
			WithAgentID(cnt.AgentID).
			WithContinuationID(cnt.ContinuationID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"state":          string(cnt.State),
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"continuation_id": cnt.ContinuationID,
		"state":          string(cnt.State),
		"message":        "continuation queued for execution",
	})
}

func (h *ContinuationHandler) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	cnt, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "continuation not found: "+id)
		return
	}

	if !cnt.CanCancel() {
		api.JSONBadRequest(w, "continuation cannot be cancelled: state="+string(cnt.State))
		return
	}

	cnt.MarkCancelled()
	h.store.Update(cnt)

	if h.eventStore != nil {
		evt := events.NewEvent("continuation.cancelled").
			WithGatewayID(h.gatewayID).
			WithDecisionID(cnt.DecisionID).
			WithApprovalID(cnt.ApprovalID).
			WithAgentID(cnt.AgentID).
			WithContinuationID(cnt.ContinuationID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"state":          string(cnt.State),
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"continuation_id": cnt.ContinuationID,
		"state":          string(cnt.State),
		"cancelled_at":   cnt.CancelledAt,
	})
}

func (h *ContinuationHandler) handleQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
			if limit > 1000 {
				limit = 1000
			}
		}
	}

	queued := h.store.ListByState(continuation.StateQueued)

	if limit > 0 && len(queued) > limit {
		queued = queued[len(queued)-limit:]
	}

	enriched := make([]map[string]any, 0, len(queued))
	for _, c := range queued {
		m := map[string]any{
			"continuation_id": c.ContinuationID,
			"decision_id":     c.DecisionID,
			"approval_id":     c.ApprovalID,
			"agent_id":        c.AgentID,
			"action_type":     c.ActionType,
			"resource":        c.Resource,
			"state":           string(c.State),
			"created_at":      c.CreatedAt,
			"approved_at":     c.ApprovedAt,
			"queued_at":      c.ApprovedAt,
		}
		enriched = append(enriched, m)
	}

	paused := false
	running := 0
	if h.orchestrator != nil {
		paused = h.orchestrator.IsPaused()
		_, running = h.orchestrator.QueueStats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"queue":           enriched,
		"count":           len(enriched),
		"queue_paused":    paused,
		"running_count":   running,
	})
}

func (h *ContinuationHandler) handleQueuePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if h.orchestrator == nil {
		api.JSONBadRequest(w, "orchestrator not configured")
		return
	}

	h.orchestrator.Pause()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"queue_paused": true,
		"message":      "execution queue paused",
	})
}

func (h *ContinuationHandler) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if h.orchestrator == nil {
		api.JSONBadRequest(w, "orchestrator not configured")
		return
	}

	h.orchestrator.Resume()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"queue_paused": false,
		"message":      "execution queue resumed",
	})
}

func (h *ContinuationHandler) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	cnt, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "continuation not found: "+id)
		return
	}

	if cnt.State == continuation.StateApproved {
		cnt.MarkReady()
	}

	if cnt.State == continuation.StateQueued {
		cnt.State = continuation.StateReady
	}

	if cnt.State == continuation.StateResumed {
		if !cnt.CanRetry() {
			api.JSONBadRequest(w, "continuation retry limit reached: retry_count="+strconv.Itoa(cnt.RetryCount)+", max_retries="+strconv.Itoa(cnt.MaxRetries))
			return
		}
		cnt.RetryCount++
	}

	if !cnt.CanExecute() {
		api.JSONBadRequest(w, "continuation not in executable state: current state="+string(cnt.State))
		return
	}

	if cnt.ActionType != "shell" {
		api.JSONBadRequest(w, "execution only supported for shell action type")
		return
	}

	timeout := 60
	if ts := r.URL.Query().Get("timeout_seconds"); ts != "" {
		if t, err := strconv.Atoi(ts); err == nil && t > 0 && t <= 300 {
			timeout = t
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
	if h.executor != nil {
		h.executor.Execute(ctx, exe)
	}

	if h.execStore != nil {
		h.execStore.Create(exe)
	}

	if h.eventStore != nil {
		var evtType string
		switch exe.State {
		case execution.StateSucceeded:
			evtType = events.EventTypeExecutionSucceeded
			cnt.MarkExecuted()
		case execution.StateTimedOut:
			evtType = events.EventTypeExecutionTimedOut
		default:
			evtType = events.EventTypeExecutionFailed
		}
		evt := events.NewEvent(evtType).
			WithGatewayID(h.gatewayID).
			WithApprovalID(cnt.ApprovalID).
			WithDecisionID(cnt.DecisionID).
			WithAgentID(cnt.AgentID).
			WithPayload(map[string]any{
				"execution_id":    exe.ExecutionID,
				"continuation_id": cnt.ContinuationID,
				"exit_code":      exe.ExitCode,
				"error":          exe.Error,
				"state":          string(exe.State),
				"retry_count":    cnt.RetryCount,
			})
		h.eventStore.Append(evt)
	}

	h.store.Update(cnt)

	resp := map[string]any{
		"execution_id":  exe.ExecutionID,
		"continuation_id": cnt.ContinuationID,
		"state":         string(exe.State),
		"exit_code":     exe.ExitCode,
		"stdout":        exe.Stdout,
		"stderr":        exe.Stderr,
		"error":         exe.Error,
		"started_at":    exe.StartedAt,
		"finished_at":   exe.FinishedAt,
		"approved_at":   cnt.ApprovedAt,
		"resolved_by":   cnt.ResolvedBy,
		"trust_score":   cnt.TrustScore,
		"trust_level":   cnt.TrustLevel,
		"action_type":   cnt.ActionType,
		"resource":      cnt.Resource,
		"retry_count":   cnt.RetryCount,
		"max_retries":   cnt.MaxRetries,
	}
	if exe.StdoutTruncated {
		resp["stdout_truncated"] = true
		resp["stdout_limit_bytes"] = exe.StdoutLimitBytes
	}
	if exe.StderrTruncated {
		resp["stderr_truncated"] = true
		resp["stderr_limit_bytes"] = exe.StderrLimitBytes
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}