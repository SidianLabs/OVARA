package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
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
	registry     *execution.ExecutorRegistry
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

func (h *ContinuationHandler) SetExecutorRegistry(reg *execution.ExecutorRegistry) {
	h.registry = reg
}

func (h *ContinuationHandler) SetExecutor(exec execution.Executor) {
	if h.registry == nil {
		h.registry = execution.NewExecutorRegistry()
	}
	h.registry.Register("shell", exec)
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
	mux.HandleFunc("POST /v1/continuations/{id}/retry", h.handleRetry)
	mux.HandleFunc("POST /v1/continuations/{id}/execute", h.handleExecute)
}

func (h *ContinuationHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limit := parseLimit(r, defaultListLimit, maxListLimit)

	stateFilter := r.URL.Query().Get("state")
	agentFilter := r.URL.Query().Get("agent_id")
	decisionFilter := r.URL.Query().Get("decision_id")
	actionTypeFilter := r.URL.Query().Get("action_type")
	environmentFilter := r.URL.Query().Get("environment")
	approvalIDFilter := r.URL.Query().Get("approval_id")
	retryableFilter := r.URL.Query().Get("retryable")
	sortOrder := r.URL.Query().Get("sort")
	createdBefore := r.URL.Query().Get("created_before")
	createdAfter := r.URL.Query().Get("created_after")

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

	if approvalIDFilter != "" {
		filtered := make([]*continuation.Continuation, 0, len(continuations))
		for _, c := range continuations {
			if c.ApprovalID == approvalIDFilter {
				filtered = append(filtered, c)
			}
		}
		continuations = filtered
	}

	if environmentFilter != "" {
		filtered := make([]*continuation.Continuation, 0, len(continuations))
		for _, c := range continuations {
			if c.Environment == environmentFilter {
				filtered = append(filtered, c)
			}
		}
		continuations = filtered
	}

	if actionTypeFilter != "" {
		filtered := make([]*continuation.Continuation, 0, len(continuations))
		for _, c := range continuations {
			if c.ActionType == actionTypeFilter {
				filtered = append(filtered, c)
			}
		}
		continuations = filtered
	}

	if retryableFilter == "true" || retryableFilter == "false" {
		wantRetryable := retryableFilter == "true"
		filtered := make([]*continuation.Continuation, 0, len(continuations))
		for _, c := range continuations {
			if c.CanRetry() == wantRetryable {
				filtered = append(filtered, c)
			}
		}
		continuations = filtered
	}

	if createdBefore != "" {
		if t, err := time.Parse(time.RFC3339, createdBefore); err == nil {
			filtered := make([]*continuation.Continuation, 0, len(continuations))
			for _, c := range continuations {
				if c.CreatedAt.Before(t) || c.CreatedAt.Equal(t) {
					filtered = append(filtered, c)
				}
			}
			continuations = filtered
		}
	}

	if createdAfter != "" {
		if t, err := time.Parse(time.RFC3339, createdAfter); err == nil {
			filtered := make([]*continuation.Continuation, 0, len(continuations))
			for _, c := range continuations {
				if c.CreatedAt.After(t) {
					filtered = append(filtered, c)
				}
			}
			continuations = filtered
		}
	}

	// Sort after all filters, before limiting and cursor filtering. The
	// default order is newest first (deterministic) so the limit window
	// returns the most recent items reproducibly; sort=oldest reverses it.
	// ContinuationID is the stable tiebreaker for equal timestamps.
	ascending := sortAscending(sortOrder)
	sort.Slice(continuations, func(i, j int) bool {
		a, b := continuations[i], continuations[j]
		if a.CreatedAt.Equal(b.CreatedAt) {
			if ascending {
				return a.ContinuationID < b.ContinuationID
			}
			return a.ContinuationID > b.ContinuationID
		}
		if ascending {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return b.CreatedAt.Before(a.CreatedAt)
	})

	// Apply cursor-based pagination after sorting, before limit.
	// This ensures the cursor skips the correct position in the full
	// sorted set, not just within the limited window.
	var nextCursor string
	if rawAfter := r.URL.Query().Get("after"); rawAfter != "" {
		if cur, ok := decodeCursor(rawAfter); ok {
			continuations = cursorFilter(continuations, cur, ascending,
				func(c *continuation.Continuation) time.Time { return c.CreatedAt },
				func(c *continuation.Continuation) string { return c.ContinuationID },
			)
		}
	}

	if continuations == nil {
		continuations = []*continuation.Continuation{}
	}

	var executableCount int
	for _, c := range continuations {
		if c.IsExecutable() {
			executableCount++
		}
	}

	retryableCount := 0
	for _, c := range continuations {
		if c.CanRetry() {
			retryableCount++
		}
	}

	if limit > 0 && len(continuations) > limit {
		// Capture cursor from the item that falls just outside the limit
		// window — that becomes the next_cursor value for the caller.
		lastItem := continuations[limit-1]
		nextCursor = encodeCursor(Cursor{
			Timestamp: lastItem.CreatedAt,
			ID:        lastItem.ContinuationID,
		})
		continuations = continuations[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"continuations": continuations,
		"count":         len(continuations),
		"executable":    executableCount,
		"retryable":    retryableCount,
	}
	if nextCursor != "" {
		resp["next_cursor"] = nextCursor
	}
	json.NewEncoder(w).Encode(resp)
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

	retryInfo := cnt.RetryInfo()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"continuation": cnt,
		"retry":       retryInfo,
	})
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
		api.JSONConflict(w, "cannot enqueue continuation: invalid state (current="+string(cnt.State)+", required=approved)")
		return
	}

	cnt.MarkQueued()
	h.store.Update(cnt)

	log.Printf("QUEUE enqueue continuation_id=%s decision_id=%s action_type=%s agent_id=%s state=%s",
		cnt.ContinuationID, cnt.DecisionID, cnt.ActionType, cnt.AgentID, cnt.State)

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
		api.JSONConflict(w, "cannot cancel continuation: invalid state (current="+string(cnt.State)+")")
		return
	}

	cnt.MarkCancelled()
	h.store.Update(cnt)

	log.Printf("QUEUE cancel continuation_id=%s decision_id=%s action_type=%s agent_id=%s state=%s",
		cnt.ContinuationID, cnt.DecisionID, cnt.ActionType, cnt.AgentID, cnt.State)

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

func (h *ContinuationHandler) handleRetry(w http.ResponseWriter, r *http.Request) {
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

	if !cnt.Retry() {
		if cnt.State != continuation.StateExecuted && cnt.State != continuation.StateResumed {
			api.JSONConflict(w, "cannot retry continuation: invalid state (current="+string(cnt.State)+", required=executed)")
			return
		}
		if cnt.MaxRetries <= 0 {
			api.JSONConflict(w, "cannot retry continuation: max_retries is 0")
			return
		}
		api.JSONConflict(w, "cannot retry continuation: retry limit reached (retry_count="+strconv.Itoa(cnt.RetryCount)+", max_retries="+strconv.Itoa(cnt.MaxRetries)+")")
		return
	}

	h.store.Update(cnt)

	log.Printf("QUEUE retry continuation_id=%s decision_id=%s action_type=%s agent_id=%s retry_count=%d",
		cnt.ContinuationID, cnt.DecisionID, cnt.ActionType, cnt.AgentID, cnt.RetryCount)

	if h.eventStore != nil {
		evt := events.NewEvent("continuation.retried").
			WithGatewayID(h.gatewayID).
			WithDecisionID(cnt.DecisionID).
			WithApprovalID(cnt.ApprovalID).
			WithAgentID(cnt.AgentID).
			WithContinuationID(cnt.ContinuationID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"state":          string(cnt.State),
				"retry_count":    cnt.RetryCount,
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"continuation_id": cnt.ContinuationID,
		"state":          string(cnt.State),
		"retry_count":    cnt.RetryCount,
		"max_retries":   cnt.MaxRetries,
		"message":       "continuation marked for retry",
	})
}

func (h *ContinuationHandler) handleQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limit := parseLimit(r, defaultListLimit, maxListLimit)

	queued := h.store.ListByState(continuation.StateQueued)

	// A queue is naturally FIFO: order by when each item was queued (oldest
	// first), falling back to creation time, with ContinuationID as a stable
	// tiebreaker. This makes the listing deterministic instead of relying on
	// map iteration order.
	sort.Slice(queued, func(i, j int) bool {
		a, b := queued[i], queued[j]
		at, bt := a.CreatedAt, b.CreatedAt
		if a.QueuedAt != nil {
			at = *a.QueuedAt
		}
		if b.QueuedAt != nil {
			bt = *b.QueuedAt
		}
		if at.Equal(bt) {
			return a.ContinuationID < b.ContinuationID
		}
		return at.Before(bt)
	})

	if limit > 0 && len(queued) > limit {
		queued = queued[:limit]
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
			"queued_at":      c.QueuedAt,
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

	log.Printf("QUEUE pause")

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

	log.Printf("QUEUE resume")

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
		api.JSONConflict(w, "continuation not in executable state: current state="+string(cnt.State))
		return
	}

	if h.registry != nil {
		if _, ok := h.registry.Get(cnt.ActionType); !ok {
			api.JSONBadRequest(w, "no executor registered for action type: "+cnt.ActionType)
			return
		}
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
	if h.registry != nil {
		if exec, ok := h.registry.Get(cnt.ActionType); ok {
			exec.Execute(ctx, exe)
		}
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