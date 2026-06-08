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
	store            continuation.Store
	execStore        execution.Store
	registry         *execution.ExecutorRegistry
	eventStore       events.Store
	gatewayID        string
	orchestrator     *continuation.Orchestrator
	bulkMaxBatchCap  int
	bulkDefaultBatch int
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

func (h *ContinuationHandler) SetBulkConfig(maxCap, defaultBatch int) {
	h.bulkMaxBatchCap = maxCap
	h.bulkDefaultBatch = defaultBatch
}

func (h *ContinuationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/continuations", h.handleList)
	mux.HandleFunc("GET /v1/continuations/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/continuations/stats", h.handleStats)
	mux.HandleFunc("GET /v1/continuations/queue", h.handleQueue)
	mux.HandleFunc("POST /v1/continuations/sweep", h.handleSweep)
	mux.HandleFunc("POST /v1/continuations/recover-executing", h.handleRecoverExecuting)
	mux.HandleFunc("POST /v1/continuations/{id}/recover-executing", h.handleRecoverExecutingItem)
	mux.HandleFunc("POST /v1/continuations/queue/pause", h.handleQueuePause)
	mux.HandleFunc("POST /v1/continuations/queue/resume", h.handleQueueResume)
	mux.HandleFunc("POST /v1/continuations/{id}/enqueue", h.handleEnqueue)
	mux.HandleFunc("POST /v1/continuations/{id}/cancel", h.handleCancel)
	mux.HandleFunc("POST /v1/continuations/{id}/retry", h.handleRetry)
	mux.HandleFunc("POST /v1/continuations/{id}/execute", h.handleExecute)
	mux.HandleFunc("POST /v1/continuations/retry", h.handleBulkRetry)
	mux.HandleFunc("POST /v1/continuations/cancel", h.handleBulkCancel)
}

func (h *ContinuationHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limit := parseLimit(r, defaultListLimit, maxListLimit)

	stateFilter := r.URL.Query().Get("state")
	actionTypeFilter := r.URL.Query().Get("action_type")
	environmentFilter := r.URL.Query().Get("environment")
	retryableFilter := r.URL.Query().Get("retryable")
	sortOrder := r.URL.Query().Get("sort")
	createdBefore := r.URL.Query().Get("created_before")
	createdAfter := r.URL.Query().Get("created_after")
	rawAfter := r.URL.Query().Get("after")

	continuations := h.buildFilteredList(r, stateFilter, actionTypeFilter, environmentFilter, retryableFilter, createdBefore, createdAfter, sortOrder)

	ascending := sortAscending(sortOrder)

	result := buildListedItems(continuations, limit, rawAfter, SortSpec[continuation.Continuation]{
		Ascending:    ascending,
		GetTimestamp: func(c continuation.Continuation) time.Time { return c.CreatedAt },
		GetID:        func(c continuation.Continuation) string { return c.ContinuationID },
	})

	if result.Items == nil {
		result.Items = []*continuation.Continuation{}
	}

	var executableCount, retryableCount int
	for _, c := range result.Items {
		if c.IsExecutable() {
			executableCount++
		}
		if c.CanRetry() {
			retryableCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"continuations": result.Items,
		"count":          result.Count,
		"executable":    executableCount,
		"retryable":     retryableCount,
	}
	if result.NextCursor != "" {
		resp["next_cursor"] = result.NextCursor
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

	cnt, ok := h.store.CancelForOperation(id)
	if !ok {
		existing, found := h.store.Get(id)
		if !found {
			api.JSONNotFound(w, "continuation not found: "+id)
			return
		}
		api.JSONConflict(w, "cannot cancel continuation: invalid state (current="+string(existing.State)+")")
		return
	}

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

	cnt, ok := h.store.RetryForExecution(id)
	if !ok {
		cnt, found := h.store.Get(id)
		if !found {
			api.JSONNotFound(w, "continuation not found: "+id)
			return
		}
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

	cnt, claimed := h.store.ClaimForExecution(id)
	if !claimed {
		cnt, found := h.store.Get(id)
		if !found {
			api.JSONNotFound(w, "continuation not found: "+id)
			return
		}
		if cnt.State == continuation.StateExecuting {
			api.JSONConflict(w, "continuation is already claimed for execution")
			return
		}
		api.JSONConflict(w, "continuation not in executable state: current state="+string(cnt.State))
		return
	}

	if h.registry != nil {
		if _, ok := h.registry.Get(cnt.ActionType); !ok {
			cnt.MarkRequeue()
			h.store.Update(cnt)
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

	switch exe.State {
	case execution.StateSucceeded:
		cnt.MarkExecuted()
	case execution.StateTimedOut, execution.StateFailed:
		cnt.MarkExecutionFailed()
	default:
		cnt.MarkExecutionFailed()
	}

	if h.eventStore != nil {
		var evtType string
		switch exe.State {
		case execution.StateSucceeded:
			evtType = events.EventTypeExecutionSucceeded
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

type recoverExecutingResult struct {
	ContinuationID string `json:"continuation_id"`
	ActionType     string `json:"action_type"`
	AgeSeconds     int64  `json:"age_seconds"`
	State          string `json:"state"`
}

type recoverExecutingResponse struct {
	Scanned    int                       `json:"scanned"`
	Recovered  int                       `json:"recovered"`
	Skipped    int                       `json:"skipped"`
	DryRun     bool                      `json:"dry_run"`
	Items      []recoverExecutingResult  `json:"items,omitempty"`
}

func (h *ContinuationHandler) handleRecoverExecuting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"

	var olderThanMins int
	if ot := r.URL.Query().Get("older_than_minutes"); ot != "" {
		if t, err := strconv.Atoi(ot); err == nil && t > 0 {
			olderThanMins = t
		}
	}

	ids := h.store.ListExecutingIDs()
	scanned := len(ids)
	items := make([]recoverExecutingResult, 0, scanned)
	skipped := 0
	recovered := 0
	now := time.Now().UTC()
	ageThreshold := time.Duration(olderThanMins) * time.Minute

	for _, id := range ids {
		snap, ok := h.store.Get(id)
		if !ok {
			skipped++
			continue
		}

		ageSeconds := int64(0)
		if !snap.CreatedAt.IsZero() {
			ageSeconds = int64(now.Sub(snap.CreatedAt).Seconds())
		}

		if olderThanMins > 0 {
			itemAge := time.Duration(ageSeconds) * time.Second
			if itemAge <= ageThreshold {
				skipped++
				continue
			}
		}

		if dryRun {
			items = append(items, recoverExecutingResult{
				ContinuationID: snap.ContinuationID,
				ActionType:     snap.ActionType,
				AgeSeconds:     ageSeconds,
				State:          string(snap.State),
			})
			continue
		}

		rec, ok := h.store.RecoverFromExecuting(id)
		if !ok {
			skipped++
			continue
		}
		recovered++

		items = append(items, recoverExecutingResult{
			ContinuationID: rec.ContinuationID,
			ActionType:     rec.ActionType,
			AgeSeconds:     ageSeconds,
			State:          string(rec.State),
		})

		if h.eventStore != nil {
			evt := events.NewEvent("continuation.recovered_executing").
				WithGatewayID(h.gatewayID).
				WithDecisionID(rec.DecisionID).
				WithApprovalID(rec.ApprovalID).
				WithAgentID(rec.AgentID).
				WithContinuationID(rec.ContinuationID).
				WithPayload(map[string]any{
					"continuation_id":  rec.ContinuationID,
					"state":           string(rec.State),
					"trigger":         "operator_recover_executing",
					"older_than_mins":  olderThanMins,
				})
			h.eventStore.Append(evt)
		}
	}

	if !dryRun && h.eventStore != nil {
		evt := events.NewEvent("continuation.recovered_executing").
			WithGatewayID(h.gatewayID).
			WithPayload(map[string]any{
				"action":     "recover_executing",
				"dry_run":    false,
				"scanned":    scanned,
				"recovered":  recovered,
				"skipped":    skipped,
				"continuation_ids": func() []string {
					ids := make([]string, 0, len(items))
					for _, it := range items {
						ids = append(ids, it.ContinuationID)
					}
					return ids
				}(),
			})
		h.eventStore.Append(evt)
	}

	log.Printf("RECOVER executing dry_run=%t scanned=%d recovered=%d skipped=%d",
		dryRun, scanned, recovered, skipped)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recoverExecutingResponse{
		Scanned:   scanned,
		Recovered: recovered,
		Skipped:   skipped,
		DryRun:    dryRun,
		Items:     items,
	})
}

func (h *ContinuationHandler) handleRecoverExecutingItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	cnt, ok := h.store.RecoverFromExecuting(id)
	if !ok {
		existing, found := h.store.Get(id)
		if !found {
			api.JSONNotFound(w, "continuation not found: "+id)
			return
		}
		api.JSONConflict(w, "cannot recover continuation: invalid state (current="+string(existing.State)+", required=executing)")
		return
	}

	log.Printf("RECOVER executing item continuation_id=%s decision_id=%s action_type=%s",
		cnt.ContinuationID, cnt.DecisionID, cnt.ActionType)

	if h.eventStore != nil {
		evt := events.NewEvent("continuation.recovered_executing").
			WithGatewayID(h.gatewayID).
			WithDecisionID(cnt.DecisionID).
			WithApprovalID(cnt.ApprovalID).
			WithAgentID(cnt.AgentID).
			WithContinuationID(cnt.ContinuationID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"state":          string(cnt.State),
				"trigger":        "operator_recover_executing_item",
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"continuation_id": cnt.ContinuationID,
		"state":          string(cnt.State),
		"message":        "continuation recovered from executing for retry",
	})
}

type bulkRetryResult struct {
	ContinuationID string `json:"continuation_id"`
	DecisionID     string `json:"decision_id"`
	State          string `json:"state"`
	RetryCount     int    `json:"retry_count,omitempty"`
	MaxRetries     int    `json:"max_retries,omitempty"`
}

type bulkSkip struct {
	ContinuationID string `json:"continuation_id"`
	DecisionID     string `json:"decision_id"`
	State          string `json:"state"`
	Reason         string `json:"reason"`
}

type bulkRetryResponse struct {
	Matched  int              `json:"matched"`
	Acted    int              `json:"acted"`
	Skipped  int              `json:"skipped"`
	DryRun   bool             `json:"dry_run"`
	Items    []bulkRetryResult `json:"acted_items,omitempty"`
	SkippedItems []bulkSkip   `json:"skipped_items,omitempty"`
}

type bulkCancelResult struct {
	ContinuationID string `json:"continuation_id"`
	DecisionID     string `json:"decision_id"`
	ActionType     string `json:"action_type"`
	State          string `json:"state"`
}

type bulkCancelResponse struct {
	Matched     int                 `json:"matched"`
	Acted       int                 `json:"acted"`
	Skipped     int                 `json:"skipped"`
	DryRun      bool                `json:"dry_run"`
	Items       []bulkCancelResult  `json:"acted_items,omitempty"`
	SkippedItems []bulkSkip        `json:"skipped_items,omitempty"`
}

func (h *ContinuationHandler) handleBulkRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"
	confirm := r.URL.Query().Get("confirm") == "true"

	maxBatch := h.bulkMaxBatchCap
	if maxBatch <= 0 {
		maxBatch = 100
	}
	defaultBatch := h.bulkDefaultBatch
	if defaultBatch <= 0 {
		defaultBatch = 20
	}

	batchLimit := parseLimit(r, defaultBatch, maxBatch)

	filter := r.URL.Query()
	stateFilter := filter.Get("state")
	actionTypeFilter := filter.Get("action_type")
	environmentFilter := filter.Get("environment")
	retryableFilter := filter.Get("retryable")
	createdBefore := filter.Get("created_before")
	createdAfter := filter.Get("created_after")
	sortOrder := filter.Get("sort")

	continuations := h.buildFilteredList(r, stateFilter, actionTypeFilter, environmentFilter, retryableFilter, createdBefore, createdAfter, sortOrder)

	matched := len(continuations)
	if matched == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bulkRetryResponse{
			Matched:  0,
			Acted:    0,
			Skipped:  0,
			DryRun:   dryRun,
		})
		return
	}

	if matched > batchLimit && !confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "batch size exceeds cap",
			"matched":        matched,
			"batch_limit":    batchLimit,
			"max_batch_cap":  maxBatch,
			"message":        "re-run with confirm=true to proceed anyway",
		})
		return
	}

	var acted []bulkRetryResult
	var skippedItems []bulkSkip

	for _, cnt := range continuations {
		if !cnt.CanRetry() {
			reason := h.skipReasonForRetry(cnt)
			skippedItems = append(skippedItems, bulkSkip{
				ContinuationID: cnt.ContinuationID,
				DecisionID:     cnt.DecisionID,
				State:          string(cnt.State),
				Reason:         reason,
			})
			continue
		}
		acted = append(acted, bulkRetryResult{
			ContinuationID: cnt.ContinuationID,
			DecisionID:     cnt.DecisionID,
			State:          string(cnt.State),
			RetryCount:     cnt.RetryCount,
			MaxRetries:     cnt.MaxRetries,
		})
	}

	if dryRun {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bulkRetryResponse{
			Matched:      matched,
			Acted:        len(acted),
			Skipped:      len(skippedItems),
			DryRun:       true,
			Items:        acted,
			SkippedItems: skippedItems,
		})
		return
	}

	for _, item := range acted {
		cnt, ok := h.store.RetryForExecution(item.ContinuationID)
		if !ok {
			continue
		}

		if h.eventStore != nil {
			evt := events.NewEvent(events.EventTypeBatchRetryExecuted).
				WithGatewayID(h.gatewayID).
				WithDecisionID(cnt.DecisionID).
				WithApprovalID(cnt.ApprovalID).
				WithAgentID(cnt.AgentID).
				WithContinuationID(cnt.ContinuationID).
				WithPayload(map[string]any{
					"continuation_id": cnt.ContinuationID,
					"state":          string(cnt.State),
					"retry_count":    cnt.RetryCount,
					"max_retries":    cnt.MaxRetries,
				})
			h.eventStore.Append(evt)
		}
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeBatchRetryExecuted).
			WithGatewayID(h.gatewayID).
			WithPayload(map[string]any{
				"action":         "bulk_retry",
				"dry_run":        false,
				"total_matched":  matched,
				"total_acted":    len(acted),
				"total_skipped":  len(skippedItems),
				"continuation_ids": func() []string {
					ids := make([]string, len(acted))
					for i, a := range acted {
						ids[i] = a.ContinuationID
					}
					return ids
				}(),
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bulkRetryResponse{
		Matched:      matched,
		Acted:        len(acted),
		Skipped:      len(skippedItems),
		DryRun:       false,
		Items:        acted,
		SkippedItems: skippedItems,
	})
}

func (h *ContinuationHandler) handleBulkCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"
	confirm := r.URL.Query().Get("confirm") == "true"

	maxBatch := h.bulkMaxBatchCap
	if maxBatch <= 0 {
		maxBatch = 100
	}
	defaultBatch := h.bulkDefaultBatch
	if defaultBatch <= 0 {
		defaultBatch = 20
	}

	batchLimit := parseLimit(r, defaultBatch, maxBatch)

	filter := r.URL.Query()
	stateFilter := filter.Get("state")
	actionTypeFilter := filter.Get("action_type")
	environmentFilter := filter.Get("environment")
	createdBefore := filter.Get("created_before")
	createdAfter := filter.Get("created_after")
	sortOrder := filter.Get("sort")

	continuations := h.buildFilteredList(r, stateFilter, actionTypeFilter, environmentFilter, "", createdBefore, createdAfter, sortOrder)

	matched := len(continuations)
	if matched == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bulkCancelResponse{
			Matched:  0,
			Acted:    0,
			Skipped:  0,
			DryRun:   dryRun,
		})
		return
	}

	if matched > batchLimit && !confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "batch size exceeds cap",
			"matched":        matched,
			"batch_limit":    batchLimit,
			"max_batch_cap":  maxBatch,
			"message":        "re-run with confirm=true to proceed anyway",
		})
		return
	}

	var acted []bulkCancelResult
	var skippedItems []bulkSkip

	for _, cnt := range continuations {
		if !cnt.CanCancel() {
			reason := "cannot cancel: state " + string(cnt.State) + " (only queued/ready/resumed can be cancelled)"
			skippedItems = append(skippedItems, bulkSkip{
				ContinuationID: cnt.ContinuationID,
				DecisionID:     cnt.DecisionID,
				State:          string(cnt.State),
				Reason:         reason,
			})
			continue
		}
		acted = append(acted, bulkCancelResult{
			ContinuationID: cnt.ContinuationID,
			DecisionID:     cnt.DecisionID,
			ActionType:     cnt.ActionType,
			State:          string(cnt.State),
		})
	}

	if dryRun {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bulkCancelResponse{
			Matched:      matched,
			Acted:        len(acted),
			Skipped:      len(skippedItems),
			DryRun:       true,
			Items:        acted,
			SkippedItems: skippedItems,
		})
		return
	}

	for _, item := range acted {
		cnt, ok := h.store.CancelForOperation(item.ContinuationID)
		if !ok {
			continue
		}

		if h.eventStore != nil {
			evt := events.NewEvent(events.EventTypeBatchCancelExecuted).
				WithGatewayID(h.gatewayID).
				WithDecisionID(cnt.DecisionID).
				WithApprovalID(cnt.ApprovalID).
				WithAgentID(cnt.AgentID).
				WithContinuationID(cnt.ContinuationID).
				WithPayload(map[string]any{
					"continuation_id": cnt.ContinuationID,
					"state":           string(cnt.State),
				})
			h.eventStore.Append(evt)
		}
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeBatchCancelExecuted).
			WithGatewayID(h.gatewayID).
			WithPayload(map[string]any{
				"action":           "bulk_cancel",
				"dry_run":          false,
				"total_matched":    matched,
				"total_acted":      len(acted),
				"total_skipped":    len(skippedItems),
				"continuation_ids": func() []string {
					ids := make([]string, len(acted))
					for i, a := range acted {
						ids[i] = a.ContinuationID
					}
					return ids
				}(),
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bulkCancelResponse{
		Matched:      matched,
		Acted:        len(acted),
		Skipped:      len(skippedItems),
		DryRun:       false,
		Items:        acted,
		SkippedItems: skippedItems,
	})
}

func (h *ContinuationHandler) buildFilteredList(r *http.Request, stateFilter, actionTypeFilter, environmentFilter, retryableFilter, createdBefore, createdAfter, sortOrder string) []*continuation.Continuation {
	filter := r.URL.Query()
	decisionFilter := filter.Get("decision_id")
	agentFilter := filter.Get("agent_id")
	approvalIDFilter := filter.Get("approval_id")

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

	return continuations
}

func (h *ContinuationHandler) skipReasonForRetry(cnt *continuation.Continuation) string {
	info := cnt.RetryInfo()
	return info.Reason
}
