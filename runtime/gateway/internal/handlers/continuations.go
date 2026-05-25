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
	store       continuation.Store
	execStore   execution.Store
	executor    execution.Executor
	eventStore  events.Store
	gatewayID   string
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

func (h *ContinuationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/continuations", h.handleList)
	mux.HandleFunc("GET /v1/continuations/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/continuations/stats", h.handleStats)
	mux.HandleFunc("POST /v1/continuations/sweep", h.handleSweep)
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
	json.NewEncoder(w).Encode(map[string]any{
		"total":        total,
		"by_state":     counts,
		"executable":   executable,
		"expired":      expired,
	})
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

	if !cnt.IsExecutable() {
		api.JSONBadRequest(w, "continuation not executable: current state="+string(cnt.State))
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
		if exe.State == execution.StateSucceeded {
			evtType = events.EventTypeExecutionSucceeded
			cnt.MarkExecuted()
		} else {
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
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}