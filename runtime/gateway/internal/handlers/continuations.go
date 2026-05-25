package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
)

type ContinuationHandler struct {
	store continuation.Store
}

func NewContinuationHandler(store continuation.Store) *ContinuationHandler {
	return &ContinuationHandler{store: store}
}

func (h *ContinuationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/continuations", h.handleList)
	mux.HandleFunc("GET /v1/continuations/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/continuations/stats", h.handleStats)
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
	var total int
	for _, c := range all {
		counts[string(c.State)]++
		total++
	}

	executable := 0
	for _, c := range all {
		if c.IsExecutable() {
			executable++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total":        total,
		"by_state":     counts,
		"executable":   executable,
	})
}