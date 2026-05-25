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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"continuations": continuations,
		"count":          len(continuations),
	})
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