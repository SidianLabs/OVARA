package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/execution"
)

type ExecutionHandler struct {
	store execution.Store
}

func NewExecutionHandler(store execution.Store) *ExecutionHandler {
	return &ExecutionHandler{store: store}
}

func (h *ExecutionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/executions", h.handleList)
	mux.HandleFunc("GET /v1/executions/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/executions/stats", h.handleStats)
}

func (h *ExecutionHandler) handleList(w http.ResponseWriter, r *http.Request) {
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
	continuationFilter := r.URL.Query().Get("continuation_id")

	var execs []*execution.Execution
	if continuationFilter != "" {
		execs = h.store.ListByContinuation(continuationFilter)
	} else if stateFilter != "" {
		execs = h.store.ListByState(execution.State(stateFilter))
	} else {
		execs = h.store.ListAll()
	}

	if limit > 0 && len(execs) > limit {
		execs = execs[len(execs)-limit:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"executions": execs,
		"count":      len(execs),
	})
}

func (h *ExecutionHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	total, succeeded, failed, running, timedOut := h.store.Stats()

	response := map[string]any{
		"total":      total,
		"succeeded":  succeeded,
		"failed":     failed,
		"running":    running,
		"timed_out":   timedOut,
	}

	if fb, ok := h.store.(*execution.FileBackedStore); ok {
		response["persistence_mode"] = "file_backed"
		response["retention_days"] = fb.RetentionDays()
		response["max_records"] = fb.MaxRecords()
		response["current_count"] = fb.CurrentCount()
		response["file_path"] = fb.FilePath()
		if size, err := fb.FileSizeBytes(); err == nil {
			response["file_size_bytes"] = size
		}
	} else {
		response["persistence_mode"] = "in_memory"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *ExecutionHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "execution id is required")
		return
	}

	exe, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "execution not found: "+id)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exe)
}