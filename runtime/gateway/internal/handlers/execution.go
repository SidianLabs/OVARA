package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type ExecutionHandler struct {
	store          execution.Store
	executor       execution.Executor
	eventStore     events.Store
	gatewayID      string
}

func NewExecutionHandler(store execution.Store, executor execution.Executor) *ExecutionHandler {
	return &ExecutionHandler{
		store:    store,
		executor: executor,
	}
}

func (h *ExecutionHandler) SetEventStore(es events.Store) {
	h.eventStore = es
}

func (h *ExecutionHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

func (h *ExecutionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/continuations/{id}/execute", h.handleExecute)
	mux.HandleFunc("GET /v1/executions", h.handleList)
	mux.HandleFunc("GET /v1/executions/{id}", h.handleGet)
}

func (h *ExecutionHandler) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "continuation id is required")
		return
	}

	var req struct {
		TimeoutSeconds int `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.TimeoutSeconds = 60
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 60
	}

	execRecord := execution.NewExecution(
		id,
		"",
		"",
		"",
		"shell",
		"",
		req.TimeoutSeconds,
	)

	ctx := context.Background()
	_ = h.executor.Execute(ctx, execRecord)

	h.store.Create(execRecord)

	resp := map[string]any{
		"execution_id":  execRecord.ExecutionID,
		"state":         string(execRecord.State),
		"exit_code":     execRecord.ExitCode,
		"stdout":        execRecord.Stdout,
		"stderr":        execRecord.Stderr,
		"error":         execRecord.Error,
		"started_at":    execRecord.StartedAt,
		"finished_at":   execRecord.FinishedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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