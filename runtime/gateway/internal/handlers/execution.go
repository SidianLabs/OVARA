package handlers

import (
	"encoding/json"
	"net/http"
	"sort"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/execution"
)

type ExecutionHandler struct {
	store      execution.Store
	execStore  execution.Store
	contStore  continuation.Store
	executor   *execution.ShellExecutor
}

func NewExecutionHandler(store execution.Store) *ExecutionHandler {
	return &ExecutionHandler{store: store, execStore: store}
}

func (h *ExecutionHandler) SetExecutor(exec *execution.ShellExecutor) {
	h.executor = exec
}

func (h *ExecutionHandler) SetContinuationStore(store continuation.Store) {
	h.contStore = store
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

	limit := parseLimit(r, defaultListLimit, maxListLimit)

	stateFilter := r.URL.Query().Get("state")
	continuationFilter := r.URL.Query().Get("continuation_id")
	decisionFilter := r.URL.Query().Get("decision_id")
	actionTypeFilter := r.URL.Query().Get("action_type")
	sortOrder := r.URL.Query().Get("sort")

	var execs []*execution.Execution
	if continuationFilter != "" {
		execs = h.store.ListByContinuation(continuationFilter)
	} else if stateFilter != "" {
		execs = h.store.ListByState(execution.State(stateFilter))
	} else if decisionFilter != "" {
		execs = h.store.ListByDecision(decisionFilter)
	} else {
		execs = h.store.ListAll()
	}

	if actionTypeFilter != "" {
		filtered := make([]*execution.Execution, 0, len(execs))
		for _, e := range execs {
			if e.ActionType == actionTypeFilter {
				filtered = append(filtered, e)
			}
		}
		execs = filtered
	}

	// Sort after filters, before limiting. Default order is newest first
	// (deterministic) so the limit window returns the most recent executions
	// reproducibly; sort=oldest reverses it. Executions are ordered by
	// StartedAt, with ExecutionID as the stable tiebreaker (also covering
	// pending executions whose StartedAt is still zero).
	ascending := sortAscending(sortOrder)
	sort.Slice(execs, func(i, j int) bool {
		a, b := execs[i], execs[j]
		if a.StartedAt.Equal(b.StartedAt) {
			if ascending {
				return a.ExecutionID < b.ExecutionID
			}
			return a.ExecutionID > b.ExecutionID
		}
		if ascending {
			return a.StartedAt.Before(b.StartedAt)
		}
		return b.StartedAt.Before(a.StartedAt)
	})

	if limit > 0 && len(execs) > limit {
		execs = execs[:limit]
	}

	if execs == nil {
		execs = []*execution.Execution{}
	}

	total, succeeded, failed, running, timedOut := h.store.Stats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"executions": execs,
		"count":      len(execs),
		"summary": map[string]int{
			"total":      total,
			"succeeded":  succeeded,
			"failed":     failed,
			"running":    running,
			"timed_out":   timedOut,
		},
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

	if h.executor != nil {
		response["executor_stdout_limit_bytes"] = h.executor.StdoutLimitBytes
		response["executor_stderr_limit_bytes"] = h.executor.StderrLimitBytes
		response["executor_default_timeout_secs"] = int(h.executor.DefaultTimeout.Seconds())
		if h.executor.WorkingDir != "" {
			response["executor_working_dir"] = h.executor.WorkingDir
		}
		if len(h.executor.AllowedEnvVars) > 0 {
			response["executor_allowed_env_vars"] = h.executor.AllowedEnvVars
		}
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

	failureInfo := exe.FailureInfo()

	response := map[string]any{
		"execution": exe,
		"failure":   failureInfo,
	}

	if h.contStore != nil && exe.ContinuationID != "" {
		if cont, found := h.contStore.Get(exe.ContinuationID); found {
			response["retry"] = cont.RetryInfo()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}