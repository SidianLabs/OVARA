package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

type AdminHandler struct {
	continuationStore continuation.Store
	eventStore       events.Store
	executionStore   execution.Store
	sweeper          *continuation.Sweeper
}

func NewAdminHandler() *AdminHandler {
	return &AdminHandler{}
}

func (h *AdminHandler) SetContinuationStore(store continuation.Store) {
	h.continuationStore = store
}

func (h *AdminHandler) SetEventStore(store events.Store) {
	h.eventStore = store
}

func (h *AdminHandler) SetExecutionStore(store execution.Store) {
	h.executionStore = store
}

func (h *AdminHandler) SetContinuationSweeper(sweeper *continuation.Sweeper) {
	h.sweeper = sweeper
}

func (h *AdminHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/admin/reconcile/continuations", h.handleReconcileContinuations)
	mux.HandleFunc("POST /v1/admin/reconcile/executions", h.handleReconcileExecutions)
	mux.HandleFunc("POST /v1/admin/compact", h.handleCompact)
	mux.HandleFunc("POST /v1/admin/sweep/continuations", h.handleSweepContinuations)
	mux.HandleFunc("POST /v1/admin/sweep/events", h.handleSweepEvents)
}

func (h *AdminHandler) handleReconcileContinuations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if h.sweeper == nil && h.continuationStore == nil {
		api.JSONBadRequest(w, "continuation store not configured")
		return
	}

	var expired int
	if h.sweeper != nil {
		expired = h.sweeper.ReconcileOnStartup()
	} else {
		now := timeNow()
		candidates := h.continuationStore.ListNonTerminal()
		for _, cnt := range candidates {
			if cnt.ShouldExpire(now) {
				cnt.MarkExpired()
				h.continuationStore.Update(cnt)
				expired++
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"action":     "reconcile_continuations",
		"expired":    expired,
		"status":     "ok",
	})
}

func (h *AdminHandler) handleReconcileExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if h.executionStore == nil {
		api.JSONBadRequest(w, "execution store not configured")
		return
	}

	total, succeeded, failed, running, timedOut := h.executionStore.Stats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"action":    "reconcile_executions",
		"stats": map[string]int{
			"total":      total,
			"succeeded":  succeeded,
			"failed":     failed,
			"running":    running,
			"timed_out":  timedOut,
		},
		"status": "ok",
	})
}

func (h *AdminHandler) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	results := make(map[string]any)

	if fbCont, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
		if err := fbCont.Compact(); err != nil {
			results["continuations"] = map[string]any{"error": err.Error()}
		} else {
			results["continuations"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["continuations"] = map[string]any{"status": "not_file_backed"}
	}

	if fbEvents, ok := h.eventStore.(*events.FileBackedStore); ok {
		if err := fbEvents.Compact(); err != nil {
			results["events"] = map[string]any{"error": err.Error()}
		} else {
			results["events"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["events"] = map[string]any{"status": "not_file_backed"}
	}

	if fbExe, ok := h.executionStore.(*execution.FileBackedStore); ok {
		if err := fbExe.Compact(); err != nil {
			results["executions"] = map[string]any{"error": err.Error()}
		} else {
			results["executions"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["executions"] = map[string]any{"status": "not_file_backed"}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"action":  "compact",
		"results": results,
		"status":  "ok",
	})
}

func (h *AdminHandler) handleSweepContinuations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if fbCont, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
		removed, err := fbCont.Sweep()
		if err != nil {
			api.JSONBadRequest(w, "sweep failed: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"action":   "sweep_continuations",
			"removed":  removed,
			"status":   "ok",
		})
		return
	}

	api.JSONBadRequest(w, "continuation store does not support sweep")
}

func (h *AdminHandler) handleSweepEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if fbEvents, ok := h.eventStore.(*events.FileBackedStore); ok {
		removed, err := fbEvents.Sweep()
		if err != nil {
			api.JSONBadRequest(w, "sweep failed: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"action":   "sweep_events",
			"removed":  removed,
			"status":   "ok",
		})
		return
	}

	api.JSONBadRequest(w, "event store does not support sweep")
}

func timeNow() time.Time {
	return time.Now().UTC()
}