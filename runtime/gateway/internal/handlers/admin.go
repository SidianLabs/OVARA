package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
)

const dryRunParam = "dry_run"

type AdminHandler struct {
	continuationStore continuation.Store
	eventStore       events.Store
	executionStore   execution.Store
	sweeper          *continuation.Sweeper
	gatewayID        string
}

func NewAdminHandler() *AdminHandler {
	return &AdminHandler{}
}

func (h *AdminHandler) SetGatewayID(id string) {
	h.gatewayID = id
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

	dryRun := r.URL.Query().Get(dryRunParam) == "true"

	var expired int
	var candidates []string
	now := timeNow()

	if h.sweeper != nil && !dryRun {
		expired = h.sweeper.ReconcileOnStartup()
	} else {
		nonTerminal := h.continuationStore.ListNonTerminal()
		for _, cnt := range nonTerminal {
			if cnt.ShouldExpire(now) {
				expired++
				if dryRun {
					candidates = append(candidates, cnt.ContinuationID)
				} else {
					cnt.MarkExpired()
					h.continuationStore.Update(cnt)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"action":  "reconcile_continuations",
		"expired": expired,
		"status":  "ok",
	}
	if dryRun {
		resp["dry_run"] = true
		resp["candidates"] = candidates
		resp["message"] = "no changes made - this was a dry run"
	}
	json.NewEncoder(w).Encode(resp)

	if !dryRun && expired > 0 && h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeAdminReconcile)
		evt.ContinuationID = fmt.Sprintf("%d", expired)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"operation": "reconcile_continuations",
			"expired":   expired,
		}
		h.eventStore.Append(evt)
	}
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

	dryRun := r.URL.Query().Get(dryRunParam) == "true"
	results := make(map[string]any)

	if fbCont, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
		if dryRun {
			results["continuations"] = map[string]any{
				"status":       "would_compact",
				"dry_run":      true,
				"file_path":    fbCont.FilePath(),
				"message":      "file would be compacted on dry_run=false",
			}
		} else if err := fbCont.Compact(); err != nil {
			results["continuations"] = map[string]any{"error": err.Error()}
		} else {
			results["continuations"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["continuations"] = map[string]any{"status": "not_file_backed"}
	}

	if fbEvents, ok := h.eventStore.(*events.FileBackedStore); ok {
		if dryRun {
			results["events"] = map[string]any{
				"status":     "would_compact",
				"dry_run":    true,
				"file_path":  fbEvents.FilePath(),
				"message":    "file would be compacted on dry_run=false",
			}
		} else if err := fbEvents.Compact(); err != nil {
			results["events"] = map[string]any{"error": err.Error()}
		} else {
			results["events"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["events"] = map[string]any{"status": "not_file_backed"}
	}

	if fbExe, ok := h.executionStore.(*execution.FileBackedStore); ok {
		if dryRun {
			results["executions"] = map[string]any{
				"status":    "would_compact",
				"dry_run":   true,
				"file_path": fbExe.FilePath(),
				"message":  "file would be compacted on dry_run=false",
			}
		} else if err := fbExe.Compact(); err != nil {
			results["executions"] = map[string]any{"error": err.Error()}
		} else {
			results["executions"] = map[string]any{"status": "compacted"}
		}
	} else {
		results["executions"] = map[string]any{"status": "not_file_backed"}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"action":  "compact",
		"results": results,
		"status":  "ok",
	}
	if dryRun {
		resp["dry_run"] = true
		resp["message"] = "no changes made - this was a dry run"
	}
	json.NewEncoder(w).Encode(resp)

	if !dryRun && h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeAdminCompact)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"results": results,
		}
		h.eventStore.Append(evt)
	}
}

func (h *AdminHandler) handleSweepContinuations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if fbCont, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
		dryRun := r.URL.Query().Get(dryRunParam) == "true"

		if dryRun {
			nonTerminal := fbCont.ListNonTerminal()
			var expiredCandidates []string
			now := timeNow()
			for _, cnt := range nonTerminal {
				if cnt.ShouldExpire(now) {
					expiredCandidates = append(expiredCandidates, cnt.ContinuationID)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"action":           "sweep_continuations",
				"dry_run":          true,
				"candidates":       expiredCandidates,
				"candidate_count":  len(expiredCandidates),
				"message":          "no changes made - this was a dry run",
				"status":          "ok",
			})
			return
		}

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

		if h.eventStore != nil {
			evt := events.NewEvent(events.EventTypeAdminSweep)
			if h.gatewayID != "" {
				evt.WithGatewayID(h.gatewayID)
			}
			evt.Payload = map[string]any{
				"operation": "sweep_continuations",
				"removed":   removed,
			}
			h.eventStore.Append(evt)
		}
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
		dryRun := r.URL.Query().Get(dryRunParam) == "true"

		if dryRun {
			allEvents := fbEvents.List(10000)
			now := timeNow()
			retentionDays := fbEvents.RetentionDays()
			ageCutoff := now.AddDate(0, 0, -retentionDays)
			maxRecords := fbEvents.MaxRecords()

			var candidates []string
			staleSet := make(map[string]bool)

			for _, evt := range allEvents {
				if !evt.Timestamp.IsZero() && evt.Timestamp.Before(ageCutoff) {
					candidates = append(candidates, evt.EventID)
					staleSet[evt.EventID] = true
				}
			}

			if len(allEvents)-len(candidates) > maxRecords && len(candidates) < len(allEvents) {
				ageSorted := make([]*events.Event, 0, len(allEvents))
				for _, evt := range allEvents {
					if !evt.Timestamp.IsZero() && !staleSet[evt.EventID] {
						ageSorted = append(ageSorted, evt)
					}
				}
				sortEventsByCreatedAt(ageSorted)
				target := maxRecords
				for i := 0; i < len(ageSorted)-target && i < len(ageSorted); i++ {
					if !staleSet[ageSorted[i].EventID] {
						candidates = append(candidates, ageSorted[i].EventID)
						staleSet[ageSorted[i].EventID] = true
					}
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"action":          "sweep_events",
				"dry_run":         true,
				"candidates":      candidates,
				"candidate_count": len(candidates),
				"message":         "no changes made - this was a dry run",
				"status":          "ok",
			})
			return
		}

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

		if h.eventStore != nil {
			evt := events.NewEvent(events.EventTypeAdminSweep)
			if h.gatewayID != "" {
				evt.WithGatewayID(h.gatewayID)
			}
			evt.Payload = map[string]any{
				"operation": "sweep_events",
				"removed":   removed,
			}
			h.eventStore.Append(evt)
		}
		return
	}

	api.JSONBadRequest(w, "event store does not support sweep")
}

func timeNow() time.Time {
	return time.Now().UTC()
}

func sortEventsByCreatedAt(evts []*events.Event) {
	sort.Slice(evts, func(i, j int) bool {
		if evts[i].Timestamp.IsZero() && evts[j].Timestamp.IsZero() {
			return false
		}
		if evts[i].Timestamp.IsZero() {
			return false
		}
		if evts[j].Timestamp.IsZero() {
			return true
		}
		return evts[i].Timestamp.Before(evts[j].Timestamp)
	})
}