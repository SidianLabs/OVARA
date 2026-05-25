package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/events"
)

type EventHandler struct {
	store events.Store
}

func NewEventHandler(store events.Store) *EventHandler {
	return &EventHandler{store: store}
}

func (h *EventHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/events", h.handleList)
	mux.HandleFunc("GET /v1/events/{id}", h.handleGet)
}

func (h *EventHandler) handleList(w http.ResponseWriter, r *http.Request) {
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

	eventType := r.URL.Query().Get("type")

	allEvents := h.store.List(limit)

	if eventType != "" {
		filtered := make([]*events.Event, 0, len(allEvents))
		for _, e := range allEvents {
			if e.EventType == eventType {
				filtered = append(filtered, e)
			}
		}
		allEvents = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events": allEvents,
		"count":  len(allEvents),
	})
}

func (h *EventHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "event id is required")
		return
	}

	evt, found := h.store.Get(id)
	if !found {
		api.JSONNotFound(w, "event not found: "+id)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evt)
}