package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

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
	mux.HandleFunc("GET /v1/events/export", h.handleExport)
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
	agentID := r.URL.Query().Get("agent_id")
	decisionID := r.URL.Query().Get("decision_id")
	approvalID := r.URL.Query().Get("approval_id")
	receiptID := r.URL.Query().Get("receipt_id")
	gatewayID := r.URL.Query().Get("gateway_id")

	var since, until *time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = &t
		}
	}
	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = &t
		}
	}

	allEvents := h.store.List(limit)

	if eventType != "" || agentID != "" || decisionID != "" || approvalID != "" || receiptID != "" || gatewayID != "" || since != nil || until != nil {
		filtered := make([]*events.Event, 0, len(allEvents))
		for _, e := range allEvents {
			if eventType != "" && e.EventType != eventType {
				continue
			}
			if agentID != "" && e.AgentID != agentID {
				continue
			}
			if decisionID != "" && e.DecisionID != decisionID {
				continue
			}
			if approvalID != "" && e.ApprovalID != approvalID {
				continue
			}
			if receiptID != "" && e.ReceiptID != receiptID {
				continue
			}
			if gatewayID != "" && e.GatewayID != gatewayID {
				continue
			}
			if since != nil && e.Timestamp.Before(*since) {
				continue
			}
			if until != nil && e.Timestamp.After(*until) {
				continue
			}
			filtered = append(filtered, e)
		}
		allEvents = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events": allEvents,
		"count":  len(allEvents),
	})
}

func (h *EventHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10000
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
			if limit > 100000 {
				limit = 100000
			}
		}
	}

	eventType := r.URL.Query().Get("type")
	gatewayID := r.URL.Query().Get("gateway_id")

	var since, until *time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = &t
		}
	}
	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = &t
		}
	}

	allEvents := h.store.List(limit)

	if eventType != "" || gatewayID != "" || since != nil || until != nil {
		filtered := make([]*events.Event, 0, len(allEvents))
		for _, e := range allEvents {
			if eventType != "" && e.EventType != eventType {
				continue
			}
			if gatewayID != "" && e.GatewayID != gatewayID {
				continue
			}
			if since != nil && e.Timestamp.Before(*since) {
				continue
			}
			if until != nil && e.Timestamp.After(*until) {
				continue
			}
			filtered = append(filtered, e)
		}
		allEvents = filtered
	}

	eventTypes := make(map[string]int)
	for _, e := range allEvents {
		eventTypes[e.EventType]++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"exported_at":     time.Now().UTC(),
		"event_count":     len(allEvents),
		"event_types":     eventTypes,
		"gateway_id":      gatewayID,
		"time_range_since": since,
		"time_range_until": until,
		"filter_type":      eventType,
		"events":          allEvents,
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