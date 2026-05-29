package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/models"
)

type CapabilitiesHandler struct {
	store        capabilities.Store
	eventStore   events.Store
	historyStore *capabilities.FileBackedHistoryStore
	gatewayID    string
}

func NewCapabilitiesHandler(s capabilities.Store) *CapabilitiesHandler {
	return &CapabilitiesHandler{
		store: s,
	}
}

func (h *CapabilitiesHandler) SetEventStore(es events.Store) {
	h.eventStore = es
}

func (h *CapabilitiesHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

func (h *CapabilitiesHandler) SetHistoryStore(hs *capabilities.FileBackedHistoryStore) {
	h.historyStore = hs
}

func (h *CapabilitiesHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/capabilities", h.handleList)
	mux.HandleFunc("GET /v1/capabilities/{id}", h.handleGet)
	mux.HandleFunc("POST /v1/capabilities/track", h.handleTrack)
	mux.HandleFunc("POST /v1/capabilities/revoke", h.handleRevoke)
	mux.HandleFunc("GET /v1/capabilities/history", h.handleHistory)
	mux.HandleFunc("POST /v1/capabilities/revoke-by-subject", h.handleRevokeBySubject)
}

type ListCapabilitiesResponse struct {
	Capabilities []*capabilities.TrackedLease `json:"capabilities"`
	Count       int                          `json:"count"`
	Active      int                          `json:"active_count"`
	Revoked     int                          `json:"revoked_count"`
	DelegationDepths []int                   `json:"delegation_depths,omitempty"`
}

func (h *CapabilitiesHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	subjectFilter := r.URL.Query().Get("subject")
	issuerFilter := r.URL.Query().Get("issuer")
	statusFilter := r.URL.Query().Get("status")

	all := h.store.List()
	active := h.store.ListActive()
	revoked := h.store.ListRevoked()

	var filtered []*capabilities.TrackedLease
	for _, tracked := range all {
		if subjectFilter != "" && tracked.Lease.Subject != subjectFilter {
			continue
		}
		if issuerFilter != "" && tracked.Lease.Issuer != issuerFilter {
			continue
		}
		if statusFilter != "" {
			switch statusFilter {
			case "active":
				isActive := tracked.RevokedAt == nil && tracked.Lease.Expiry.After(time.Now())
				if !isActive {
					continue
				}
			case "revoked":
				if tracked.RevokedAt == nil {
					continue
				}
			case "all":
			default:
				api.JSONBadRequest(w, "status must be one of: active, revoked, all")
				return
			}
		}
		filtered = append(filtered, tracked)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ListCapabilitiesResponse{
		Capabilities: filtered,
		Count:       len(filtered),
		Active:      len(active),
		Revoked:     len(revoked),
	})
}

func (h *CapabilitiesHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	leaseID := r.PathValue("id")
	if leaseID == "" {
		api.JSONBadRequest(w, "capability id is required")
		return
	}

	tracked, ok := h.store.Get(leaseID)
	if !ok {
		api.JSONNotFound(w, "capability not found: "+leaseID)
		return
	}

	var history []capabilities.LeaseHistoryEntry
	if h.historyStore != nil {
		history = h.historyStore.ListByLeaseID(leaseID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"lease":   tracked,
		"history": history,
	})
}

type TrackRequest struct {
	Lease *models.CapabilityLease `json:"lease"`
}

func (h *CapabilitiesHandler) handleTrack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req TrackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if req.Lease == nil || req.Lease.LeaseID == "" {
		api.JSONBadRequest(w, "lease with lease_id is required")
		return
	}

	id := h.store.Track(req.Lease, h.gatewayID)

	if h.historyStore != nil {
		h.historyStore.Append(capabilities.LeaseTrackedEntry(id, h.gatewayID, req.Lease.Subject, req.Lease.Issuer))
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeCapabilityTracked)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"lease_id": id,
			"subject":  req.Lease.Subject,
			"issuer":   req.Lease.Issuer,
			"expiry":   req.Lease.Expiry,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "tracked",
		"lease_id": id,
	})
}

type RevokeRequest struct {
	LeaseID string `json:"lease_id"`
	Reason  string `json:"reason"`
}

type HistoryResponse struct {
	Entries []capabilities.LeaseHistoryEntry `json:"entries"`
	Count   int                             `json:"count"`
}

func (h *CapabilitiesHandler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	var entries []capabilities.LeaseHistoryEntry
	if h.historyStore != nil {
		entries = h.historyStore.ListRecent(500)
	} else {
		entries = []capabilities.LeaseHistoryEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HistoryResponse{
		Entries: entries,
		Count:   len(entries),
	})
}

type RevokeBySubjectRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

type RevokeBySubjectResponse struct {
	Subject     string   `json:"subject"`
	Revoked     int     `json:"revoked_count"`
	LeaseIDs    []string `json:"lease_ids"`
	NotFound    int     `json:"not_found_count"`
}

func (h *CapabilitiesHandler) handleRevokeBySubject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req RevokeBySubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if req.Subject == "" {
		api.JSONBadRequest(w, "subject is required")
		return
	}
	if req.Reason == "" {
		req.Reason = "operator_bulk_revoked"
	}

	active := h.store.ListActive()
	var revokedIDs []string
	var notFound int

	for _, tracked := range active {
		if tracked.Lease.Subject == req.Subject {
			_, ok := h.store.Revoke(tracked.Lease.LeaseID, req.Reason)
			if !ok {
				notFound++
				continue
			}
			revokedIDs = append(revokedIDs, tracked.Lease.LeaseID)

			if h.historyStore != nil {
				h.historyStore.Append(capabilities.LeaseRevokedEntry(tracked.Lease.LeaseID, h.gatewayID, req.Reason, tracked.Lease.Subject, tracked.Lease.Issuer))
			}
			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeCapabilityRevoked)
				if h.gatewayID != "" {
					evt.WithGatewayID(h.gatewayID)
				}
				evt.Payload = map[string]any{
					"lease_id": tracked.Lease.LeaseID,
					"reason":   req.Reason,
					"subject":  tracked.Lease.Subject,
					"issuer":   tracked.Lease.Issuer,
					"bulk":     true,
				}
				h.eventStore.Append(evt)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RevokeBySubjectResponse{
		Subject:  req.Subject,
		Revoked:  len(revokedIDs),
		LeaseIDs: revokedIDs,
	})
}

func (h *CapabilitiesHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if req.LeaseID == "" {
		api.JSONBadRequest(w, "lease_id is required")
		return
	}

	if req.Reason == "" {
		req.Reason = "operator_revoked"
	}

	tracked, ok := h.store.Revoke(req.LeaseID, req.Reason)
	if !ok {
		api.JSONBadRequest(w, "capability not found: "+req.LeaseID)
		return
	}

	if h.historyStore != nil {
		h.historyStore.Append(capabilities.LeaseRevokedEntry(req.LeaseID, h.gatewayID, req.Reason, tracked.Lease.Subject, tracked.Lease.Issuer))
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeCapabilityRevoked)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"lease_id": req.LeaseID,
			"reason":   req.Reason,
			"subject":  tracked.Lease.Subject,
			"issuer":   tracked.Lease.Issuer,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "revoked",
		"lease_id":     req.LeaseID,
		"revoked_at":   tracked.RevokedAt,
		"revoked_reason": tracked.RevocationReason,
	})
}

func (h *CapabilitiesHandler) CheckRevocation(leaseID string) bool {
	return h.store.IsRevoked(leaseID)
}

func (h *CapabilitiesHandler) IsRevoked(leaseID string) bool {
	return h.store.IsRevoked(leaseID)
}

func (h *CapabilitiesHandler) Touch(leaseID, action, resource string) {
	h.store.Touch(leaseID)
	if h.historyStore != nil {
		h.historyStore.Append(capabilities.LeaseUsedEntryWithContext(leaseID, h.gatewayID, action, resource))
	}
	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeCapabilityUsed)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"lease_id": leaseID,
			"action":   action,
			"resource": resource,
		}
		h.eventStore.Append(evt)
	}
}

func (h *CapabilitiesHandler) RecordUse(leaseID, action, resource string) {
	h.Touch(leaseID, action, resource)
}
