package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/revocation"
)

// maxCapabilitiesBodyBytes caps request bodies on capabilities endpoints.
const maxCapabilitiesBodyBytes = 10 << 20 // 10 MiB

type CapabilitiesHandler struct {
	store        capabilities.Store
	eventStore   events.Store
	historyStore *capabilities.FileBackedHistoryStore
	gatewayID    string
	// leaseValidator verifies lease signatures against trusted issuer keys
	// before a lease is accepted for tracking/revocation. When nil, leases
	// are tracked without signature verification only if allowUnsignedLeases
	// was explicitly opted in.
	leaseValidator *identity.Validator
	// allowUnsignedLeases permits track to accept leases without signature
	// verification when no validator is configured (dev mode opt-in).
	allowUnsignedLeases bool
	// revWriter is the durable revocation sink (P2.3.4) — the domain
	// authority journal. A lease revoke writes the journal record FIRST
	// (the authoritative kill every execution path consults); the
	// tracked-lease flag remains the observability view.
	revWriter RevocationWriter
}

// RevocationWriter is the durable revocation sink (P2.3.4) — the
// domain authority journal (*gwidentity.Registry).
type RevocationWriter interface {
	Revoke(class, target, actor, reason string) (*gwidentity.RevokeRecord, error)
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

// SetLeaseValidator wires the identity validator used to verify lease
// signatures (against trusted issuer keys) before tracking. Once set,
// /v1/capabilities/track rejects leases whose signature does not verify.
func (h *CapabilitiesHandler) SetLeaseValidator(v *identity.Validator) {
	h.leaseValidator = v
}

// SetAllowUnsignedLeases opts in to accepting unsigned leases when no lease
// validator is configured. Default is false: track rejects leases it cannot
// verify.
func (h *CapabilitiesHandler) SetAllowUnsignedLeases(allow bool) {
	h.allowUnsignedLeases = allow
}

// SetRevocationWriter installs the durable revocation sink (P2.3.4).
// Once set, lease revocation is journal-authoritative: the tracked
// flag is observability, and an untracked lease is still killable.
func (h *CapabilitiesHandler) SetRevocationWriter(w RevocationWriter) {
	h.revWriter = w
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
	Capabilities     []*capabilities.TrackedLease `json:"capabilities"`
	Count            int                          `json:"count"`
	Active           int                          `json:"active_count"`
	Revoked          int                          `json:"revoked_count"`
	DelegationDepths []int                        `json:"delegation_depths,omitempty"`
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
		Count:        len(filtered),
		Active:       len(active),
		Revoked:      len(revoked),
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCapabilitiesBodyBytes)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if req.Lease == nil || req.Lease.LeaseID == "" {
		api.JSONBadRequest(w, "lease with lease_id is required")
		return
	}

	// Verify the lease signature against trusted issuer keys before tracking:
	// tracked leases drive revocation decisions, so accepting unsigned or
	// forged leases would let an attacker revoke or spoof capabilities.
	if h.leaseValidator != nil {
		if vr := h.leaseValidator.ValidateCapabilityLease(req.Lease); !vr.Valid {
			api.JSONBadRequest(w, "lease validation failed: "+strings.Join(vr.Reasons, "; "))
			return
		}
	} else if !h.allowUnsignedLeases {
		// Fail closed: with no trusted issuers configured there is no way to
		// verify the lease, and accepting it silently would let an attacker
		// track or spoof capabilities. Requires the explicit
		// allow_unsigned_leases config opt-in.
		api.JSONBadRequest(w, "lease verification unavailable: no trusted_issuers configured and allow_unsigned_leases is not set")
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
		"status":   "tracked",
		"lease_id": id,
	})
}

type RevokeRequest struct {
	LeaseID string `json:"lease_id"`
	Reason  string `json:"reason"`
}

type HistoryResponse struct {
	Entries []capabilities.LeaseHistoryEntry `json:"entries"`
	Count   int                              `json:"count"`
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
	Subject  string   `json:"subject"`
	Revoked  int      `json:"revoked_count"`
	LeaseIDs []string `json:"lease_ids"`
	NotFound int      `json:"not_found_count"`
}

func (h *CapabilitiesHandler) handleRevokeBySubject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req RevokeBySubjectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCapabilitiesBodyBytes)).Decode(&req); err != nil {
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

	actor := auth.PrincipalID(r)
	if actor == "" {
		actor = "operator"
	}

	active := h.store.ListActive()
	var revokedIDs []string
	var notFound int

	for _, tracked := range active {
		if tracked.Lease.Subject == req.Subject {
			// P2.3.4: journal write is the authoritative kill — a
			// failure aborts the bulk operation honestly rather than
			// flipping observability flags the boundary ignores.
			if h.revWriter != nil {
				if _, err := h.revWriter.Revoke(string(revocation.ClassLease), tracked.Lease.LeaseID, actor, req.Reason); err != nil {
					api.JSONInternalError(w, fmt.Sprintf("durable revocation failed after %d lease(s): %v", len(revokedIDs), err))
					return
				}
			}
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCapabilitiesBodyBytes)).Decode(&req); err != nil {
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

	actor := auth.PrincipalID(r)
	if actor == "" {
		actor = "operator"
	}

	// P2.3.4: the journal record is the authoritative kill — written
	// BEFORE the tracked-lease flag so a revocation is never reported
	// that the execution boundary cannot see. An untracked lease is
	// still killable (a lease need not be tracked to be presented).
	var epoch uint64
	if h.revWriter != nil {
		rv, err := h.revWriter.Revoke(string(revocation.ClassLease), req.LeaseID, actor, req.Reason)
		if err != nil {
			api.JSONInternalError(w, "durable revocation failed: "+err.Error())
			return
		}
		epoch = rv.Seq
	}

	tracked, trackedOK := h.store.Revoke(req.LeaseID, req.Reason)
	if !trackedOK && h.revWriter == nil {
		api.JSONBadRequest(w, "capability not found: "+req.LeaseID)
		return
	}

	subject, issuer := "", ""
	if trackedOK {
		subject, issuer = tracked.Lease.Subject, tracked.Lease.Issuer
	}
	if h.historyStore != nil {
		h.historyStore.Append(capabilities.LeaseRevokedEntry(req.LeaseID, h.gatewayID, req.Reason, subject, issuer))
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeCapabilityRevoked)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"lease_id": req.LeaseID,
			"reason":   req.Reason,
			"subject":  subject,
			"issuer":   issuer,
			"actor":    actor,
			"epoch":    epoch,
		}
		h.eventStore.Append(evt)
	}

	resp := map[string]any{
		"status":   "revoked",
		"lease_id": req.LeaseID,
		"actor":    actor,
	}
	if epoch > 0 {
		resp["epoch"] = epoch
	}
	if trackedOK {
		resp["revoked_at"] = tracked.RevokedAt
		resp["revoked_reason"] = tracked.RevocationReason
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
