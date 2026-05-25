package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/metrics"
)

type ApprovalHandler struct {
	service    *approval.Service
	eventStore events.Store
	gatewayID  string
}

func NewApprovalHandler(s *approval.Service) *ApprovalHandler {
	return &ApprovalHandler{service: s}
}

func (h *ApprovalHandler) SetEventStore(store events.Store) {
	h.eventStore = store
}

func (h *ApprovalHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

func (h *ApprovalHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/approval/create", h.handleCreate)
	mux.HandleFunc("GET /v1/approval/{id}", h.handleGet)
	mux.HandleFunc("POST /v1/approval/{id}/approve", h.handleApprove)
	mux.HandleFunc("POST /v1/approval/{id}/deny", h.handleDeny)
	mux.HandleFunc("GET /v1/approval/pending", h.handleListPending)
	mux.HandleFunc("POST /v1/approval/{id}/resume", h.handleResume)
}

func (h *ApprovalHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.JSONBadRequest(w, "failed to read body")
		return
	}
	defer r.Body.Close()

	var req approval.CreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		api.JSONBadRequest(w, "invalid request: "+err.Error())
		return
	}

	if req.DecisionID == "" || req.ActionType == "" {
		api.JSONBadRequest(w, "decision_id and action_type are required")
		return
	}

	created, err := h.service.CreateApproval(&req)
	if err != nil {
		api.JSONInternalError(w, "failed to create approval: "+err.Error())
		return
	}

	metrics.RecordApproval()

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeApprovalCreated).
			WithGatewayID(h.gatewayID).
			WithDecisionID(req.DecisionID).
			WithApprovalID(created.ApprovalID).
			WithAgentID(req.AgentID).
			WithPayload(map[string]any{
				"action_type": created.ActionType,
				"resource":    created.Resource,
				"trust_score": created.TrustScore,
				"status":      string(created.Status),
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (h *ApprovalHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "approval id is required")
		return
	}

	approval, err := h.service.GetApproval(id)
	if err != nil {
		api.JSONNotFound(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(approval)
}

func (h *ApprovalHandler) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "approval id is required")
		return
	}

	var body struct {
		ResolvedBy string `json:"resolved_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	if body.ResolvedBy == "" {
		api.JSONBadRequest(w, "resolved_by is required")
		return
	}

	updated, err := h.service.Approve(id, body.ResolvedBy)
	if err != nil {
		api.JSONInternalError(w, "failed to approve: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeApprovalResolved).
			WithGatewayID(h.gatewayID).
			WithApprovalID(id).
			WithDecisionID(updated.DecisionID).
			WithPayload(map[string]any{
				"action":      "approved",
				"resolved_by": body.ResolvedBy,
				"trust_score": updated.TrustScore,
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

func (h *ApprovalHandler) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "approval id is required")
		return
	}

	var body struct {
		ResolvedBy string `json:"resolved_by"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	if body.ResolvedBy == "" {
		api.JSONBadRequest(w, "resolved_by is required")
		return
	}

	updated, err := h.service.Deny(id, body.ResolvedBy, body.Reason)
	if err != nil {
		api.JSONInternalError(w, "failed to deny: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeApprovalResolved).
			WithGatewayID(h.gatewayID).
			WithApprovalID(id).
			WithDecisionID(updated.DecisionID).
			WithPayload(map[string]any{
				"action":      "denied",
				"resolved_by": body.ResolvedBy,
				"reason":      body.Reason,
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

func (h *ApprovalHandler) handleListPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	pending := h.service.ListPending()
	if pending == nil {
		pending = []*approval.ApprovalRequest{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"approvals": pending,
		"count":     len(pending),
	})
}

func (h *ApprovalHandler) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "approval id is required")
		return
	}

	result, err := h.service.ResumeAction(id)
	if err != nil {
		api.JSONBadRequest(w, "cannot resume: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeApprovalResumed).
			WithGatewayID(h.gatewayID).
			WithApprovalID(id).
			WithDecisionID(result.DecisionID).
			WithPayload(map[string]any{
				"trust_score":   result.TrustScore,
				"trust_level":   result.TrustLevel,
				"anomaly_codes": result.AnomalyCodes,
			})
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}