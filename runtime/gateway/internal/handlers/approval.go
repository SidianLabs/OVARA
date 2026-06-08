package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/metrics"
)

type ApprovalHandler struct {
	service           *approval.Service
	eventStore         events.Store
	gatewayID          string
	continuationStore  continuation.Store
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

func (h *ApprovalHandler) SetContinuationStore(store continuation.Store) {
	h.continuationStore = store
}

func (h *ApprovalHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/approval/create", h.handleCreate)
	mux.HandleFunc("GET /v1/approval/{id}", h.handleGet)
	mux.HandleFunc("POST /v1/approval/{id}/approve", h.handleApprove)
	mux.HandleFunc("POST /v1/approval/{id}/deny", h.handleDeny)
	mux.HandleFunc("GET /v1/approval/pending", h.handleListPending)
	mux.HandleFunc("GET /v1/approvals", h.handleListApprovals)
	mux.HandleFunc("POST /v1/approval/{id}/resume", h.handleResume)
}

func (h *ApprovalHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.JSONBadRequest(w, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req approval.CreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
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

	cnt := continuation.NewContinuation(req.DecisionID, string(req.ActionType), req.Resource).
		WithAgentID(req.AgentID).
		WithEnvironment(string(req.Environment)).
		WithTrustContext(req.TrustScore, string(req.TrustLevel), req.AnomalyCodes, req.ShieldActive, req.Restricted).
		WithApprovalID(created.ApprovalID).
		WithExpiration(continuation.DefaultExpirationMinutes)

	if req.ActionType == "shell" || req.ActionType == "git.push" {
		cnt.WithMetadata("escalation_reason", "policy_escalate")
	}

	if h.continuationStore != nil {
		_ = h.continuationStore.Create(cnt)
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeContinuationCreated).
			WithGatewayID(h.gatewayID).
			WithDecisionID(req.DecisionID).
			WithApprovalID(created.ApprovalID).
			WithAgentID(req.AgentID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"action_type":    string(req.ActionType),
				"resource":       req.Resource,
				"trust_score":    req.TrustScore,
				"state":          string(cnt.State),
				"expires_at":     cnt.ExpiresAt,
			})
		h.eventStore.Append(evt)
	}

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

	if h.continuationStore != nil {
		list := h.continuationStore.ListByApprovalID(id)
		for _, cnt := range list {
			cnt.MarkApproved(body.ResolvedBy)
			cnt.MarkReady()
			_ = h.continuationStore.Update(cnt)

			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationQueued).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"resolved_by":     body.ResolvedBy,
						"state":           string(cnt.State),
					})
				h.eventStore.Append(evt)
			}
		}
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

	if h.continuationStore != nil {
		list := h.continuationStore.ListByApprovalID(id)
		for _, cnt := range list {
			cnt.MarkDenied(body.ResolvedBy, body.Reason)
			_ = h.continuationStore.Update(cnt)

			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationDenied).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"resolved_by":     body.ResolvedBy,
						"reason":          body.Reason,
						"state":           string(cnt.State),
					})
				h.eventStore.Append(evt)
			}
		}
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

func (h *ApprovalHandler) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	status := r.URL.Query().Get("status")
	requester := r.URL.Query().Get("requester")
	environment := r.URL.Query().Get("environment")
	actionType := r.URL.Query().Get("action_type")
	sortOrder := r.URL.Query().Get("sort")
	createdBefore := r.URL.Query().Get("created_before")
	createdAfter := r.URL.Query().Get("created_after")
	rawAfter := r.URL.Query().Get("after")

	limit := parseLimit(r, defaultListLimit, maxListLimit)

	var approvals []*approval.ApprovalRequest

	if status != "" {
		approvals = h.service.ListByStatus(approval.Status(status))
	} else if requester != "" {
		approvals = h.service.ListByDecision(requester)
	} else {
		approvals = h.service.ListAll()
	}

	if environment != "" {
		filtered := make([]*approval.ApprovalRequest, 0, len(approvals))
		for _, a := range approvals {
			if string(a.Environment) == environment {
				filtered = append(filtered, a)
			}
		}
		approvals = filtered
	}

	if actionType != "" {
		filtered := make([]*approval.ApprovalRequest, 0, len(approvals))
		for _, a := range approvals {
			if string(a.ActionType) == actionType {
				filtered = append(filtered, a)
			}
		}
		approvals = filtered
	}

	if createdBefore != "" {
		if t, err := time.Parse(time.RFC3339, createdBefore); err == nil {
			filtered := make([]*approval.ApprovalRequest, 0, len(approvals))
			for _, a := range approvals {
				if a.CreatedAt.Before(t) || a.CreatedAt.Equal(t) {
					filtered = append(filtered, a)
				}
			}
			approvals = filtered
		}
	}

	if createdAfter != "" {
		if t, err := time.Parse(time.RFC3339, createdAfter); err == nil {
			filtered := make([]*approval.ApprovalRequest, 0, len(approvals))
			for _, a := range approvals {
				if a.CreatedAt.After(t) {
					filtered = append(filtered, a)
				}
			}
			approvals = filtered
		}
	}

	ascending := sortAscending(sortOrder)
	sort.Slice(approvals, func(i, j int) bool {
		a, b := approvals[i], approvals[j]
		if a.CreatedAt.Equal(b.CreatedAt) {
			if ascending {
				return a.ApprovalID < b.ApprovalID
			}
			return a.ApprovalID > b.ApprovalID
		}
		if ascending {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return b.CreatedAt.Before(a.CreatedAt)
	})

	result := buildListedItems(approvals, limit, rawAfter, SortSpec[approval.ApprovalRequest]{
		Ascending:    ascending,
		GetTimestamp: func(a approval.ApprovalRequest) time.Time { return a.CreatedAt },
		GetID:        func(a approval.ApprovalRequest) string { return a.ApprovalID },
	})

	if result.Items == nil {
		result.Items = []*approval.ApprovalRequest{}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"approvals": result.Items,
		"count":     result.Count,
	}
	if result.NextCursor != "" {
		resp["next_cursor"] = result.NextCursor
	}
	json.NewEncoder(w).Encode(resp)
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

	if h.continuationStore != nil {
		list := h.continuationStore.ListByApprovalID(id)
		for _, cnt := range list {
			if !cnt.CanResume() {
				api.JSONConflict(w, "continuation not ready for resume: state="+string(cnt.State))
				return
			}
		}
	}

	result, err := h.service.ResumeAction(id)
	if err != nil {
		api.JSONBadRequest(w, "resume failed: "+err.Error())
		return
	}

	if h.continuationStore != nil {
		list := h.continuationStore.ListByApprovalID(id)
		for _, cnt := range list {
			cnt.MarkResumed()
			_ = h.continuationStore.Update(cnt)

			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationResumed).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"state":          string(cnt.State),
					})
				h.eventStore.Append(evt)
			}
		}
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

	resp := map[string]any{
		"resumed":            true,
		"approval_id":        id,
		"decision_id":        result.DecisionID,
		"action_type":       result.ActionType,
		"resource":          result.Resource,
		"trust_score":       result.TrustScore,
		"trust_level":       result.TrustLevel,
		"anomaly_codes":     result.AnomalyCodes,
		"shield_active":      result.ShieldActive,
		"restricted":        result.Restricted,
	}

	if h.continuationStore != nil {
		list := h.continuationStore.ListByApprovalID(id)
		if len(list) > 0 {
			cnt := list[0]
			resp["continuation_id"] = cnt.ContinuationID
			resp["policy_version"] = cnt.PolicyVersion
			resp["capability_ref"] = cnt.CapabilityRef
			resp["metadata"] = cnt.Metadata
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}