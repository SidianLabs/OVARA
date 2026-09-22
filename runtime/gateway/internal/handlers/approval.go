package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/metrics"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/revocation"
)

// maxApprovalBodyBytes caps approval request bodies so a client cannot force
// an unbounded io.ReadAll allocation.
const maxApprovalBodyBytes = 10 << 20 // 10 MiB

type ApprovalHandler struct {
	service           *approval.Service
	eventStore        events.Store
	gatewayID         string
	continuationStore continuation.Store
	// decisionLookup resolves decision_id to the server-recorded
	// request+decision. Approvals may only be created for decisions the
	// policy engine actually produced — never for caller-fabricated IDs.
	decisionLookup func(string) (*models.ActionRequest, *models.DecisionResponse, bool)
	// revocation is the P2.3.4 shared boundary — consulted at resume so
	// an approval cannot ride authority revoked after it was granted.
	revocation revocation.Checker
}

func NewApprovalHandler(s *approval.Service) *ApprovalHandler {
	return &ApprovalHandler{service: s}
}

// SetDecisionLookup wires the decision cache as the provenance source.
func (h *ApprovalHandler) SetDecisionLookup(fn func(string) (*models.ActionRequest, *models.DecisionResponse, bool)) {
	h.decisionLookup = fn
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

// SetRevocation installs the shared revocation boundary (P2.3.4) —
// consulted at resume before the single-use token is consumed.
func (h *ApprovalHandler) SetRevocation(rc revocation.Checker) {
	h.revocation = rc
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxApprovalBodyBytes))
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

	if req.DecisionID == "" {
		api.JSONBadRequest(w, "decision_id is required")
		return
	}

	// PROVENANCE: an approval may only be created for a decision the
	// policy engine actually produced AND escalated. Caller-supplied
	// action/resource/agent/environment are never authoritative — they are
	// derived from the server-recorded request. Divergent caller values are
	// rejected as tampering.
	origReq, origResp, ok := h.lookupDecision(req.DecisionID)
	if !ok {
		h.emitSecurityEvent("fabricated_decision", req.DecisionID, req.AgentID,
			"approval create referenced a decision the gateway never produced")
		api.JSONNotFound(w, "unknown decision_id — approvals can only be created for gateway-produced decisions")
		return
	}
	// OWNERSHIP: the approval inherits the decision's authenticated
	// principal. Only that principal (or an operator) may create it —
	// agent-B must never mint an approval on agent-A's decision.
	if caller := auth.PrincipalID(r); caller != "" &&
		auth.Principal(r) != string(auth.RoleOperator) &&
		caller != agentIDOf(origReq) {
		h.emitSecurityEvent("cross_principal_approval", req.DecisionID, caller,
			"approval create referenced a decision owned by another principal")
		api.JSONError(w, http.StatusForbidden, "decision belongs to another principal — approvals may only be created by the owning principal or an operator")
		return
	}
	if origResp.Decision != models.DecisionEscalate && !origResp.RequiresApproval {
		h.emitSecurityEvent("unescalated_decision_approval", req.DecisionID, agentIDOf(origReq),
			"approval create referenced a decision that did not escalate")
		api.JSONConflict(w, "decision did not escalate — no approval required")
		return
	}
	if diverged := divergence(req, origReq); diverged != "" {
		h.emitSecurityEvent("approval_field_tamper", req.DecisionID, agentIDOf(origReq),
			"caller-supplied "+diverged+" diverges from the evaluated request")
		api.JSONBadRequest(w, diverged+" does not match the evaluated request")
		return
	}

	// Idempotent per decision: two approvals for one decision would queue
	// two continuations — the same action executing twice on approval.
	// Pending/approved → return the existing one; denied → 409 (a denied
	// decision must not mint a second bite — re-submit for a fresh
	// decision instead: approval-fatigue defense).
	for _, existing := range h.service.ListByDecision(req.DecisionID) {
		switch existing.Status {
		case approval.StatusPending, approval.StatusApproved:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(existing)
			return
		case approval.StatusDenied:
			api.JSONConflict(w, "decision already resolved (denied) — re-submit the action for a new decision")
			return
		}
	}

	// Rebuild the create request entirely from server-recorded state.
	bound := approval.CreateRequest{
		DecisionID:  req.DecisionID,
		ActionType:  origReq.ActionType,
		Resource:    origReq.Resource,
		Environment: origReq.Environment,
		AgentID:     agentIDOf(origReq),
		TrustScore:  origResp.TrustScore,
		TrustLevel:  origResp.TrustLevel,
	}
	if origResp.ReceiptStub != nil {
		bound.RequestHash = origResp.ReceiptStub.ActionDigest
		bound.PolicyVersion = origResp.ReceiptStub.PolicyVersion
	}
	if origResp.TrustContext != nil {
		bound.ShieldActive = origResp.TrustContext.ShieldActive
		bound.Restricted = origResp.TrustContext.Restricted
	}

	// P2.3.4 — capture the authority identifiers of the evaluated
	// request so the continuation can be revalidated at claim time
	// against CURRENT revocation state. The decision cache is the only
	// source — caller fields are never authoritative for these.
	if origReq.CapabilityLease != nil {
		bound.LeaseID = origReq.CapabilityLease.LeaseID
	}
	if origReq.DelegationChain != nil {
		bound.DelegationKeys, bound.Issuers = identity.ChainRevocationIDs(origReq.DelegationChain)
	}
	// C4 — the earliest expiry across all captured authority (lease
	// expiry, delegation-hop expiries). The validator enforces
	// expiry narrowing, so min-over-hops equals the effective bound.
	var authorityExpiry *time.Time
	minInto := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if authorityExpiry == nil || t.Before(*authorityExpiry) {
			tt := t
			authorityExpiry = &tt
		}
	}
	if origReq.CapabilityLease != nil {
		minInto(origReq.CapabilityLease.Expiry)
	}
	if origReq.DelegationChain != nil {
		for _, hop := range origReq.DelegationChain.Authorities {
			minInto(hop.ExpiresAt)
		}
	}

	created, err := h.service.CreateApproval(&bound)
	if err != nil {
		api.JSONInternalError(w, "failed to create approval: "+err.Error())
		return
	}

	metrics.RecordApproval()

	cnt := continuation.NewContinuation(bound.DecisionID, string(bound.ActionType), bound.Resource).
		WithAgentID(bound.AgentID).
		WithEnvironment(string(bound.Environment)).
		WithTrustContext(bound.TrustScore, string(bound.TrustLevel), bound.AnomalyCodes, bound.ShieldActive, bound.Restricted).
		WithApprovalID(created.ApprovalID).
		WithAuthorityIDs(bound.LeaseID, bound.DelegationKeys, bound.Issuers).
		WithAuthorityExpiry(authorityExpiry).
		WithExpiration(continuation.DefaultExpirationMinutes).
		WithMetadata("request_hash", bound.RequestHash).
		WithMetadata("policy_version", bound.PolicyVersion)

	if bound.ActionType == "shell" || bound.ActionType == "git.push" {
		cnt.WithMetadata("escalation_reason", "policy_escalate")
	}

	if h.continuationStore != nil {
		_ = h.continuationStore.Create(cnt)
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeContinuationCreated).
			WithGatewayID(h.gatewayID).
			WithDecisionID(bound.DecisionID).
			WithApprovalID(created.ApprovalID).
			WithAgentID(bound.AgentID).
			WithPayload(map[string]any{
				"continuation_id": cnt.ContinuationID,
				"action_type":     string(bound.ActionType),
				"resource":        bound.Resource,
				"trust_score":     bound.TrustScore,
				"state":           string(cnt.State),
				"expires_at":      cnt.ExpiresAt,
			})
		h.eventStore.Append(evt)
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypeApprovalCreated).
			WithGatewayID(h.gatewayID).
			WithDecisionID(bound.DecisionID).
			WithApprovalID(created.ApprovalID).
			WithAgentID(bound.AgentID).
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

// writeResolveError maps approval resolution errors to honest status codes:
// missing approval → 404, already-resolved → 409, anything else → 500.
func writeResolveError(w http.ResponseWriter, op string, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		api.JSONNotFound(w, msg)
	case strings.Contains(msg, "not pending"):
		api.JSONConflict(w, "failed to "+op+": "+msg)
	default:
		api.JSONInternalError(w, "failed to "+op+": "+msg)
	}
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

	// OWNERSHIP: an agent may read only approvals it owns; operators see
	// all. Foreign IDs answer 404 — guessing an ID must not disclose
	// that another principal's approval exists.
	if caller := auth.PrincipalID(r); caller != "" &&
		auth.Principal(r) != string(auth.RoleOperator) &&
		approval.AgentID != caller {
		api.JSONNotFound(w, "approval not found: "+id)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxApprovalBodyBytes)).Decode(&body); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	// resolved_by is derived from the authenticated credential — the
	// caller's optional label is a display suffix, never the identity.
	// A caller cannot impersonate a different authorization domain.
	resolvedBy := auth.Principal(r)
	if body.ResolvedBy != "" {
		resolvedBy += ":" + body.ResolvedBy
	}

	updated, err := h.service.Approve(id, resolvedBy)
	if err != nil {
		writeResolveError(w, "approve", err)
		return
	}

	if h.continuationStore != nil {
		// Apply approved→queued to all bound continuations atomically in the
		// store: no stale snapshots, and an in-flight execution is never
		// retargeted by a racing resolution.
		for _, cnt := range h.continuationStore.ApplyApprovalDecision(id, true, resolvedBy, "") {
			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationQueued).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"resolved_by":     resolvedBy,
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
				"resolved_by": resolvedBy,
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxApprovalBodyBytes)).Decode(&body); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	resolvedBy := auth.Principal(r)
	if body.ResolvedBy != "" {
		resolvedBy += ":" + body.ResolvedBy
	}

	updated, err := h.service.Deny(id, resolvedBy, body.Reason)
	if err != nil {
		writeResolveError(w, "deny", err)
		return
	}

	if h.continuationStore != nil {
		for _, cnt := range h.continuationStore.ApplyApprovalDecision(id, false, resolvedBy, body.Reason) {
			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationDenied).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"resolved_by":     resolvedBy,
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
				"resolved_by": resolvedBy,
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
		// In the wired path continuations are approved→queued at approve
		// time, so resume has nothing to do. Return an honest 409 rather
		// than succeeding vacuously.
		if len(list) > 0 {
			anyResumable := false
			for _, cnt := range list {
				if cnt.CanResume() {
					anyResumable = true
					break
				}
			}
			if !anyResumable {
				api.JSONConflict(w, "continuation not ready for resume: state="+string(list[0].State))
				return
			}
		}
	}

	// P2.3.4 — an approval must not bypass revocation. The approval's
	// recorded authority identifiers (lease, presentation key, hop
	// issuers) are revalidated against CURRENT revocation state before
	// the single-use resume token is consumed. A revoked authority
	// denies the resume; a storage failure fails closed (the token is
	// not consumed — the operator can retry when the store recovers).
	if h.revocation != nil {
		cur, err := h.service.GetApproval(id)
		if err == nil {
			pairs := revocation.PairsFor(cur.LeaseID, cur.DelegationKeys, cur.Issuers)
			if len(pairs) > 0 {
				off, rev, rerr := h.revocation.AnyRevoked(pairs...)
				switch {
				case rerr != nil:
					api.JSONConflict(w, "revocation state unavailable — cannot resume")
					return
				case rev:
					api.JSONConflict(w, fmt.Sprintf("approval cannot resume: %s %q is revoked", off.Class, off.Target))
					return
				}
			}
		}
	}

	// Single-use: ResumeAction atomically consumes the resume token, so a
	// replayed request fails instead of re-resuming.
	result, err := h.service.ResumeAction(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			api.JSONNotFound(w, err.Error())
			return
		}
		api.JSONConflict(w, "resume failed: "+err.Error())
		return
	}

	var resumed []*continuation.Continuation
	if h.continuationStore != nil {
		resumed = h.continuationStore.ResumeForApproval(id)
		for _, cnt := range resumed {
			if h.eventStore != nil {
				evt := events.NewEvent(events.EventTypeContinuationResumed).
					WithGatewayID(h.gatewayID).
					WithApprovalID(id).
					WithDecisionID(cnt.DecisionID).
					WithAgentID(cnt.AgentID).
					WithPayload(map[string]any{
						"continuation_id": cnt.ContinuationID,
						"state":           string(cnt.State),
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
		"resumed":       true,
		"approval_id":   id,
		"decision_id":   result.DecisionID,
		"action_type":   result.ActionType,
		"resource":      result.Resource,
		"trust_score":   result.TrustScore,
		"trust_level":   result.TrustLevel,
		"anomaly_codes": result.AnomalyCodes,
		"shield_active": result.ShieldActive,
		"restricted":    result.Restricted,
	}

	if len(resumed) > 0 {
		cnt := resumed[0]
		resp["continuation_id"] = cnt.ContinuationID
		resp["policy_version"] = cnt.PolicyVersion
		resp["capability_ref"] = cnt.CapabilityRef
		resp["metadata"] = cnt.Metadata
	} else if h.continuationStore != nil {
		if list := h.continuationStore.ListByApprovalID(id); len(list) > 0 {
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

// lookupDecision resolves a decision_id through the wired provenance
// source. A nil lookup fails closed — no provenance, no approvals.
func (h *ApprovalHandler) lookupDecision(id string) (*models.ActionRequest, *models.DecisionResponse, bool) {
	if h.decisionLookup == nil {
		return nil, nil, false
	}
	return h.decisionLookup(id)
}

// emitSecurityEvent records a failed authorization attempt.
func (h *ApprovalHandler) emitSecurityEvent(kind, decisionID, agentID, reason string) {
	if h.eventStore == nil {
		return
	}
	evt := events.NewEvent(events.EventTypeSecurityViolation).
		WithGatewayID(h.gatewayID).
		WithDecisionID(decisionID).
		WithAgentID(agentID).
		WithPayload(map[string]any{
			"kind":   kind,
			"reason": reason,
		})
	h.eventStore.Append(evt)
}

func agentIDOf(req *models.ActionRequest) string {
	if req != nil && req.AgentIdentity != nil {
		return req.AgentIdentity.SubjectID
	}
	return ""
}

// divergence names the first caller-supplied field that conflicts with the
// server-recorded request. Empty fields are not divergent (omitted = no
// claim). Returns "" when nothing conflicts.
func divergence(req approval.CreateRequest, orig *models.ActionRequest) string {
	if req.ActionType != "" && req.ActionType != orig.ActionType {
		return "action_type"
	}
	if req.Resource != "" && req.Resource != orig.Resource {
		return "resource"
	}
	if req.Environment != "" && req.Environment != orig.Environment {
		return "environment"
	}
	if req.AgentID != "" && req.AgentID != agentIDOf(orig) {
		return "agent_id"
	}
	return ""
}
