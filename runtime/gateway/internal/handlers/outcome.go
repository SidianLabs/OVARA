package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/models"
)

// Outcome reports: a component that acted on a decision the gateway
// produced (an SDK tool guard running an in-process tool, a harness running
// a command) says how it went. The record is the point: the decision says
// what was allowed, the outcome says what happened, and the two share the
// decision id. Reporting never changes a decision.

const (
	outcomeOK    = "ok"
	outcomeError = "error"
	// maxOutcomeErrorLen bounds the error text kept in the event, as the
	// approval context bounds what a request may put in front of a person.
	maxOutcomeErrorLen = 600
)

// ActionOutcome is what the caller reports after acting on a decision.
type ActionOutcome struct {
	DecisionID string `json:"decision_id"`
	// Status is "ok" or "error".
	Status string `json:"status"`
	// DurationMS is how long the action took, when the caller measured it.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// Error is the error the action ended with, for a status of "error".
	Error      string    `json:"error,omitempty"`
	ReportedAt time.Time `json:"reported_at"`
}

// handleOutcome is POST /v1/runtime/outcome: {decision_id, status, duration_ms?, error?}.
//
//   - 200 {decision_id, status, recorded}: the outcome is on record (an
//     "action.outcome" event naming the decision, the agent and the action).
//   - 404 for a decision the gateway never produced or no longer holds.
//   - 403 for another principal's decision (an operator may report any).
//   - 409 for a decision that was denied: nothing was allowed to run, so a
//     report is evidence of a caller that ignored the answer, and is kept as
//     a security event; and for a second report on the same decision.
func (h *Handler) handleOutcome(w http.ResponseWriter, r *http.Request) {
	var in ActionOutcome
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		api.JSONBadRequest(w, "invalid JSON body: "+err.Error())
		return
	}
	in.DecisionID = strings.TrimSpace(in.DecisionID)
	if in.DecisionID == "" {
		api.JSONBadRequest(w, "decision_id is required")
		return
	}
	if in.Status != outcomeOK && in.Status != outcomeError {
		api.JSONBadRequest(w, `status must be "ok" or "error"`)
		return
	}
	if in.DurationMS < 0 {
		api.JSONBadRequest(w, "duration_ms must not be negative")
		return
	}
	if in.Status == outcomeOK {
		in.Error = ""
	}
	in.Error = truncateContextValue(in.Error, maxOutcomeErrorLen)
	in.ReportedAt = time.Now().UTC()

	origReq, resp, known := h.LookupDecision(in.DecisionID)
	if !known {
		api.JSONNotFound(w, "unknown decision_id: outcomes can only be reported for decisions the gateway produced")
		return
	}
	// OWNERSHIP: as an approval, an outcome may only be reported by the
	// principal the decision was made for, or by an operator.
	caller := auth.PrincipalID(r)
	if caller != "" && auth.Principal(r) != string(auth.RoleOperator) && caller != agentIDOf(origReq) {
		h.emitOutcomeViolation("cross_principal_outcome", in, origReq, caller,
			"outcome reported for a decision owned by another principal")
		api.JSONError(w, http.StatusForbidden, "decision belongs to another principal")
		return
	}
	if resp != nil && resp.Decision == models.DecisionDeny {
		h.emitOutcomeViolation("outcome_for_denied_decision", in, origReq, agentIDOf(origReq),
			"an outcome was reported for a decision the gateway denied: the caller acted against the answer")
		api.JSONConflict(w, "the decision was deny: nothing was allowed to run, so there is no outcome to report (recorded as a security event)")
		return
	}
	if _, _, ok := h.decisionCache.SetOutcome(in.DecisionID, &in); !ok {
		api.JSONConflict(w, "an outcome is already on record for this decision")
		return
	}

	recorded := false
	if h.eventStore != nil {
		payload := map[string]any{
			"action_type": string(origReq.ActionType),
			"resource":    origReq.Resource,
			"environment": string(origReq.Environment),
			"status":      in.Status,
			"duration_ms": in.DurationMS,
		}
		if resp != nil {
			payload["decision"] = string(resp.Decision)
			if resp.ApprovalID != "" {
				payload["approval_id"] = resp.ApprovalID
			}
		}
		if in.Error != "" {
			payload["error"] = in.Error
		}
		h.eventStore.Append(events.NewEvent(events.EventTypeActionOutcome).
			WithDecisionID(in.DecisionID).
			WithAgentID(agentIDOf(origReq)).
			WithPayload(payload))
		recorded = true
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"decision_id": in.DecisionID,
		"status":      in.Status,
		"recorded":    recorded,
	})
}

func (h *Handler) emitOutcomeViolation(kind string, in ActionOutcome, origReq *models.ActionRequest, agent, detail string) {
	if h.eventStore == nil {
		return
	}
	payload := map[string]any{
		"kind":            kind,
		"detail":          detail,
		"reported_status": in.Status,
	}
	if origReq != nil {
		payload["action_type"] = string(origReq.ActionType)
		payload["resource"] = origReq.Resource
	}
	h.eventStore.Append(events.NewEvent(events.EventTypeSecurityViolation).
		WithDecisionID(in.DecisionID).
		WithAgentID(agent).
		WithPayload(payload))
}
