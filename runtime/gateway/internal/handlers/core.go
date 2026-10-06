package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"ovara.runtime.gateway/core/audit"
	"ovara.runtime.gateway/core/decide"
	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/auth"
)

// Core runtime surface: signed requests through the redesigned
// pipeline (spec/action_model.md, capability_token.md, policy_ir.md).
// Unlike /v1/runtime/check, the request must carry an edsig_v2
// signature over its canonical form (nonce + issued_at inside the
// signature), actor identity is credential-derived — never trusted
// from the wire — and every decision is a write-ahead audit record:
// if the record cannot be durably appended, the action may not run.

// SetCore installs the redesigned engine and its audit log.
func (h *Handler) SetCore(e *decide.Engine, l *audit.Log) {
	h.coreEngine = e
	h.coreLog = l
}

// coreDecisionResponse is the agent-visible surface — coarse reason
// classes only (spec §5 split: operator detail stays in the audit
// record, never crosses to the agent channel). AuditSeq is the
// correlation handle into the write-ahead log.
type coreDecisionResponse struct {
	Outcome     string `json:"outcome"` // allow | deny | escalate
	ReasonClass string `json:"reason_class"`
	ActionHash  string `json:"action_hash"`
	PolicyID    string `json:"policy_id"`
	AuditSeq    uint64 `json:"audit_seq"`
}

func (h *Handler) handleCoreCheck(w http.ResponseWriter, r *http.Request) {
	if h.coreEngine == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "core runtime not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRuntimeBodyBytes))
	if err != nil {
		api.JSONBadRequest(w, "failed to read request body")
		return
	}
	defer r.Body.Close()
	var req decide.Request
	if err := json.Unmarshal(body, &req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}
	// Identity comes from the credential, not the payload: when a
	// principal is authenticated it overwrites whatever the wire
	// claimed (spec/capability_token.md §3 — actor_id filled by auth
	// layer). Open mode leaves the wire value; the engine then
	// requires it to be a registered actor signing key.
	if pid := auth.PrincipalID(r); pid != "" {
		req.ActorID = pid
	}

	res := h.coreEngine.Evaluate(&req)

	// Write-ahead: the decision record must be durable before the
	// caller may act on it. An audit failure is a deny, not a
	// degraded pass (spec/audit_log.md).
	var auditSeq uint64
	if h.coreLog != nil {
		payload, _ := json.Marshal(map[string]any{
			"request":  req.RequestCanonical(),
			"outcome":  res.Outcome,
			"reason":   res.OpReason,
			"policy":   res.PolicyID,
			"action":   res.ActionHash,
			"actor":    req.ActorID,
			"ts":       time.Now().UTC(),
		})
		rec, aerr := h.coreLog.Append("decision", payload)
		if aerr != nil {
			api.JSONError(w, http.StatusServiceUnavailable,
				"audit write-ahead failed — action not authorized")
			return
		}
		auditSeq = rec.Seq
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(coreDecisionResponse{
		Outcome:     string(res.Outcome),
		ReasonClass: res.ReasonClass,
		ActionHash:  res.ActionHash,
		PolicyID:    res.PolicyID,
		AuditSeq:    auditSeq,
	})
}
