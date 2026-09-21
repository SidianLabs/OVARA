// Revocation authority endpoints (P2.3.4). Operator-only by the auth
// model (the agent route scope does not include these paths — default
// deny). This is the network-plane counterpart of `gwctl revoke` for
// operators without filesystem access to the domain journal.
//
// Authority boundary: the endpoint writes to the domain journal —
// authenticated operator role is the authority (same as grant/deny/
// retire via gwctl file access). The actor recorded on the record is
// the AUTHENTICATED principal id, never a caller-supplied field.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/revocation"
)

type RevocationsHandler struct {
	registry   *gwidentity.Registry
	eventStore events.Store
	gatewayID  string
}

func NewRevocationsHandler(r *gwidentity.Registry) *RevocationsHandler {
	return &RevocationsHandler{registry: r}
}

func (h *RevocationsHandler) SetEventStore(es events.Store) { h.eventStore = es }
func (h *RevocationsHandler) SetGatewayID(id string)        { h.gatewayID = id }

func (h *RevocationsHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/revocations", h.handleRevoke)
	mux.HandleFunc("GET /v1/revocations", h.handleList)
	mux.HandleFunc("GET /v1/revocations/epoch", h.handleEpoch)
}

type revokeRequest struct {
	Class  string `json:"class"`  // issuer | delegation | lease
	Target string `json:"target"` // canonical id for the class
	Reason string `json:"reason,omitempty"`
}

func (h *RevocationsHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "revocation store is not configured")
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}
	switch revocation.Class(req.Class) {
	case revocation.ClassIssuer, revocation.ClassDelegation, revocation.ClassLease:
	default:
		api.JSONBadRequest(w, "class must be one of: issuer, delegation, lease")
		return
	}
	if req.Target == "" {
		api.JSONBadRequest(w, "target is required")
		return
	}
	// The actor is the authenticated principal — revocation authority is
	// never self-asserted.
	actor := auth.PrincipalID(r)
	if actor == "" {
		actor = "operator"
	}
	rv, err := h.registry.Revoke(req.Class, req.Target, actor, req.Reason)
	if err != nil {
		// Storage failure → 500, never a fake success.
		api.JSONInternalError(w, "durable revocation failed: "+err.Error())
		return
	}
	if h.eventStore != nil {
		evt := events.NewEvent("authority.revoked")
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"class":  rv.Class,
			"target": rv.Target,
			"actor":  actor,
			"reason": rv.Reason,
			"epoch":  rv.Seq,
		}
		h.eventStore.Append(evt)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "revoked",
		"class":   rv.Class,
		"target":  rv.Target,
		"actor":   actor,
		"epoch":   rv.Seq,
		"revoked": true,
	})
}

func (h *RevocationsHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "revocation store is not configured")
		return
	}
	recs, err := h.registry.Revocations()
	if err != nil {
		api.JSONInternalError(w, "revocation state unavailable: "+err.Error())
		return
	}
	ep, _ := h.registry.Epoch()
	out := make([]map[string]any, 0, len(recs))
	for _, rv := range recs {
		out = append(out, map[string]any{
			"class":      rv.Class,
			"target":     rv.Target,
			"actor":      rv.Actor,
			"reason":     rv.Reason,
			"revoked_at": rv.RevokedAt.Format(time.RFC3339),
			"epoch":      rv.Seq,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"revocations": out, "count": len(out), "epoch": ep})
}

func (h *RevocationsHandler) handleEpoch(w http.ResponseWriter, r *http.Request) {
	if h.registry == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "revocation store is not configured")
		return
	}
	ep, err := h.registry.Epoch()
	if err != nil {
		api.JSONInternalError(w, "revocation epoch unavailable: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"epoch": ep})
}
