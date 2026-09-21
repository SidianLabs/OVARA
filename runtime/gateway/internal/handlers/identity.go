// P2.2 identity + credential lifecycle endpoints.
//
// /v1/whoami — any authenticated credential resolves its own stable
// identity (agent-accessible; reveals only the caller's identity).
//
// Everything else is operator-only by the middleware role gate:
// register, rotate, revoke, suspend/resume/retire/migrate, list.
// Agents can never manage identities — registration is not an
// agent-reachable surface, so identity squatting/hijack requires an
// operator credential (already gateway-root in RC1).
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/idregistry"
)

type IdentityHandler struct {
	registry *idregistry.Registry
}

func NewIdentityHandler(reg *idregistry.Registry) *IdentityHandler {
	return &IdentityHandler{registry: reg}
}

func (h *IdentityHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/whoami", h.whoami)
	mux.HandleFunc("POST /v1/identities/register", h.register)
	mux.HandleFunc("POST /v1/identities/rotate", h.rotate)
	mux.HandleFunc("POST /v1/identities/status", h.transition)
	mux.HandleFunc("POST /v1/credentials/revoke", h.revoke)
	mux.HandleFunc("GET /v1/identities", h.list)
}


func jsonOK(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

func (h *IdentityHandler) whoami(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, http.StatusOK, map[string]any{
		"principal_id": auth.PrincipalID(r),
		"role":         auth.Principal(r),
	})
}

type registerReq struct {
	Role       string `json:"role"`        // "agent" | "operator"
	IdentityID string `json:"identity_id"` // optional hint
	Token      string `json:"token"`       // optional — generated if empty
	ExpiresAt  string `json:"expires_at"`  // optional RFC3339
}

func (h *IdentityHandler) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	if req.Role != "agent" && req.Role != "operator" {
		api.JSONBadRequest(w, "role must be \"agent\" or \"operator\"")
		return
	}
	var exp *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			api.JSONBadRequest(w, "expires_at must be RFC3339")
			return
		}
		exp = &t
	}
	id, tok, err := h.registry.Register(req.Role, req.IdentityID, req.Token, exp)
	if err != nil {
		api.JSONBadRequest(w, err.Error())
		return
	}
	resp := map[string]any{"identity_id": id}
	if req.Token == "" {
		resp["token"] = tok // returned once, only when server-generated
	}
	jsonOK(w, http.StatusCreated, resp)
}

type rotateReq struct {
	IdentityID  string `json:"identity_id"`
	NewToken    string `json:"new_token"`   // optional — generated if empty
	GraceSeconds int   `json:"grace_seconds"` // dual-valid window, default 300, max 24h
}

func (h *IdentityHandler) rotate(w http.ResponseWriter, r *http.Request) {
	var req rotateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	if req.IdentityID == "" {
		api.JSONBadRequest(w, "identity_id is required")
		return
	}
	tok, err := h.registry.Rotate(req.IdentityID, req.NewToken, req.GraceSeconds)
	if err != nil {
		api.JSONBadRequest(w, err.Error())
		return
	}
	resp := map[string]any{"identity_id": req.IdentityID}
	if req.NewToken == "" {
		resp["new_token"] = tok
	}
	jsonOK(w, http.StatusOK, resp)
}

type transitionReq struct {
	IdentityID string `json:"identity_id"`
	Action     string `json:"action"` // suspend|resume|retire|migrate
	MigratedTo string `json:"migrated_to"`
}

func (h *IdentityHandler) transition(w http.ResponseWriter, r *http.Request) {
	var req transitionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	if err := h.registry.Transition(req.IdentityID, req.Action, req.MigratedTo); err != nil {
		api.JSONBadRequest(w, err.Error())
		return
	}
	jsonOK(w, http.StatusOK, map[string]any{"identity_id": req.IdentityID, "action": req.Action})
}

type revokeReq struct {
	Token       string `json:"token"`       // raw token → fingerprinted server-side
	Fingerprint string `json:"fingerprint"` // or the sha256 fingerprint directly
}

func (h *IdentityHandler) revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body")
		return
	}
	fp := req.Fingerprint
	if fp == "" && req.Token != "" {
		fp = idregistry.Fingerprint(req.Token)
	}
	if fp == "" {
		api.JSONBadRequest(w, "token or fingerprint is required")
		return
	}
	if err := h.registry.Revoke(fp); err != nil {
		api.JSONBadRequest(w, err.Error())
		return
	}
	jsonOK(w, http.StatusOK, map[string]any{"revoked": true})
}

func (h *IdentityHandler) list(w http.ResponseWriter, r *http.Request) {
	ids, creds := h.registry.List()
	jsonOK(w, http.StatusOK, map[string]any{"identities": ids, "credentials": creds})
}
