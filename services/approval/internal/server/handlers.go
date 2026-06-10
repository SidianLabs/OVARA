package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"ovara.services.approval/internal/models"
	"ovara.services.approval/internal/store"
)

type Handlers struct {
	Store store.Store
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func extractID(path, prefix string) string {
	id := strings.TrimPrefix(path, prefix)
	id = strings.TrimSuffix(id, "/approve")
	id = strings.TrimSuffix(id, "/deny")
	return id
}

func (h *Handlers) HandleApproval(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/approvals" {
		switch r.Method {
		case http.MethodPost:
			h.create(w, r)
		case http.MethodGet:
			h.list(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if path == "/v1/approvals/expire" && r.Method == http.MethodPost {
		h.expire(w, r)
		return
	}

	if path == "/v1/approvals/stats" && r.Method == http.MethodGet {
		h.stats(w, r)
		return
	}

	if strings.HasPrefix(path, "/v1/approvals/") {
		if strings.HasSuffix(path, "/approve") && r.Method == http.MethodPost {
			h.approve(w, r, extractID(path, "/v1/approvals/"))
			return
		}
		if strings.HasSuffix(path, "/deny") && r.Method == http.MethodPost {
			h.deny(w, r, extractID(path, "/v1/approvals/"))
			return
		}
		if r.Method == http.MethodGet {
			h.get(w, r, extractID(path, "/v1/approvals/"))
			return
		}
	}

	writeErr(w, http.StatusNotFound, "not found")
}

type createRequest struct {
	GatewayID   string `json:"gateway_id"`
	DecisionID  string `json:"decision_id"`
	ActionType  string `json:"action_type"`
	Resource    string `json:"resource"`
	AgentID     string `json:"agent_id"`
	RequestedBy string `json:"requested_by"`
	ExpiresIn   int    `json:"expires_in_seconds"`
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.GatewayID == "" || req.DecisionID == "" || req.RequestedBy == "" {
		writeErr(w, http.StatusBadRequest, "gateway_id, decision_id, and requested_by are required")
		return
	}

	expiresIn := time.Duration(req.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 10 * time.Minute
	}

	a := &models.Approval{
		ID:          uuid.New().String(),
		GatewayID:   req.GatewayID,
		DecisionID:  req.DecisionID,
		ActionType:  req.ActionType,
		Resource:    req.Resource,
		AgentID:     req.AgentID,
		RequestedBy: req.RequestedBy,
		State:       models.StatePending,
		ExpiresAt:   time.Now().UTC().Add(expiresIn),
		CreatedAt:   time.Now().UTC(),
	}

	if err := h.Store.Create(a); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, a)
}

func (h *Handlers) get(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}

	a, err := h.Store.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, a)
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.ListFilter{
		State:     models.ApprovalState(q.Get("state")),
		GatewayID: q.Get("gateway_id"),
		AgentID:   q.Get("agent_id"),
	}

	if v := q.Get("limit"); v != "" {
		filter.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		filter.Offset, _ = strconv.Atoi(v)
	}

	results, err := h.Store.List(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"approvals": results,
		"count":     len(results),
	})
}

func (h *Handlers) approve(w http.ResponseWriter, r *http.Request, id string) {
	h.resolve(w, r, id, models.StateApproved)
}

type denyRequest struct {
	Reason    string `json:"reason"`
	ResolvedBy string `json:"resolved_by"`
}

func (h *Handlers) deny(w http.ResponseWriter, r *http.Request, id string) {
	var req denyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = denyRequest{}
	}

	resolvedBy := req.ResolvedBy
	if resolvedBy == "" {
		resolvedBy = "system"
	}

	if err := h.Store.Resolve(id, models.StateDenied, resolvedBy, req.Reason); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusConflict, err.Error())
		}
		return
	}

	a, _ := h.Store.Get(id)
	writeJSON(w, http.StatusOK, a)
}

func (h *Handlers) resolve(w http.ResponseWriter, r *http.Request, id string, state models.ApprovalState) {
	var body struct {
		ResolvedBy string `json:"resolved_by"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	resolvedBy := body.ResolvedBy
	if resolvedBy == "" {
		resolvedBy = "system"
	}

	if err := h.Store.Resolve(id, state, resolvedBy, ""); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusConflict, err.Error())
		}
		return
	}

	a, _ := h.Store.Get(id)
	writeJSON(w, http.StatusOK, a)
}

type expireRequest struct {
	Before string `json:"before"`
}

func (h *Handlers) expire(w http.ResponseWriter, r *http.Request) {
	var req expireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var before time.Time
	if req.Before != "" {
		var err error
		before, err = time.Parse(time.RFC3339, req.Before)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid before time, use RFC3339")
			return
		}
	} else {
		before = time.Now().UTC().Add(-30 * time.Minute)
	}

	count, err := h.Store.ExpireOlderThan(before)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"expired": count,
	})
}

func (h *Handlers) stats(w http.ResponseWriter, r *http.Request) {
	count := h.Store.Count()
	writeJSON(w, http.StatusOK, map[string]any{
		"total": count,
	})
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/v1/approvals", h.HandleApproval)
	mux.HandleFunc("/v1/approvals/", h.HandleApproval)
}

func NewServer(addr string, s store.Store) *http.Server {
	h := &Handlers{Store: s}
	mux := http.NewServeMux()
	h.Register(mux)

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}


