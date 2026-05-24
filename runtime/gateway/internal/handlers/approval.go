package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/approval"
)

type ApprovalHandler struct {
	service *approval.Service
}

func NewApprovalHandler(s *approval.Service) *ApprovalHandler {
	return &ApprovalHandler{service: s}
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req approval.CreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.DecisionID == "" || req.ActionType == "" {
		http.Error(w, "decision_id and action_type are required", http.StatusBadRequest)
		return
	}

	created, err := h.service.CreateApproval(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create approval: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (h *ApprovalHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "approval id is required", http.StatusBadRequest)
		return
	}

	approval, err := h.service.GetApproval(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("approval not found: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(approval)
}

func (h *ApprovalHandler) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "approval id is required", http.StatusBadRequest)
		return
	}

	var body struct {
		ResolvedBy string `json:"resolved_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.ResolvedBy == "" {
		http.Error(w, "resolved_by is required", http.StatusBadRequest)
		return
	}

	updated, err := h.service.Approve(id, body.ResolvedBy)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to approve: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

func (h *ApprovalHandler) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "approval id is required", http.StatusBadRequest)
		return
	}

	var body struct {
		ResolvedBy string `json:"resolved_by"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.ResolvedBy == "" {
		http.Error(w, "resolved_by is required", http.StatusBadRequest)
		return
	}

	updated, err := h.service.Deny(id, body.ResolvedBy, body.Reason)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to deny: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

func (h *ApprovalHandler) handleListPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pending := h.service.ListPending()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"approvals": pending,
		"count":     len(pending),
	})
}

func (h *ApprovalHandler) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "approval id is required", http.StatusBadRequest)
		return
	}

	canResume, err := h.service.ResumeAction(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot resume: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"resumed": canResume,
	})
}