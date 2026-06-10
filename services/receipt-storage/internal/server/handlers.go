package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"ovara.services.receipt/internal/models"
	"ovara.services.receipt/internal/store"
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

func (h *Handlers) HandleReceipt(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/receipts" {
		switch r.Method {
		case http.MethodPost:
			h.archive(w, r)
		case http.MethodGet:
			h.list(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if path == "/v1/receipts/stats" && r.Method == http.MethodGet {
		h.stats(w, r)
		return
	}

	if strings.HasPrefix(path, "/v1/receipts/") {
		rest := strings.TrimPrefix(path, "/v1/receipts/")
		parts := strings.Split(rest, "/")

		if len(parts) == 2 && parts[1] == "verify" && r.Method == http.MethodGet {
			h.verify(w, r, parts[0])
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			h.get(w, r, parts[0])
			return
		}
	}

	writeErr(w, http.StatusNotFound, "not found")
}

type archiveRequest struct {
	DecisionID    string  `json:"decision_id"`
	GatewayID     string  `json:"gateway_id"`
	OrganizationID string `json:"organization_id"`
	ActionType    string  `json:"action_type"`
	Resource      string  `json:"resource"`
	Decision      string  `json:"decision"`
	AgentID       string  `json:"agent_id"`
	TrustScore    float64 `json:"trust_score"`
	Payload       string  `json:"payload"`
	Signature     string  `json:"signature"`
	IssuedAt      string  `json:"issued_at"`
}

func (h *Handlers) archive(w http.ResponseWriter, r *http.Request) {
	var req archiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.DecisionID == "" || req.GatewayID == "" || req.OrganizationID == "" {
		writeErr(w, http.StatusBadRequest, "decision_id, gateway_id, and organization_id are required")
		return
	}

	issuedAt := time.Now().UTC()
	if req.IssuedAt != "" {
		parsed, err := time.Parse(time.RFC3339, req.IssuedAt)
		if err == nil {
			issuedAt = parsed
		}
	}

	receipt := &models.Receipt{
		ID:             uuid.New().String(),
		DecisionID:     req.DecisionID,
		GatewayID:      req.GatewayID,
		OrganizationID: req.OrganizationID,
		ActionType:     req.ActionType,
		Resource:       req.Resource,
		Decision:       req.Decision,
		AgentID:        req.AgentID,
		TrustScore:     req.TrustScore,
		Payload:        req.Payload,
		Signature:      req.Signature,
		IssuedAt:       issuedAt,
		ArchivedAt:     time.Now().UTC(),
	}

	if err := h.Store.Archive(receipt); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, receipt)
}

func (h *Handlers) get(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}

	receipt, err := h.Store.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, receipt)
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.ListFilter{
		OrganizationID: q.Get("organization_id"),
		GatewayID:      q.Get("gateway_id"),
		Decision:       q.Get("decision"),
		ActionType:     q.Get("action_type"),
	}

	if v := q.Get("start_date"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartDate = t
		}
	}
	if v := q.Get("end_date"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndDate = t
		}
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
		"receipts": results,
		"count":    len(results),
	})
}

func (h *Handlers) verify(w http.ResponseWriter, r *http.Request, id string) {
	result, err := h.Store.Verify(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handlers) stats(w http.ResponseWriter, r *http.Request) {
	total := h.Store.Count()
	orgID := r.URL.Query().Get("organization_id")
	var orgCount int
	if orgID != "" {
		orgCount = h.Store.CountByOrg(orgID)
	}

	stats := map[string]any{
		"total": total,
	}
	if orgID != "" {
		stats["organization_id"] = orgID
		stats["organization_count"] = orgCount
	}

	writeJSON(w, http.StatusOK, stats)
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/v1/receipts", h.HandleReceipt)
	mux.HandleFunc("/v1/receipts/", h.HandleReceipt)
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
