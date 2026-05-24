package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipts"
)

type Handler struct {
	evaluator     *evaluator.Evaluator
	logger        *logging.DecisionLogger
	config        *config.Config
	receiptsStore *receipts.InMemoryStore
}

func New(e *evaluator.Evaluator, l *logging.DecisionLogger, cfg *config.Config, rs *receipts.InMemoryStore) *Handler {
	return &Handler{evaluator: e, logger: l, config: cfg, receiptsStore: rs}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/runtime/check", h.handleCheck)
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /ready", h.handleReady)
}

func (h *Handler) handleCheck(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req models.ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := h.evaluator.Evaluate(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("evaluation failed: %v", err), http.StatusInternalServerError)
		return
	}

	if h.logger != nil {
		_ = h.logger.Log(&req, resp)
	}

	if h.receiptsStore != nil && resp.ReceiptStub != nil {
		receipt := h.buildReceipt(resp, &req)
		_ = h.receiptsStore.Put(receipt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) buildReceipt(resp *models.DecisionResponse, req *models.ActionRequest) *models.Receipt {
	receipt := &models.Receipt{
		ReceiptID:    resp.ReceiptStub.ReceiptID,
		DecisionID:   resp.DecisionID,
		ActionDigest: resp.ReceiptStub.ActionDigest,
		ActionType:   resp.ReceiptStub.ActionType,
		Resource:     resp.ReceiptStub.Resource,
		Decision:     string(resp.Decision),
		PolicyVersion: resp.ReceiptStub.PolicyVersion,
		TrustScore:   resp.ReceiptStub.TrustContextScore,
		IssuedAt:     resp.ReceiptStub.IssuedAt,
	}
	if req.AgentIdentity != nil {
		receipt.AgentID = req.AgentIdentity.SubjectID
	}
	if resp.ApprovalID != "" {
		receipt.ApprovalID = resp.ApprovalID
	}
	receipt.Signature = "sig_v1_local:" + resp.ReceiptStub.ReceiptID
	return receipt
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}