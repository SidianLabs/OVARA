package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/receipts"
)

type ReceiptHandler struct {
	store    receipts.Store
	resolver receipt.KeyResolver
}

func NewReceiptHandler(store receipts.Store) *ReceiptHandler {
	return &ReceiptHandler{store: store}
}

// SetKeyResolver installs the authoritative historical-key resolver
// used by the verify endpoint. The resolver reads the gateway
// identity registry — a caller-supplied public key is never accepted
// as verification authority.
func (h *ReceiptHandler) SetKeyResolver(r receipt.KeyResolver) {
	h.resolver = r
}

func (h *ReceiptHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/receipts/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/receipts", h.handleList)
	mux.HandleFunc("GET /v1/receipts/decision/{decision_id}", h.handleListByDecision)
	mux.HandleFunc("POST /v1/receipts/verify", h.handleVerify)
}

func (h *ReceiptHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "receipt id is required")
		return
	}

	receipt, err := h.store.Get(id)
	if err != nil {
		api.JSONNotFound(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipt)
}

func (h *ReceiptHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	all := h.store.ListAll()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"receipts": all,
		"count":    len(all),
	})
}

func (h *ReceiptHandler) handleListByDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}
	decisionID := r.PathValue("decision_id")
	if decisionID == "" {
		api.JSONBadRequest(w, "decision_id is required")
		return
	}

	receipts := h.store.ListByDecision(decisionID)
	if receipts == nil {
		receipts = []*models.Receipt{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"decision_id": decisionID,
		"receipts":    receipts,
		"count":       len(receipts),
	})
}

// handleVerify is the independent-verification endpoint (P2.3.5):
// the caller submits a receipt and gets the verdict of Ed25519
// signature verification against the authoritative registry record
// for (gateway_id, gateway_key_id). Any key lifecycle state resolves
// — historical receipts signed under superseded/revoked keys remain
// cryptographically verifiable; that says nothing about CURRENT
// gateway authorization. No caller-supplied public key is accepted.
func (h *ReceiptHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRuntimeBodyBytes))
	if err != nil {
		api.JSONBadRequest(w, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var rcpt models.Receipt
	if err := json.Unmarshal(body, &rcpt); err != nil {
		api.JSONBadRequest(w, "invalid receipt: "+err.Error())
		return
	}
	valid, verr := receipt.VerifySignature(h.resolver, &rcpt)
	resp := map[string]any{
		"valid":          valid,
		"gateway_id":     rcpt.GatewayID,
		"gateway_key_id": rcpt.GatewayKeyID,
	}
	if verr != nil {
		resp["reason"] = verr.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
