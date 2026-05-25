package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/receipts"
)

type ReceiptHandler struct {
	store receipts.Store
}

func NewReceiptHandler(store receipts.Store) *ReceiptHandler {
	return &ReceiptHandler{store: store}
}

func (h *ReceiptHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/receipts/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/receipts", h.handleList)
	mux.HandleFunc("GET /v1/receipts/decision/{decision_id}", h.handleListByDecision)
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
		api.JSONNotFound(w, "receipt not found: "+err.Error())
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"decision_id": decisionID,
		"receipts":    receipts,
		"count":       len(receipts),
	})
}

func (h *ReceiptHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.JSONBadRequest(w, "failed to read body")
		return
	}
	defer r.Body.Close()

	var receipt map[string]any
	if err := json.Unmarshal(body, &receipt); err != nil {
		api.JSONBadRequest(w, "invalid receipt: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}