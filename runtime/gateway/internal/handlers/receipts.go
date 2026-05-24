package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"ovara.runtime.gateway/internal/receipts"
)

type ReceiptHandler struct {
	store *receipts.InMemoryStore
}

func NewReceiptHandler(store *receipts.InMemoryStore) *ReceiptHandler {
	return &ReceiptHandler{store: store}
}

func (h *ReceiptHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/receipts/{id}", h.handleGet)
	mux.HandleFunc("GET /v1/receipts", h.handleList)
	mux.HandleFunc("GET /v1/receipts/decision/{decision_id}", h.handleListByDecision)
}

func (h *ReceiptHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "receipt id is required", http.StatusBadRequest)
		return
	}

	receipt, err := h.store.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("receipt not found: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipt)
}

func (h *ReceiptHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	decisionID := r.PathValue("decision_id")
	if decisionID == "" {
		http.Error(w, "decision_id is required", http.StatusBadRequest)
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
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var receipt map[string]any
	if err := json.Unmarshal(body, &receipt); err != nil {
		http.Error(w, fmt.Sprintf("invalid receipt: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}