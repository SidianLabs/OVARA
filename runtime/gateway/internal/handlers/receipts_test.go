package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipts"
)

func TestReceiptHandler_HandleGet(t *testing.T) {
	store := receipts.NewInMemoryStore()
	store.Put(&models.Receipt{
		ReceiptID:  "rcpt_test123",
		DecisionID: "dec_456",
		ActionType: "shell",
		Resource:   "shell:echo test",
		Decision:   "allow",
	})

	h := NewReceiptHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	t.Run("returns receipt when found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/receipts/rcpt_test123", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var receipt models.Receipt
		if err := json.NewDecoder(rec.Body).Decode(&receipt); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if receipt.ReceiptID != "rcpt_test123" {
			t.Errorf("receipt_id = %v, want rcpt_test123", receipt.ReceiptID)
		}
	})

	t.Run("returns 404 when not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/receipts/rcpt_notfound", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

func TestReceiptHandler_HandleList(t *testing.T) {
	store := receipts.NewInMemoryStore()
	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_2", ActionType: "git.push", Decision: "deny"})

	h := NewReceiptHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestReceiptHandler_HandleListByDecision(t *testing.T) {
	store := receipts.NewInMemoryStore()
	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_a", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_b", ActionType: "git.push", Decision: "deny"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_3", DecisionID: "dec_a", ActionType: "git.push", Decision: "escalate"})

	h := NewReceiptHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	t.Run("returns receipts for decision", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/receipts/decision/dec_a", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if result["decision_id"] != "dec_a" {
			t.Errorf("decision_id = %v, want dec_a", result["decision_id"])
		}
		if result["count"].(float64) != 2 {
			t.Errorf("count = %v, want 2", result["count"])
		}
	})

	t.Run("returns empty array not null for decision with no receipts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/receipts/decision/dec_nonexistent", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var result map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if result["count"].(float64) != 0 {
			t.Errorf("count = %v, want 0", result["count"])
		}
		receipts, ok := result["receipts"].([]any)
		if !ok {
			t.Errorf("receipts is not an array, got %T", result["receipts"])
		}
		if len(receipts) != 0 {
			t.Errorf("receipts length = %d, want 0", len(receipts))
		}
	})
}

func TestReceiptHandler_HandleGet_MethodNotAllowed(t *testing.T) {
	store := receipts.NewInMemoryStore()
	h := NewReceiptHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/receipts/rcpt_test123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestReceiptHandler_HandleList_MethodNotAllowed(t *testing.T) {
	store := receipts.NewInMemoryStore()
	h := NewReceiptHandler(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}