package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	JSONError(w, http.StatusBadRequest, "something went wrong")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %s, want application/json", ct)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp.Error != "something went wrong" {
		t.Errorf("error = %s, want 'something went wrong'", resp.Error)
	}
	if resp.Code != "" {
		t.Errorf("code = %s, want empty", resp.Code)
	}
}

func TestJSONErrorWithCode(t *testing.T) {
	w := httptest.NewRecorder()
	JSONErrorWithCode(w, http.StatusNotFound, "not found", "NOT_FOUND")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var resp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Code != "NOT_FOUND" {
		t.Errorf("code = %s, want NOT_FOUND", resp.Code)
	}
}

func TestJSONBadRequest(t *testing.T) {
	w := httptest.NewRecorder()
	JSONBadRequest(w, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestJSONNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	JSONNotFound(w, "resource not found")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestJSONInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	JSONInternalError(w, "internal error")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestJSONMethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	JSONMethodNotAllowed(w)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	var resp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != "method not allowed" {
		t.Errorf("error = %s, want 'method not allowed'", resp.Error)
	}
}

func TestJSONError_PreservesMessage(t *testing.T) {
	w := httptest.NewRecorder()
	JSONError(w, http.StatusInternalServerError, "evaluation failed: context deadline exceeded")

	var resp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != "evaluation failed: context deadline exceeded" {
		t.Errorf("error message was not preserved: %s", resp.Error)
	}
}

func TestJSONConflict(t *testing.T) {
	w := httptest.NewRecorder()
	JSONConflict(w, "state conflict")

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}

	var resp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != "state conflict" {
		t.Errorf("error = %s, want 'state conflict'", resp.Error)
	}
}

func TestJSONUnprocessableEntity(t *testing.T) {
	w := httptest.NewRecorder()
	JSONUnprocessableEntity(w, "validation failed")

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnprocessableEntity)
	}

	var resp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != "validation failed" {
		t.Errorf("error = %s, want 'validation failed'", resp.Error)
	}
}