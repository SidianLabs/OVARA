package api

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func JSONError(w http.ResponseWriter, code int, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg})
}

func JSONErrorWithCode(w http.ResponseWriter, code int, errMsg, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errMsg, Code: errCode})
}

func JSONBadRequest(w http.ResponseWriter, message string) {
	JSONError(w, http.StatusBadRequest, message)
}

func JSONNotFound(w http.ResponseWriter, message string) {
	JSONError(w, http.StatusNotFound, message)
}

func JSONInternalError(w http.ResponseWriter, message string) {
	JSONError(w, http.StatusInternalServerError, message)
}

func JSONMethodNotAllowed(w http.ResponseWriter) {
	JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func JSONConflict(w http.ResponseWriter, message string) {
	JSONError(w, http.StatusConflict, message)
}

func JSONUnprocessableEntity(w http.ResponseWriter, message string) {
	JSONError(w, http.StatusUnprocessableEntity, message)
}