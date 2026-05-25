package trust

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/models"
)

type Handler struct {
	shieldStore *ShieldStore
	trustEval  *Evaluator
}

func NewHandler(shieldStore *ShieldStore, trustEval *Evaluator) *Handler {
	return &Handler{shieldStore: shieldStore, trustEval: trustEval}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/trust/context", h.handleGetTrustContext)
	mux.HandleFunc("GET /v1/shield/status", h.handleShieldStatus)
	mux.HandleFunc("GET /v1/shield/status/{agent_id}", h.handleAgentShieldStatus)
	mux.HandleFunc("POST /v1/shield/restrict/{agent_id}", h.handleRestrict)
	mux.HandleFunc("POST /v1/shield/unrestrict/{agent_id}", h.handleUnrestrict)
}

func (h *Handler) handleGetTrustContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		api.JSONBadRequest(w, "agent_id is required")
		return
	}

	stats := h.shieldStore.GetStats(agentID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"agent_id":        agentID,
		"restricted":      stats.Restricted,
		"risk_count":      stats.RiskCount,
		"last_decision":   stats.LastDecision,
		"last_decision_at": stats.LastDecisionAt,
	})
}

func (h *Handler) handleShieldStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	restricted := h.shieldStore.GetAllRestricted()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"restricted_agents": restricted,
		"count":             len(restricted),
	})
}

func (h *Handler) handleAgentShieldStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}
	agentID := r.PathValue("agent_id")
	if agentID == "" {
		api.JSONBadRequest(w, "agent_id is required")
		return
	}

	stats := h.shieldStore.GetStats(agentID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"agent_id":        agentID,
		"restricted":     stats.Restricted,
		"risk_count":     stats.RiskCount,
		"last_decision":  stats.LastDecision,
		"last_decision_at": stats.LastDecisionAt,
	})
}

func (h *Handler) handleRestrict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	agentID := r.PathValue("agent_id")
	if agentID == "" {
		api.JSONBadRequest(w, "agent_id is required")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		body.Reason = "manual_restriction"
	}

	h.shieldStore.Restrict(agentID, body.Reason)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"agent_id":  agentID,
		"restricted": true,
		"reason":   body.Reason,
	})
}

func (h *Handler) handleUnrestrict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}
	agentID := r.PathValue("agent_id")
	if agentID == "" {
		api.JSONBadRequest(w, "agent_id is required")
		return
	}

	h.shieldStore.Unrestrict(agentID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"agent_id":   agentID,
		"restricted": false,
	})
}

func GenerateTrustContext(req *models.ActionRequest, store *ShieldStore) *models.TrustContext {
	eval := NewEvaluator(store)
	result := eval.Evaluate(req)

	signals := make([]models.AnomalySignal, len(result.AnomalySignals))
	copy(signals, result.AnomalySignals)

	return &models.TrustContext{
		Score:          result.Score,
		Level:          result.Level,
		AnomalySignals: signals,
		ShieldActive:   result.ShieldActive,
		Restricted:     result.Restricted,
		RiskCount:      result.RiskCount,
		EvaluationTime: time.Now().UTC(),
	}
}

func TrustContextToReasonCodes(tc *models.TrustContext) []models.ReasonCode {
	if tc == nil {
		return nil
	}
	var reasons []models.ReasonCode
	if tc.Restricted {
		reasons = append(reasons, models.ReasonContainmentActive)
	}
	if tc.Score < 0.5 {
		reasons = append(reasons, models.ReasonTrustLow)
	} else if tc.Score < 0.8 {
		reasons = append(reasons, models.ReasonTrustMedium)
	}
	for _, s := range tc.AnomalySignals {
		reasons = append(reasons, models.ReasonCode(s.Code))
	}
	return reasons
}

func buildTrustContext(req *models.ActionRequest, store *ShieldStore) *models.TrustContext {
	return GenerateTrustContext(req, store)
}

func createTrustDecisionID() string {
	return "trd_" + uuid.New().String()[:16]
}

func parseTrustLevel(level string) models.TrustLevel {
	switch strings.ToLower(level) {
	case "high":
		return models.TrustLevelHigh
	case "medium":
		return models.TrustLevelMedium
	case "low":
		return models.TrustLevelLow
	default:
		return models.TrustLevelNone
	}
}