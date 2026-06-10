package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ovara.services.alerting/internal/engine"
	"ovara.services.alerting/internal/models"
)

type Handlers struct {
	Engine *engine.Engine
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

func extractID(path, prefix string) string {
	id := strings.TrimPrefix(path, prefix)
	id = strings.TrimSuffix(id, "/acknowledge")
	id = strings.TrimSuffix(id, "/resolve")
	return id
}

func (h *Handlers) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/alerts" {
		switch r.Method {
		case http.MethodPost:
			h.ingest(w, r)
		case http.MethodGet:
			h.listAlerts(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if path == "/v1/alerts/ingest" && r.Method == http.MethodPost {
		h.ingest(w, r)
		return
	}

	if path == "/v1/alerts/stats" && r.Method == http.MethodGet {
		h.stats(w, r)
		return
	}

	if strings.HasPrefix(path, "/v1/alerts/") && !strings.HasPrefix(path, "/v1/alerts/rules") {
		id := extractID(path, "/v1/alerts/")

		if strings.HasSuffix(path, "/acknowledge") && r.Method == http.MethodPost {
			h.acknowledge(w, r, id)
			return
		}
		if strings.HasSuffix(path, "/resolve") && r.Method == http.MethodPost {
			h.resolve(w, r, id)
			return
		}
		if r.Method == http.MethodGet {
			h.getAlert(w, r, id)
			return
		}
	}

	writeErr(w, http.StatusNotFound, "not found")
}

func (h *Handlers) HandleRules(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/alerts/rules" {
		switch r.Method {
		case http.MethodGet:
			h.listRules(w, r)
		case http.MethodPost:
			h.createRule(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if strings.HasPrefix(path, "/v1/alerts/rules/") {
		id := strings.TrimPrefix(path, "/v1/alerts/rules/")
		switch r.Method {
		case http.MethodPut:
			h.updateRule(w, r, id)
		case http.MethodDelete:
			h.deleteRule(w, r, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	writeErr(w, http.StatusNotFound, "not found")
}

type ingestRequest struct {
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	AgentID        string  `json:"agent_id"`
	GatewayID      string  `json:"gateway_id"`
	OrganizationID string  `json:"organization_id"`
	Action         string  `json:"action"`
	Resource       string  `json:"resource"`
	TrustScore     float64 `json:"trust_score"`
	Message        string  `json:"message"`
}

func (h *Handlers) ingest(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Type == "" {
		writeErr(w, http.StatusBadRequest, "type is required")
		return
	}

	ev := engine.Event{
		Type:           models.AlertType(req.Type),
		Severity:       models.Severity(req.Severity),
		AgentID:        req.AgentID,
		GatewayID:      req.GatewayID,
		OrganizationID: req.OrganizationID,
		Action:         req.Action,
		Resource:       req.Resource,
		TrustScore:     req.TrustScore,
		Message:        req.Message,
	}

	if ev.Severity == "" {
		ev.Severity = models.SeverityMedium
	}

	alert, err := h.Engine.ProcessEvent(ev)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	ruleAlerts := h.Engine.EvaluateRules(ev)

	response := map[string]any{
		"alert": alert,
	}
	if len(ruleAlerts) > 0 {
		response["rule_alerts"] = ruleAlerts
	}

	writeJSON(w, http.StatusCreated, response)
}

func (h *Handlers) getAlert(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}

	alert, err := h.Engine.GetAlert(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (h *Handlers) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := models.AlertFilter{
		Severity:       models.Severity(q.Get("severity")),
		Type:           models.AlertType(q.Get("type")),
		State:          models.AlertState(q.Get("state")),
		AgentID:        q.Get("agent_id"),
		GatewayID:      q.Get("gateway_id"),
		OrganizationID: q.Get("organization_id"),
	}

	if v := q.Get("limit"); v != "" {
		filter.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		filter.Offset, _ = strconv.Atoi(v)
	}

	results, err := h.Engine.ListAlerts(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"alerts": results,
		"count":  len(results),
	})
}

type acknowledgeRequest struct {
	AcknowledgedBy string `json:"acknowledged_by"`
}

func (h *Handlers) acknowledge(w http.ResponseWriter, r *http.Request, id string) {
	var req acknowledgeRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	by := req.AcknowledgedBy
	if by == "" {
		by = "system"
	}

	alert, err := h.Engine.AcknowledgeAlert(id, by)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusConflict, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (h *Handlers) resolve(w http.ResponseWriter, r *http.Request, id string) {
	alert, err := h.Engine.ResolveAlert(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusConflict, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

type createRuleRequest struct {
	Name          string  `json:"name"`
	Condition     string  `json:"condition"`
	Threshold     float64 `json:"threshold"`
	WindowSeconds int     `json:"window_seconds"`
	Severity      string  `json:"severity"`
	Enabled       *bool   `json:"enabled"`
}

func (h *Handlers) createRule(w http.ResponseWriter, r *http.Request) {
	var req createRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" || req.Condition == "" {
		writeErr(w, http.StatusBadRequest, "name and condition are required")
		return
	}

	rule := &models.AlertRule{
		ID:            generateID(),
		Name:          req.Name,
		Condition:     models.ConditionType(req.Condition),
		Threshold:     req.Threshold,
		WindowSeconds: req.WindowSeconds,
		Severity:      models.Severity(req.Severity),
		Enabled:       req.Enabled == nil || *req.Enabled,
	}

	if rule.Severity == "" {
		rule.Severity = models.SeverityMedium
	}
	if rule.WindowSeconds <= 0 {
		rule.WindowSeconds = 300
	}

	if err := h.Engine.CreateRule(rule); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handlers) listRules(w http.ResponseWriter, r *http.Request) {
	rules := h.Engine.ListRules()
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"count": len(rules),
	})
}

type updateRuleRequest struct {
	Name          string   `json:"name"`
	Condition     string   `json:"condition"`
	Threshold     *float64 `json:"threshold"`
	WindowSeconds *int     `json:"window_seconds"`
	Severity      string   `json:"severity"`
	Enabled       *bool    `json:"enabled"`
}

func (h *Handlers) updateRule(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.Engine.GetRule(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	var req updateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Condition != "" {
		existing.Condition = models.ConditionType(req.Condition)
	}
	if req.Threshold != nil {
		existing.Threshold = *req.Threshold
	}
	if req.WindowSeconds != nil {
		existing.WindowSeconds = *req.WindowSeconds
	}
	if req.Severity != "" {
		existing.Severity = models.Severity(req.Severity)
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if err := h.Engine.UpdateRule(existing); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (h *Handlers) deleteRule(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Engine.DeleteRule(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, err.Error())
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (h *Handlers) stats(w http.ResponseWriter, r *http.Request) {
	counts := h.Engine.CountBySeverity()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":    h.Engine.Count(),
		"by_severity": counts,
	})
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/v1/alerts/rules", h.HandleRules)
	mux.HandleFunc("/v1/alerts/rules/", h.HandleRules)
	mux.HandleFunc("/v1/alerts", h.HandleAlerts)
	mux.HandleFunc("/v1/alerts/", h.HandleAlerts)
}

func NewServer(addr string, e *engine.Engine) *http.Server {
	h := &Handlers{Engine: e}
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
