package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

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
	receiptsStore receipts.Store
	decisionCache *decisionCache
}

func New(e *evaluator.Evaluator, l *logging.DecisionLogger, cfg *config.Config, rs receipts.Store) *Handler {
	return &Handler{
		evaluator:     e,
		logger:        l,
		config:        cfg,
		receiptsStore: rs,
		decisionCache: newDecisionCache(),
	}
}

type HandlerWithStores struct {
	*Handler
	approvalStore interface {
		ListByStatus(status string) []*approvalRequest
	}
	shieldStats func() (restricted, total int)
}

type approvalRequest struct {
	ApprovalID string
	Status     string
}

const (
	defaultMaxCacheSize = 10000
	defaultCacheTTL     = 10 * time.Minute
)

type decisionCache struct {
	mu       sync.RWMutex
	decisions map[string]*decisionEntry
	maxSize   int
	ttl       time.Duration
	order     []string
}

type decisionEntry struct {
	DecisionID string
	Response   *models.DecisionResponse
	Timestamp  time.Time
}

func newDecisionCache() *decisionCache {
	return &decisionCache{
		decisions: make(map[string]*decisionEntry),
		maxSize:   defaultMaxCacheSize,
		ttl:       defaultCacheTTL,
		order:     make([]string, 0, defaultMaxCacheSize),
	}
}

func (c *decisionCache) Put(id string, resp *models.DecisionResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	if existing, ok := c.decisions[id]; ok {
		existing.Response = resp
		existing.Timestamp = now
		return
	}
	if len(c.decisions) >= c.maxSize {
		c.evictOldest()
	}
	c.decisions[id] = &decisionEntry{
		DecisionID: id,
		Response:   resp,
		Timestamp:  now,
	}
	c.order = append(c.order, id)
}

func (c *decisionCache) evictOldest() {
	if len(c.order) == 0 {
		return
	}
	oldest := c.order[0]
	c.order = c.order[1:]
	delete(c.decisions, oldest)
}

func (c *decisionCache) Get(id string) (*models.DecisionResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.decisions[id]; ok {
		if time.Since(e.Timestamp) > c.ttl {
			return nil, false
		}
		return e.Response, true
	}
	return nil, false
}

func (c *decisionCache) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			c.cleanup()
		}
	}()
}

func (c *decisionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	var validIDs []string
	for _, id := range c.order {
		if e, ok := c.decisions[id]; ok {
			if now.Sub(e.Timestamp) <= c.ttl {
				validIDs = append(validIDs, id)
			} else {
				delete(c.decisions, id)
			}
		}
	}
	c.order = validIDs
}

func (c *decisionCache) Stats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.decisions), c.maxSize
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/runtime/check", h.handleCheck)
	mux.HandleFunc("GET /v1/runtime/decision/{id}", h.handleGetDecision)
	mux.HandleFunc("GET /v1/runtime/agent/{agent_id}/recent", h.handleGetAgentRecentDecisions)
	mux.HandleFunc("GET /v1/runtime/status", h.handleGetStatus)
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

	if h.decisionCache != nil {
		h.decisionCache.Put(resp.DecisionID, resp)
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
		TrustLevel:   resp.TrustLevel,
		IssuedAt:     resp.ReceiptStub.IssuedAt,
	}
	if req.AgentIdentity != nil {
		receipt.AgentID = req.AgentIdentity.SubjectID
	}
	if req.CapabilityLease != nil {
		receipt.CapabilityLeaseID = req.CapabilityLease.LeaseID
	}
	if resp.ApprovalID != "" {
		receipt.ApprovalID = resp.ApprovalID
	}
	if resp.TrustContext != nil {
		receipt.ShieldActive = resp.TrustContext.ShieldActive
		receipt.Restricted = resp.TrustContext.Restricted
		receipt.RiskCount = resp.TrustContext.RiskCount
		receipt.AnomalySignals = resp.TrustContext.AnomalySignals
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

func (h *Handler) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "decision id is required", http.StatusBadRequest)
		return
	}

	if h.decisionCache != nil {
		if resp, ok := h.decisionCache.Get(id); ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	http.Error(w, "decision not found", http.StatusNotFound)
}

func (h *Handler) handleGetAgentRecentDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := r.PathValue("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}

	if h.decisionCache == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"decisions": []any{}, "count": 0})
		return
	}

	receipts := h.receiptsStore.ListByAgent(agentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"agent_id": agentID,
		"receipts": receipts,
		"count":    len(receipts),
	})
}

func (h *Handler) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cacheCount, cacheMax := 0, 0
	if h.decisionCache != nil {
		cacheCount, cacheMax = h.decisionCache.Stats()
	}

	receiptCount := 0
	if h.receiptsStore != nil {
		receiptCount = len(h.receiptsStore.ListAll())
	}

	policyVersion := ""
	if h.evaluator != nil {
		policyVersion = h.evaluator.PolicyVersion()
	}

	policySource := "in-memory"
	if h.config != nil && h.config.PolicyFile != "" {
		policySource = "file:" + h.config.PolicyFile
	}

	storageMode := "in-memory"
	if h.config != nil && h.config.ReceiptsFile != "" {
		storageMode = "file-backed"
	}

	status := map[string]any{
		"gateway_id":           h.config.GatewayID,
		"gateway_name":         h.config.GatewayName,
		"gateway_version":      h.config.GatewayVersion,
		"enrollment_status":    "local",
		"policy_version":       policyVersion,
		"policy_source":        policySource,
		"policy_refresh_secs":   h.config.PolicyRefreshInterval,
		"storage_mode":         storageMode,
		"decision_cache_count": cacheCount,
		"decision_cache_max":   cacheMax,
		"receipt_count":        receiptCount,
	}

	if h.config.PolicyRefreshInterval > 0 {
		status["hot_reload"] = "enabled"
	} else {
		status["hot_reload"] = "disabled"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (h *Handler) StartCacheCleanup(interval time.Duration) {
	if h.decisionCache != nil {
		h.decisionCache.StartCleanup(interval)
	}
}