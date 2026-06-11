package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/integrity"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/metrics"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/observe"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/receipts"
)

type Handler struct {
	evaluator          *evaluator.Evaluator
	logger             *logging.DecisionLogger
	config             *config.Config
	receiptsStore      receipts.Store
	receiptSigner      *receipt.Signer
	decisionCache      *decisionCache
	enrollmentSvc      enrollment.Service
	approvalSvc        *approval.Service
	eventStore         events.Store
	continuationStore  continuation.Store
	executionStore     execution.Store
	orchestrator       *continuation.Orchestrator
	integrityChecker   *integrity.Checker
	shieldStats        func() (restricted, total int)
	maintenanceMode    bool
	capabilitiesStore  capabilities.Store
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

func (h *Handler) SetEnrollment(svc enrollment.Service) {
	h.enrollmentSvc = svc
}

func (h *Handler) SetApprovalStats(svc *approval.Service) {
	h.approvalSvc = svc
}

func (h *Handler) SetShieldStats(fn func() (restricted, total int)) {
	h.shieldStats = fn
}

func (h *Handler) SetEventStore(store events.Store) {
	h.eventStore = store
}

func (h *Handler) SetApprovalService(svc *approval.Service) {
	h.approvalSvc = svc
}

func (h *Handler) SetContinuationStore(store continuation.Store) {
	h.continuationStore = store
}

func (h *Handler) SetExecutionStore(store execution.Store) {
	h.executionStore = store
}

func (h *Handler) SetOrchestrator(orch *continuation.Orchestrator) {
	h.orchestrator = orch
}

func (h *Handler) SetIntegrityChecker(checker *integrity.Checker) {
	h.integrityChecker = checker
}

func (h *Handler) SetMaintenanceMode(enabled bool) {
	h.maintenanceMode = enabled
}

func (h *Handler) SetReceiptSigner(signer *receipt.Signer) {
	h.receiptSigner = signer
}

func (h *Handler) SetCapabilitiesStore(store capabilities.Store) {
	h.capabilitiesStore = store
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
	mux.HandleFunc("POST /v1/runtime/batch-check", h.handleBatchCheck)
	mux.HandleFunc("GET /v1/runtime/decision/{id}", h.handleGetDecision)
	mux.HandleFunc("GET /v1/runtime/agent/{agent_id}/recent", h.handleGetAgentRecentDecisions)
	mux.HandleFunc("GET /v1/runtime/status", h.handleGetStatus)
	mux.HandleFunc("GET /v1/runtime/metrics", h.handleGetMetrics)
	mux.HandleFunc("GET /v1/runtime/integrity", h.handleIntegrity)
	mux.HandleFunc("GET /v1/runtime/snapshot", h.handleSnapshot)
	mux.HandleFunc("GET /v1/runtime/trace", h.handleTrace)
	mux.HandleFunc("GET /v1/runtime/summary", h.handleSummary)
	mux.HandleFunc("GET /v1/runtime/health", h.handleGetHealth)
	mux.HandleFunc("GET /v1/audit/export", h.handleAuditExport)
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /ready", h.handleReady)
}

func (h *Handler) handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	ctx, span := observe.StartDecisionSpan(r.Context(), nil)
	defer func() {
		if span != nil {
			observe.AddSpanAttribute(span, "http.method", r.Method)
			observe.AddSpanAttribute(span, "http.path", r.URL.Path)
		}
	}()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if span != nil {
			observe.AddSpanEvent(span, "request.read_failed", map[string]string{"error": err.Error()})
		}
		api.JSONBadRequest(w, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req models.ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		if span != nil {
			observe.AddSpanEvent(span, "request.parse_failed", map[string]string{"error": err.Error()})
		}
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	ctx, span = observe.StartDecisionSpan(ctx, &req)

	resp, err := h.evaluator.Evaluate(&req)
	if err != nil {
		if span != nil {
			observe.AddSpanEvent(span, "evaluation.failed", map[string]string{"error": err.Error()})
			observe.EndSpan(span, models.DecisionDeny)
		}
		api.JSONInternalError(w, "evaluation failed: "+err.Error())
		return
	}

	observe.EndSpan(span, resp.Decision)

	latencyMs := time.Since(start).Milliseconds()

	if h.logger != nil {
		_ = h.logger.Log(&req, resp, latencyMs)
	}

	if h.receiptsStore != nil && resp.ReceiptStub != nil {
		receipt := h.buildReceipt(resp, &req)
		_ = h.receiptsStore.Put(receipt)

		if h.eventStore != nil {
			var agentID string
			if req.AgentIdentity != nil {
				agentID = req.AgentIdentity.SubjectID
			}
			gwID := ""
			if h.enrollmentSvc != nil && h.enrollmentSvc.GetIdentity() != nil {
				gwID = h.enrollmentSvc.GetIdentity().ID
			}

			evt := events.NewEvent(events.EventTypeDecisionEvaluated).
				WithGatewayID(gwID).
				WithAgentID(agentID).
				WithDecisionID(resp.DecisionID).
				WithReceiptID(resp.ReceiptStub.ReceiptID).
				WithPayload(map[string]any{
					"action_type":  string(req.ActionType),
					"resource":      req.Resource,
					"decision":      string(resp.Decision),
					"trust_score":   resp.TrustScore,
					"trust_level":   resp.TrustLevel,
					"requires_approval": resp.RequiresApproval,
					"latency_ms":    latencyMs,
				})
			h.eventStore.Append(evt)

			receiptEvt := events.NewEvent(events.EventTypeReceiptIssued).
				WithGatewayID(gwID).
				WithAgentID(agentID).
				WithDecisionID(resp.DecisionID).
				WithReceiptID(resp.ReceiptStub.ReceiptID).
				WithPayload(map[string]any{
					"action_type":   string(req.ActionType),
					"resource":       req.Resource,
					"decision":       string(resp.Decision),
					"policy_version": resp.ReceiptStub.PolicyVersion,
				})
			h.eventStore.Append(receiptEvt)
		}
	}

	if h.decisionCache != nil {
		h.decisionCache.Put(resp.DecisionID, resp)
	}

	metrics.RecordDecision(string(resp.Decision), string(req.ActionType), latencyMs)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Trace-ID", span.TraceID)
	w.Header().Set("X-Span-ID", span.SpanID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleBatchCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.JSONBadRequest(w, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var reqBody struct {
		Requests []models.ActionRequest `json:"requests"`
	}
	if err := json.Unmarshal(body, &reqBody); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if reqBody.Requests == nil {
		reqBody.Requests = []models.ActionRequest{}
	}

	decisions := make([]*models.DecisionResponse, 0, len(reqBody.Requests))
	for i := range reqBody.Requests {
		req :=&reqBody.Requests[i]
		resp, err := h.evaluator.Evaluate(req)
		if err != nil {
			resp = &models.DecisionResponse{
				Decision: models.DecisionDeny,
				ReasonCodes: []models.ReasonCode{models.ReasonDeny},
			}
		}
		decisions = append(decisions, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"decisions": decisions})
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
	if h.receiptSigner != nil {
		receipt.Signature = h.receiptSigner.Sign(receipt)
	}
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
		api.JSONMethodNotAllowed(w)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		api.JSONBadRequest(w, "decision id is required")
		return
	}

	if h.decisionCache != nil {
		if resp, ok := h.decisionCache.Get(id); ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	api.JSONNotFound(w, "decision not found")
}

func (h *Handler) handleGetAgentRecentDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}
	agentID := r.PathValue("agent_id")
	if agentID == "" {
		api.JSONBadRequest(w, "agent_id is required")
		return
	}

	if h.decisionCache == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"agent_id": agentID, "receipts": []any{}, "count": 0})
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
		api.JSONMethodNotAllowed(w)
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
		"gateway_version":       h.config.GatewayVersion,
		"policy_version":        policyVersion,
		"policy_source":         policySource,
		"policy_refresh_secs":   h.config.PolicyRefreshInterval,
		"storage_mode":          storageMode,
		"decision_cache_count":  cacheCount,
		"decision_cache_max":    cacheMax,
		"receipt_count":         receiptCount,
		"enrollment_file":       h.config.EnrollmentFile,
	}

	if h.config.PolicyRefreshInterval > 0 {
		status["hot_reload"] = "enabled"
	} else {
		status["hot_reload"] = "disabled"
	}

	if h.enrollmentSvc != nil {
		identity := h.enrollmentSvc.GetIdentity()
		enrollStatus := h.enrollmentSvc.GetStatus()
		status["gateway_id"] = identity.ID
		status["gateway_name"] = identity.Name
		status["enrollment_state"] = identity.EnrollmentState
		status["environment"] = identity.Environment
		status["registered_at"] = identity.RegisteredAt
		status["last_seen_at"] = identity.LastSeenAt
		status["gateway_version"] = identity.Version
		if enrollStatus != nil {
			status["enrollment_healthy"] = enrollStatus.IsHealthy
			if !identity.LastSeenAt.IsZero() {
				status["last_seen_age_secs"] = time.Since(identity.LastSeenAt).Seconds()
			}
		}
	} else {
		status["gateway_id"] = h.config.GatewayID
		status["gateway_name"] = h.config.GatewayName
		status["enrollment_state"] = "local"
	}

	if h.approvalSvc != nil {
		pending := h.approvalSvc.ListPending()
		approved := h.approvalSvc.ListByStatus(approval.StatusApproved)
		denied := h.approvalSvc.ListByStatus(approval.StatusDenied)
		approvalStats := map[string]any{
			"pending":  len(pending),
			"approved": len(approved),
			"denied":   len(denied),
		}
		if len(pending) > 0 {
			var oldest time.Time
			for _, a := range pending {
				if oldest.IsZero() || a.CreatedAt.Before(oldest) {
					oldest = a.CreatedAt
				}
			}
			approvalStats["oldest_pending_at"] = oldest
		}
		status["approvals"] = approvalStats
	}

	if h.shieldStats != nil {
		restricted, total := h.shieldStats()
		status["shield_restricted_agents"] = restricted
		status["shield_total_agents"] = total
	}

	if h.executionStore != nil {
		total, succeeded, failed, running, timedOut := h.executionStore.Stats()
		execStats := map[string]any{
			"total": total, "succeeded": succeeded, "failed": failed,
			"running": running, "timed_out": timedOut,
		}
		if h.config != nil {
			execStats["storage_mode"] = "in_memory"
		}
		status["executions"] = execStats
	}

	if h.eventStore != nil {
		eventStats := map[string]any{"count": h.eventStore.Count()}
		if h.config != nil {
			eventStats["storage_mode"] = "in_memory"
		}
		if fb, ok := h.eventStore.(*events.FileBackedStore); ok {
			eventStats["storage_mode"] = "file_backed"
			eventStats["retention_days"] = fb.RetentionDays()
			eventStats["max_records"] = fb.MaxRecords()
			eventStats["current_count"] = fb.CurrentCount()
			eventStats["file_path"] = fb.FilePath()
			if size, err := fb.FileSizeBytes(); err == nil {
				eventStats["file_size_bytes"] = size
			}
		}
		status["events"] = eventStats
	}

	if h.continuationStore != nil {
		all := h.continuationStore.ListAll()
		stateCounts := make(map[string]int)
		var executableCount, retryableCount, executingCount int
		var oldestExecutable, oldestRetryable, oldestExecuting time.Time
		for _, c := range all {
			stateCounts[string(c.State)]++
			if c.IsExecutable() {
				executableCount++
				if oldestExecutable.IsZero() || c.CreatedAt.Before(oldestExecutable) {
					oldestExecutable = c.CreatedAt
				}
			}
			if c.CanRetry() {
				retryableCount++
				if oldestRetryable.IsZero() || c.CreatedAt.Before(oldestRetryable) {
					oldestRetryable = c.CreatedAt
				}
			}
			if c.State == continuation.StateExecuting {
				executingCount++
				if oldestExecuting.IsZero() || c.CreatedAt.Before(oldestExecuting) {
					oldestExecuting = c.CreatedAt
				}
			}
		}
		contStats := map[string]any{
			"count":       len(all),
			"by_state":    stateCounts,
			"executable":  executableCount,
			"retryable":   retryableCount,
			"executing":   executingCount,
		}
		if executableCount > 0 {
			contStats["oldest_executable_at"] = oldestExecutable
		}
		if retryableCount > 0 {
			contStats["oldest_retryable_at"] = oldestRetryable
		}
		if executingCount > 0 {
			contStats["oldest_executing_at"] = oldestExecuting
		}
		if fb, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
			contStats["storage_mode"] = "file_backed"
			contStats["retention_days"] = fb.RetentionDays()
			contStats["max_records"] = fb.MaxRecords()
			contStats["current_count"] = fb.CurrentCount()
			contStats["file_path"] = fb.FilePath()
			if size, err := fb.FileSizeBytes(); err == nil {
				contStats["file_size_bytes"] = size
			}
		} else {
			contStats["storage_mode"] = "in_memory"
		}
		status["continuations"] = contStats
	}

	if h.orchestrator != nil {
		status["queue_paused"] = h.orchestrator.IsPaused()
		queued, running := h.orchestrator.QueueStats()
		status["queue_stats"] = map[string]int{
			"queued":   queued,
			"running": running,
		}
		executing := h.orchestrator.ExecutingCount()
		status["executing"] = executing
		if executing > 0 {
			if oldest := h.orchestrator.OldestExecutingAt(); !oldest.IsZero() {
				status["oldest_executing_at"] = oldest
			}
		}
	}

	status["maintenance_mode"] = h.maintenanceMode

	h.addSLABreaches(status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (h *Handler) handleGetHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	status := map[string]any{}

	h.addSLABreaches(status)

	status["maintenance_mode"] = h.maintenanceMode

	if h.orchestrator != nil {
		status["queue_paused"] = h.orchestrator.IsPaused()
	}

	health := map[string]any{
		"healthy": true,
		"sla":     status["sla"],
	}
	if status["maintenance_mode"] == true {
		health["healthy"] = false
		health["reason"] = "maintenance_mode"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (h *Handler) addSLABreaches(status map[string]any) {
	if h.config == nil {
		return
	}

	var approvalBreachCount int
	var retryableBreachCount int
	var executingBreachCount int

	approvalThreshold := h.config.SLAApprovalMaxAgeMin
	if approvalThreshold <= 0 {
		approvalThreshold = h.config.SLAPendingApprovalMaxAgeMin
	}
	if approvalThreshold <= 0 {
		approvalThreshold = 30
	}
	approvalDuration := time.Duration(approvalThreshold) * time.Minute

	retryableThreshold := h.config.SLARetryableMaxAgeMin
	if retryableThreshold <= 0 {
		retryableThreshold = 60
	}
	retryableDuration := time.Duration(retryableThreshold) * time.Minute

	executingThreshold := h.config.SLAExecutingMaxAgeMin
	if executingThreshold <= 0 {
		executingThreshold = 5
	}
	executingDuration := time.Duration(executingThreshold) * time.Minute

	now := time.Now().UTC()

	if h.approvalSvc != nil {
		pending := h.approvalSvc.ListPending()
		for _, a := range pending {
			if now.Sub(a.CreatedAt) > approvalDuration {
				approvalBreachCount++
			}
		}
	}

	if h.continuationStore != nil {
		all := h.continuationStore.ListAll()
		for _, c := range all {
			if c.CanRetry() && now.Sub(c.CreatedAt) > retryableDuration {
				retryableBreachCount++
			}
			if c.State == continuation.StateExecuting && now.Sub(c.CreatedAt) > executingDuration {
				executingBreachCount++
			}
		}
	}

	status["sla"] = map[string]any{
		"approvals_breaching":    approvalBreachCount,
		"retryable_breaching":    retryableBreachCount,
		"executing_breaching":    executingBreachCount,
		"approval_threshold_min": approvalThreshold,
		"retryable_threshold_min": retryableThreshold,
		"executing_threshold_min": executingThreshold,
	}
}

func (h *Handler) handleIntegrity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	if h.integrityChecker == nil {
		api.JSONBadRequest(w, "integrity checker not configured")
		return
	}

	result := h.integrityChecker.Check()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	snap := metrics.Global().Snapshot()

	var eventStats, contStats, execStats map[string]any

	if h.eventStore != nil {
		eventCount := h.eventStore.Count()
		if fb, ok := h.eventStore.(*events.FileBackedStore); ok {
			eventStats = map[string]any{
				"count":            fb.CurrentCount(),
				"storage_mode":     "file_backed",
				"retention_days":   fb.RetentionDays(),
				"max_records":      fb.MaxRecords(),
				"file_path":       fb.FilePath(),
			}
			if size, err := fb.FileSizeBytes(); err == nil {
				eventStats["file_size_bytes"] = size
			}
		} else {
			eventStats = map[string]any{"count": eventCount, "storage_mode": "in_memory"}
		}
	}

	if h.continuationStore != nil {
		allConts := h.continuationStore.ListAll()
		stateCounts := make(map[string]int)
		for _, c := range allConts {
			stateCounts[string(c.State)]++
		}
		if fb, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
			contStats = map[string]any{
				"count":            len(allConts),
				"storage_mode":     "file_backed",
				"retention_days":   fb.RetentionDays(),
				"max_records":      fb.MaxRecords(),
				"file_path":       fb.FilePath(),
				"by_state":        stateCounts,
			}
			if size, err := fb.FileSizeBytes(); err == nil {
				contStats["file_size_bytes"] = size
			}
		} else {
			contStats = map[string]any{"count": len(allConts), "storage_mode": "in_memory", "by_state": stateCounts}
		}
	}

	if h.executionStore != nil {
		total, succeeded, failed, running, timedOut := h.executionStore.Stats()
		execStats = map[string]any{
			"total":      total,
			"succeeded":  succeeded,
			"failed":     failed,
			"running":    running,
			"timed_out":  timedOut,
		}
		if fb, ok := h.executionStore.(*execution.FileBackedStore); ok {
			execStats["storage_mode"] = "file_backed"
			execStats["retention_days"] = fb.RetentionDays()
			execStats["max_records"] = fb.MaxRecords()
			execStats["file_path"] = fb.FilePath()
		} else {
			execStats["storage_mode"] = "in_memory"
		}
	}

	gatewayID := ""
	gatewayName := ""
	enrollmentState := "local"
	if h.enrollmentSvc != nil {
		gatewayID = h.enrollmentSvc.GetIdentity().ID
		gatewayName = h.enrollmentSvc.GetIdentity().Name
		enrollmentState = string(h.enrollmentSvc.GetIdentity().EnrollmentState)
	}

	cacheCount, cacheMax := h.decisionCache.Stats()

	retentionConfig := make(map[string]any)
	if fb, ok := h.eventStore.(*events.FileBackedStore); ok {
		retentionConfig["events"] = map[string]any{
			"retention_days": fb.RetentionDays(),
			"max_records":    fb.MaxRecords(),
		}
	}
	if fb, ok := h.continuationStore.(*continuation.FileBackedStore); ok {
		retentionConfig["continuations"] = map[string]any{
			"retention_days": fb.RetentionDays(),
			"max_records":    fb.MaxRecords(),
		}
	}
	if fb, ok := h.executionStore.(*execution.FileBackedStore); ok {
		retentionConfig["executions"] = map[string]any{
			"retention_days": fb.RetentionDays(),
			"max_records":    fb.MaxRecords(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"snapshot_at":           time.Now().UTC(),
		"gateway_id":           gatewayID,
		"gateway_name":         gatewayName,
		"enrollment_state":     enrollmentState,
		"policy_version":      h.evaluator.PolicyVersion(),
		"decision_cache_count": cacheCount,
		"decision_cache_max":   cacheMax,
		"total_decisions":     snap.TotalDecisions,
		"retention_config":    retentionConfig,
		"events":              eventStats,
		"continuations":       contStats,
		"executions":          execStats,
		"metrics": map[string]any{
			"decision_counts": snap.DecisionCounts,
			"action_counts":  snap.ActionCounts,
			"avg_latency_ms": snap.AvgLatencyMs,
		},
	})
}

func (h *Handler) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	snap := metrics.Global().Snapshot()

	policyVersion := ""
	if h.evaluator != nil {
		policyVersion = h.evaluator.PolicyVersion()
	}

	policySource := "in-memory"
	if h.config != nil && h.config.PolicyFile != "" {
		policySource = "file:" + h.config.PolicyFile
	}

	response := map[string]any{
		"decision_counts":   snap.DecisionCounts,
		"action_counts":      snap.ActionCounts,
		"total_decisions":    snap.TotalDecisions,
		"avg_latency_ms":     snap.AvgLatencyMs,
		"last_latency_ms":    snap.LastLatencyMs,
		"last_decision_at":   snap.LastDecisionAt,
		"approval_counts":    snap.ApprovalCounts,
		"heartbeat_count":    snap.HeartbeatCount,
		"last_heartbeat_at":  snap.LastHeartbeatAt,
		"policy_version":      policyVersion,
		"policy_source":       policySource,
		"policy_reload_status": snap.PolicyReloadStatus,
		"policy_reload_last":   snap.PolicyReloadLastAt,
		"policy_reload_err":    snap.PolicyReloadErrMsg,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	limit := 10000
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if l, err := strconv.Atoi(ls); err == nil && l > 0 {
			limit = l
			if limit > 100000 {
				limit = 100000
			}
		}
	}

	gatewayID := r.URL.Query().Get("gateway_id")

	var since, until *time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = &t
		}
	}
	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = &t
		}
	}

	var exportedEvents []*events.Event
	if h.eventStore != nil {
		allEvents := h.eventStore.List(limit)
		for _, e := range allEvents {
			if gatewayID != "" && e.GatewayID != gatewayID {
				continue
			}
			if since != nil && e.Timestamp.Before(*since) {
				continue
			}
			if until != nil && e.Timestamp.After(*until) {
				continue
			}
			exportedEvents = append(exportedEvents, e)
		}
	}

	var exportedExecs []*execution.Execution
	if h.executionStore != nil {
		allExecs := h.executionStore.ListAll()
		for _, e := range allExecs {
			if since != nil && e.StartedAt.Before(*since) {
				continue
			}
			if until != nil && e.StartedAt.After(*until) {
				continue
			}
			exportedExecs = append(exportedExecs, e)
			if len(exportedExecs) >= limit {
				break
			}
		}
	}

	var exportedConts []*continuation.Continuation
	if h.continuationStore != nil {
		allConts := h.continuationStore.ListAll()
		for _, c := range allConts {
			if since != nil && c.CreatedAt.Before(*since) {
				continue
			}
			if until != nil && c.CreatedAt.After(*until) {
				continue
			}
			exportedConts = append(exportedConts, c)
			if len(exportedConts) >= limit {
				break
			}
		}
	}

	eventTypeCounts := make(map[string]int)
	for _, e := range exportedEvents {
		eventTypeCounts[e.EventType]++
	}

	execTotal, execSucceeded, execFailed, execRunning, execTimedOut := 0, 0, 0, 0, 0
	if h.executionStore != nil {
		execTotal, execSucceeded, execFailed, execRunning, execTimedOut = h.executionStore.Stats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"exported_at":        time.Now().UTC(),
		"gateway_id":         gatewayID,
		"time_range_since":   since,
		"time_range_until":  until,
		"event_count":       len(exportedEvents),
		"execution_count":   len(exportedExecs),
		"continuation_count": len(exportedConts),
		"event_types":         eventTypeCounts,
		"execution_stats": map[string]int{
			"total": execTotal, "succeeded": execSucceeded,
			"failed": execFailed, "running": execRunning, "timed_out": execTimedOut,
		},
		"events":        exportedEvents,
		"executions":    exportedExecs,
		"continuations": exportedConts,
	})
}

func (h *Handler) StartCacheCleanup(interval time.Duration) {
	if h.decisionCache != nil {
		h.decisionCache.StartCleanup(interval)
	}
}

type TraceResponse struct {
	Decision     *models.DecisionResponse `json:"decision,omitempty"`
	Receipt      *models.Receipt          `json:"receipt,omitempty"`
	Continuations []*continuation.Continuation `json:"continuations,omitempty"`
	Approvals    []*approval.ApprovalRequest  `json:"approvals,omitempty"`
	Executions   []*execution.Execution        `json:"executions,omitempty"`
	Events       []*events.Event               `json:"events,omitempty"`
	Capabilities  []*capabilities.TrackedLease  `json:"capabilities,omitempty"`
}

func (h *Handler) handleTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	decisionID := r.URL.Query().Get("decision_id")
	continuationID := r.URL.Query().Get("continuation_id")
	executionID := r.URL.Query().Get("execution_id")
	approvalID := r.URL.Query().Get("approval_id")
	receiptID := r.URL.Query().Get("receipt_id")

	if decisionID == "" && continuationID == "" && executionID == "" && approvalID == "" && receiptID == "" {
		api.JSONBadRequest(w, "at least one of decision_id, continuation_id, execution_id, approval_id, or receipt_id is required")
		return
	}

	var decision *models.DecisionResponse
	var receipt *models.Receipt
	var continuations []*continuation.Continuation
	var approvals []*approval.ApprovalRequest
	var executions []*execution.Execution
	var evts []*events.Event
	var caps []*capabilities.TrackedLease

	if decisionID != "" {
		h.decisionCache.mu.RLock()
		if cached, ok := h.decisionCache.decisions[decisionID]; ok {
			decision = cached.Response
		}
		h.decisionCache.mu.RUnlock()

		if h.receiptsStore != nil {
			if rcp, err := h.receiptsStore.Get(decisionID); err == nil {
				receipt = rcp
			}
		}

		if h.continuationStore != nil {
			continuations = h.continuationStore.ListByDecision(decisionID)
		}

		if h.approvalSvc != nil {
			approvals = h.approvalSvc.ListByDecision(decisionID)
		}

		if h.executionStore != nil {
			executions = h.executionStore.ListByDecision(decisionID)
		}
	}

	if continuationID != "" {
		if h.continuationStore != nil {
			if cnt, found := h.continuationStore.Get(continuationID); found {
				continuations = append(continuations, cnt)
			}
		}
		if h.executionStore != nil {
			executions = append(executions, h.executionStore.ListByContinuation(continuationID)...)
		}
	}

	if executionID != "" {
		if h.executionStore != nil {
			if exe, found := h.executionStore.Get(executionID); found {
				executions = append(executions, exe)
			}
		}
	}

	if approvalID != "" {
		if h.approvalSvc != nil {
			if apr, err := h.approvalSvc.GetApproval(approvalID); err == nil {
				approvals = append(approvals, apr)
			}
		}
	}

	if receiptID != "" {
		if h.receiptsStore != nil {
			if rcp, err := h.receiptsStore.Get(receiptID); err == nil {
				receipt = rcp
			}
		}
	}

	if h.eventStore != nil {
		allEvents := h.eventStore.List(500)
		for _, e := range allEvents {
			if decisionID != "" && e.DecisionID == decisionID {
				evts = append(evts, e)
				continue
			}
			if continuationID != "" && e.ContinuationID == continuationID {
				evts = append(evts, e)
				continue
			}
			if approvalID != "" && e.ApprovalID == approvalID {
				evts = append(evts, e)
				continue
			}
			if receiptID != "" && e.ReceiptID == receiptID {
				evts = append(evts, e)
				continue
			}
			for _, exe := range executions {
				if exe != nil && e.ContinuationID == exe.ContinuationID {
					evts = append(evts, e)
					break
				}
			}
		}
	}

	if receipt != nil && receipt.CapabilityLeaseID != "" && h.capabilitiesStore != nil {
		if tracked, ok := h.capabilitiesStore.Get(receipt.CapabilityLeaseID); ok {
			caps = append(caps, tracked)
		}
	}

	if h.capabilitiesStore != nil {
		for _, cnt := range continuations {
			if cnt != nil && cnt.CapabilityRef != "" {
				if tracked, ok := h.capabilitiesStore.Get(cnt.CapabilityRef); ok {
					found := false
					for _, c := range caps {
						if c.Lease.LeaseID == tracked.Lease.LeaseID {
							found = true
							break
						}
					}
					if !found {
						caps = append(caps, tracked)
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TraceResponse{
		Decision:      decision,
		Receipt:       receipt,
		Continuations: continuations,
		Approvals:     approvals,
		Executions:    executions,
		Events:        evts,
		Capabilities:  caps,
	})
}

type SummaryResponse struct {
	Approvals      ApprovalSummary      `json:"approvals"`
	Executions     ExecutionSummary     `json:"executions"`
	Capabilities   CapabilitySummary    `json:"capabilities"`
	DecisionCache  int                 `json:"decision_cache_size"`
}

type ApprovalSummary struct {
	Pending   int `json:"pending"`
	Approved int `json:"approved"`
	Denied   int `json:"denied"`
	Total    int `json:"total"`
}

type ExecutionSummary struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Running   int `json:"running"`
	TimedOut  int `json:"timed_out"`
	Total     int `json:"total"`
}

type CapabilitySummary struct {
	Active   int `json:"active"`
	Revoked  int `json:"revoked"`
	Total    int `json:"total"`
}

func (h *Handler) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	var approvalSummary ApprovalSummary
	var executionSummary ExecutionSummary
	var capabilitySummary CapabilitySummary

	if h.approvalSvc != nil {
		pending := h.approvalSvc.ListByStatus(approval.StatusPending)
		approved := h.approvalSvc.ListByStatus(approval.StatusApproved)
		denied := h.approvalSvc.ListByStatus(approval.StatusDenied)
		approvalSummary.Pending = len(pending)
		approvalSummary.Approved = len(approved)
		approvalSummary.Denied = len(denied)
		approvalSummary.Total = approvalSummary.Pending + approvalSummary.Approved + approvalSummary.Denied
	}

	if h.executionStore != nil {
		total, succeeded, failed, running, timedOut := h.executionStore.Stats()
		executionSummary.Total = total
		executionSummary.Succeeded = succeeded
		executionSummary.Failed = failed
		executionSummary.Running = running
		executionSummary.TimedOut = timedOut
	}

	if h.capabilitiesStore != nil {
		if fs, ok := h.capabilitiesStore.(interface{ Stats() (int, int, int) }); ok {
			total, active, revoked := fs.Stats()
			capabilitySummary.Total = total
			capabilitySummary.Active = active
			capabilitySummary.Revoked = revoked
		} else {
			all := h.capabilitiesStore.List()
			active := h.capabilitiesStore.ListActive()
			revoked := h.capabilitiesStore.ListRevoked()
			capabilitySummary.Total = len(all)
			capabilitySummary.Active = len(active)
			capabilitySummary.Revoked = len(revoked)
		}
	}

	h.decisionCache.mu.RLock()
	cacheSize := len(h.decisionCache.decisions)
	h.decisionCache.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SummaryResponse{
		Approvals:     approvalSummary,
		Executions:    executionSummary,
		Capabilities:  capabilitySummary,
		DecisionCache: cacheSize,
	})
}