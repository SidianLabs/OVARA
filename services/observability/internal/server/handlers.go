package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ovara.services.observability/internal/models"
	"ovara.services.observability/internal/store"
)

type Handlers struct {
	Store store.Store
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
	id = strings.TrimSuffix(id, "/graph")
	return id
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/v1/traces", h.HandleTraces)
	mux.HandleFunc("/v1/traces/", h.HandleTraces)
	mux.HandleFunc("/v1/agents/", h.HandleAgents)
	mux.HandleFunc("/v1/stats", h.HandleStats)
}

func (h *Handlers) HandleTraces(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/traces" && r.Method == http.MethodGet {
		h.query(w, r)
		return
	}

	if path == "/v1/traces/ingest/batch" && r.Method == http.MethodPost {
		h.ingestBatch(w, r)
		return
	}

	if path == "/v1/traces/ingest" && r.Method == http.MethodPost {
		h.ingest(w, r)
		return
	}

	if strings.HasPrefix(path, "/v1/traces/") {
		rest := strings.TrimPrefix(path, "/v1/traces/")
		if strings.HasSuffix(rest, "/graph") && r.Method == http.MethodGet {
			traceID := strings.TrimSuffix(rest, "/graph")
			h.getGraph(w, r, traceID)
			return
		}
		if !strings.Contains(rest, "/") && r.Method == http.MethodGet {
			h.getTrace(w, r, rest)
			return
		}
	}

	writeErr(w, http.StatusNotFound, "not found")
}

func (h *Handlers) HandleAgents(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	rest := strings.TrimPrefix(path, "/v1/agents/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		writeErr(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	agentID := parts[0]

	if len(parts) == 1 && r.Method == http.MethodGet {
		h.getAgentLineage(w, r, agentID)
		return
	}

	if len(parts) == 2 && parts[1] == "lineage" && r.Method == http.MethodGet {
		h.getAgentLineage(w, r, agentID)
		return
	}

	if len(parts) == 2 && parts[1] == "graph" && r.Method == http.MethodGet {
		h.getAgentGraph(w, r, agentID)
		return
	}

	writeErr(w, http.StatusNotFound, "not found")
}

func (h *Handlers) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_events": h.Store.Count(),
	})
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type ingestRequest struct {
	TraceID        string            `json:"trace_id"`
	SpanID         string            `json:"span_id"`
	ParentSpanID   string            `json:"parent_span_id,omitempty"`
	EventType      string            `json:"event_type"`
	AgentID        string            `json:"agent_id"`
	Action         string            `json:"action"`
	Resource       string            `json:"resource,omitempty"`
	Decision       string            `json:"decision,omitempty"`
	TrustScore     float64           `json:"trust_score,omitempty"`
	PolicyVersion  string            `json:"policy_version,omitempty"`
	GatewayID      string            `json:"gateway_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	Duration       int64             `json:"duration_ns,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func (h *Handlers) ingest(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.TraceID == "" || req.SpanID == "" || req.AgentID == "" || req.Action == "" {
		writeErr(w, http.StatusBadRequest, "trace_id, span_id, agent_id, and action are required")
		return
	}

	evt := &models.TraceEvent{
		TraceID:        req.TraceID,
		SpanID:         req.SpanID,
		ParentSpanID:   req.ParentSpanID,
		EventType:      models.EventType(req.EventType),
		AgentID:        req.AgentID,
		Action:         req.Action,
		Resource:       req.Resource,
		Decision:       req.Decision,
		TrustScore:     req.TrustScore,
		PolicyVersion:  req.PolicyVersion,
		GatewayID:      req.GatewayID,
		OrganizationID: req.OrganizationID,
		Timestamp:      time.Now().UTC(),
		Duration:       time.Duration(req.Duration),
		Metadata:       req.Metadata,
	}

	if err := h.Store.Ingest(evt); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, evt)
}

func (h *Handlers) ingestBatch(w http.ResponseWriter, r *http.Request) {
	var reqs []ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var ingested []*models.TraceEvent
	var errs []string
	for _, req := range reqs {
		if req.TraceID == "" || req.SpanID == "" || req.AgentID == "" || req.Action == "" {
			errs = append(errs, "skipped event with missing required fields")
			continue
		}

		evt := &models.TraceEvent{
			TraceID:        req.TraceID,
			SpanID:         req.SpanID,
			ParentSpanID:   req.ParentSpanID,
			EventType:      models.EventType(req.EventType),
			AgentID:        req.AgentID,
			Action:         req.Action,
			Resource:       req.Resource,
			Decision:       req.Decision,
			TrustScore:     req.TrustScore,
			PolicyVersion:  req.PolicyVersion,
			GatewayID:      req.GatewayID,
			OrganizationID: req.OrganizationID,
			Timestamp:      time.Now().UTC(),
			Duration:       time.Duration(req.Duration),
			Metadata:       req.Metadata,
		}

		if err := h.Store.Ingest(evt); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		ingested = append(ingested, evt)
	}

	result := map[string]any{
		"ingested": len(ingested),
	}
	if len(errs) > 0 {
		result["errors"] = errs
	}

	status := http.StatusCreated
	if len(ingested) == 0 && len(errs) > 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, result)
}

func (h *Handlers) query(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.TraceFilter{
		AgentID:   q.Get("agent_id"),
		Action:    q.Get("action"),
		Decision:  q.Get("decision"),
		GatewayID: q.Get("gateway_id"),
	}

	if v := q.Get("start_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = t
		}
	}
	if v := q.Get("end_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = t
		}
	}
	if v := q.Get("limit"); v != "" {
		filter.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		filter.Offset, _ = strconv.Atoi(v)
	}

	results, err := h.Store.Query(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"traces": results,
		"count":  len(results),
	})
}

func (h *Handlers) getTrace(w http.ResponseWriter, r *http.Request, traceID string) {
	if traceID == "" {
		writeErr(w, http.StatusBadRequest, "trace_id is required")
		return
	}

	record, err := h.Store.GetTrace(traceID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, record)
}

func (h *Handlers) getGraph(w http.ResponseWriter, r *http.Request, traceID string) {
	if traceID == "" {
		writeErr(w, http.StatusBadRequest, "trace_id is required")
		return
	}

	g, err := h.Store.GetGraph(traceID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, g)
}

func (h *Handlers) getAgentLineage(w http.ResponseWriter, r *http.Request, agentID string) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	records, err := h.Store.GetAgentLineage(agentID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": agentID,
		"lineage":  records,
		"count":    len(records),
	})
}

func (h *Handlers) getAgentGraph(w http.ResponseWriter, r *http.Request, agentID string) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	records, err := h.Store.GetAgentLineage(agentID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	builder := &struct {
		MergeGraphs func([]models.TraceGraph) models.TraceGraph
	}{
		MergeGraphs: func(graphs []models.TraceGraph) models.TraceGraph {
			seen := make(map[string]bool)
			var nodes []models.TraceNode
			var edges []models.TraceEdge
			for _, g := range graphs {
				for _, n := range g.Nodes {
					if !seen[n.ID] {
						seen[n.ID] = true
						nodes = append(nodes, n)
					}
				}
				edges = append(edges, g.Edges...)
			}
			return models.TraceGraph{Nodes: nodes, Edges: edges}
		},
	}

	var graphs []models.TraceGraph
	for _, r := range records {
		graphs = append(graphs, r.Graph)
	}
	merged := builder.MergeGraphs(graphs)

	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": agentID,
		"graph":    merged,
	})
}

func NewServer(addr string, s store.Store) *http.Server {
	h := &Handlers{Store: s}
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
