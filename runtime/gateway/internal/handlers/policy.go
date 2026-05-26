package handlers

import (
	"encoding/json"
	"net/http"
	"os"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

type PolicyHandler struct {
	evaluator *evaluator.Evaluator
	store     *policy.Store
	eventStore events.Store
	gatewayID  string
}

func NewPolicyHandler(e *evaluator.Evaluator, s *policy.Store) *PolicyHandler {
	return &PolicyHandler{
		evaluator: e,
		store:     s,
	}
}

func (h *PolicyHandler) SetEventStore(es events.Store) {
	h.eventStore = es
}

func (h *PolicyHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

func (h *PolicyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/policy/validate", h.handleValidate)
	mux.HandleFunc("POST /v1/policy/simulate", h.handleSimulate)
	mux.HandleFunc("POST /v1/policy/simulate-batch", h.handleSimulateBatch)
	mux.HandleFunc("GET /v1/policy/diff", h.handlePolicyDiff)
	mux.HandleFunc("POST /v1/policy/diff", h.handlePolicyDiff)
	mux.HandleFunc("POST /v1/policy/candidate/load", h.handleCandidateLoad)
	mux.HandleFunc("POST /v1/policy/candidate/promote", h.handleCandidatePromote)
	mux.HandleFunc("GET /v1/policy/rules", h.handleListRules)
}

type ValidateRequest struct {
	PolicyData []byte `json:"policy_data,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
}

func (h *PolicyHandler) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	validator := policy.NewValidator()

	var result *policy.ValidationResult
	var err error

	if len(req.PolicyData) > 0 {
		result, err = validator.ValidatePolicyData(req.PolicyData)
	} else if req.FilePath != "" {
		data, err := readFile(req.FilePath)
		if err != nil {
			api.JSONBadRequest(w, "failed to read file: "+err.Error())
			return
		}
		result, err = validator.ValidatePolicyData(data)
	} else {
		api.JSONBadRequest(w, "either policy_data or file_path required")
		return
	}

	if err != nil {
		api.JSONBadRequest(w, "validation error: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyValidated)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"valid":   result.Valid,
			"errors":  len(result.Errors),
			"warnings": len(result.Warnings),
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type SimulateRequest struct {
	Request        *models.ActionRequest `json:"request"`
	CandidatePolicy []byte             `json:"candidate_policy,omitempty"`
	CandidateFile   string             `json:"candidate_file,omitempty"`
	UseCurrent     bool               `json:"use_current,omitempty"`
}

func (h *PolicyHandler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req SimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if req.Request == nil {
		api.JSONBadRequest(w, "request is required")
		return
	}

	candidateStore := h.store
	if !req.UseCurrent {
		if len(req.CandidatePolicy) > 0 {
			fp, err := parsePolicyJSON(req.CandidatePolicy)
			if err != nil {
				api.JSONBadRequest(w, "invalid candidate policy: "+err.Error())
				return
			}
			candidateStore = fp
		} else if req.CandidateFile != "" {
			loaded, err := policy.LoadStoreFromFile(req.CandidateFile, h.store.Version())
			if err != nil {
				api.JSONBadRequest(w, "failed to load candidate file: "+err.Error())
				return
			}
			candidateStore = loaded
		} else if candidatePolicyStore != nil {
			candidateStore = candidatePolicyStore
		}
	}

	result, err := h.evaluator.Simulate(req.Request, candidateStore)
	if err != nil {
		api.JSONBadRequest(w, "simulation error: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicySimulated)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"action_type":  req.Request.ActionType,
			"environment":  req.Request.Environment,
			"decision":     result.Decision,
			"changed":      result.DecisionChanged,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type SimulateBatchRequest struct {
	Requests         []*models.ActionRequest `json:"requests"`
	CandidatePolicy  []byte                `json:"candidate_policy,omitempty"`
	CandidateFile    string                `json:"candidate_file,omitempty"`
	UseCurrent       bool                  `json:"use_current,omitempty"`
}

func (h *PolicyHandler) handleSimulateBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req SimulateBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if len(req.Requests) == 0 {
		api.JSONBadRequest(w, "requests array is required")
		return
	}

	candidateStore := h.store
	if !req.UseCurrent {
		if len(req.CandidatePolicy) > 0 {
			fp, err := parsePolicyJSON(req.CandidatePolicy)
			if err != nil {
				api.JSONBadRequest(w, "invalid candidate policy: "+err.Error())
				return
			}
			candidateStore = fp
		} else if req.CandidateFile != "" {
			loaded, err := policy.LoadStoreFromFile(req.CandidateFile, h.store.Version())
			if err != nil {
				api.JSONBadRequest(w, "failed to load candidate file: "+err.Error())
				return
			}
			candidateStore = loaded
		} else if candidatePolicyStore != nil {
			candidateStore = candidatePolicyStore
		}
	}

	result := h.evaluator.SimulateBatch(req.Requests, candidateStore)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type DiffRequest struct {
	CandidatePolicy []byte `json:"candidate_policy,omitempty"`
	CandidateFile   string `json:"candidate_file,omitempty"`
}

func (h *PolicyHandler) handlePolicyDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req DiffRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSONBadRequest(w, "invalid JSON: "+err.Error())
			return
		}
	} else {
		req.CandidateFile = r.URL.Query().Get("file")
	}

	candidateStore := h.store
	if len(req.CandidatePolicy) > 0 {
		fp, err := parsePolicyJSON(req.CandidatePolicy)
		if err != nil {
			api.JSONBadRequest(w, "invalid candidate policy: "+err.Error())
			return
		}
		candidateStore = fp
	} else if req.CandidateFile != "" {
		loaded, err := policy.LoadStoreFromFile(req.CandidateFile, h.store.Version())
		if err != nil {
			api.JSONBadRequest(w, "failed to load candidate file: "+err.Error())
			return
		}
		candidateStore = loaded
	} else {
		api.JSONBadRequest(w, "candidate_policy or candidate_file required")
		return
	}

	diff := h.evaluator.ComparePolicies(candidateStore)

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyDiffGenerated)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"from_version": diff.FromVersion,
			"to_version":   diff.ToVersion,
			"added":        len(diff.AddedRules),
			"removed":      len(diff.RemovedRules),
			"changed":      len(diff.ChangedRules),
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diff)
}

type CandidateState struct {
	Version string        `json:"version"`
	Rules   []policy.Rule `json:"rules"`
	Loaded  bool          `json:"loaded"`
}

var candidatePolicyStore *policy.Store

type LoadCandidateRequest struct {
	PolicyData []byte `json:"policy_data,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	Version    string `json:"version,omitempty"`
}

func (h *PolicyHandler) handleCandidateLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req LoadCandidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	version := req.Version
	if version == "" {
		version = "candidate"
	}

	var store *policy.Store
	var err error

	if len(req.PolicyData) > 0 {
		fp, perr := parsePolicyJSON(req.PolicyData)
		if perr != nil {
			api.JSONBadRequest(w, "invalid policy JSON: "+perr.Error())
			return
		}
		fp.SetVersion(version)
		store = fp
	} else if req.FilePath != "" {
		store, err = policy.LoadStoreFromFile(req.FilePath, version)
		if err != nil {
			api.JSONBadRequest(w, "failed to load file: "+err.Error())
			return
		}
	} else {
		api.JSONBadRequest(w, "policy_data or file_path required")
		return
	}

	validator := policy.NewValidator()
	if vr := validator.ValidateRules(store.ListRules()); !vr.Valid {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "validation failed",
			"errors":  vr.Errors,
			"warnings": vr.Warnings,
		})
		return
	}

	candidatePolicyStore = store

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyCandidateLoaded)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"version": store.Version(),
			"rules":   len(store.ListRules()),
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CandidateState{
		Version: store.Version(),
		Rules:   store.ListRules(),
		Loaded:  true,
	})
}

func (h *PolicyHandler) handleCandidatePromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	if candidatePolicyStore == nil {
		api.JSONBadRequest(w, "no candidate policy loaded")
		return
	}

	if err := h.store.ReloadFromStore(candidatePolicyStore); err != nil {
		api.JSONBadRequest(w, "failed to promote candidate: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyPromoted)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"version": candidatePolicyStore.Version(),
			"rules":   len(candidatePolicyStore.ListRules()),
		}
		h.eventStore.Append(evt)
	}

	candidatePolicyStore = nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "promoted",
		"version":   h.store.Version(),
		"rules":    len(h.store.ListRules()),
	})
}

func (h *PolicyHandler) handleListRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	rules := h.store.ListRules()

	var candidateLoaded bool
	var candidateVersion string
	if candidatePolicyStore != nil {
		candidateLoaded = true
		candidateVersion = candidatePolicyStore.Version()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"version":           h.store.Version(),
		"rules":            rules,
		"candidate_loaded": candidateLoaded,
		"candidate_version": candidateVersion,
	})
}

func parsePolicyJSON(data []byte) (*policy.Store, error) {
	var fp filePolicyLite
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, err
	}

	version := fp.Version
	if version == "" {
		version = "candidate"
	}

	store := policy.NewStore(version)
	store.ClearRules()
	for _, r := range fp.Rules {
		store.AddRule(policy.Rule{
			ActionType:  r.ActionType,
			Environment: r.Environment,
			Allow:       r.Allow,
			Deny:        r.Deny,
			Escalate:    r.Escalate,
		})
	}
	return store, nil
}

type filePolicyLite struct {
	Version string     `json:"version"`
	Rules   []fileRule `json:"rules"`
}

type fileRule struct {
	ActionType  string `json:"action_type"`
	Environment string `json:"environment"`
	Allow       bool   `json:"allow"`
	Deny        bool   `json:"deny"`
	Escalate    bool   `json:"escalate"`
}

func readFile(path string) ([]byte, error) {
	return osReadFile(path)
}

var osReadFile = readFileImpl

func readFileImpl(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func init() {
	osReadFile = readFileImpl
}
