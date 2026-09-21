package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ovara.runtime.gateway/internal/api"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// maxPolicyBodyBytes caps request bodies on policy endpoints.
const maxPolicyBodyBytes = 10 << 20 // 10 MiB

// maxSimulateBatch caps the number of requests in a single simulate-batch call.
const maxSimulateBatch = 500

type PolicyHandler struct {
	evaluator  *evaluator.Evaluator
	store      *policy.Store
	eventStore events.Store
	gatewayID  string
	history    *policy.PolicyHistorySnapshotter
	// policyDir is the only directory from which caller-supplied file paths
	// (file_path, candidate_file, ?file=) may be read. Empty means file-based
	// inputs are rejected entirely.
	policyDir string
	// policyDirReal is policyDir after symlink resolution, cached by
	// SetPolicyDir so resolvePolicyPath can compare canonical paths and
	// reject symlink escapes that a lexical prefix check would miss.
	policyDirReal string
}

func NewPolicyHandler(e *evaluator.Evaluator, s *policy.Store) *PolicyHandler {
	return &PolicyHandler{
		evaluator: e,
		store:     s,
		history:   policy.NewPolicyHistorySnapshotter(),
	}
}

func (h *PolicyHandler) SetEventStore(es events.Store) {
	h.eventStore = es
}

func (h *PolicyHandler) SetGatewayID(id string) {
	h.gatewayID = id
}

// SetPolicyDir configures the directory that caller-supplied policy file
// paths are restricted to. Paths are cleaned and must resolve inside this
// directory; anything else is rejected (path traversal protection).
func (h *PolicyHandler) SetPolicyDir(dir string) {
	if dir == "" {
		h.policyDir = ""
		h.policyDirReal = ""
		return
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		h.policyDir = ""
		h.policyDirReal = ""
		return
	}
	// Cache the symlink-resolved directory so per-request checks compare
	// canonical paths; a lexical prefix check alone can be escaped by
	// symlinks inside the directory.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	h.policyDir = abs
	h.policyDirReal = real
}

// resolvePolicyPath validates that p is inside h.policyDir and returns the
// cleaned absolute path. It returns an error when no policy dir is configured
// or when p escapes it.
func (h *PolicyHandler) resolvePolicyPath(p string) (string, error) {
	if h.policyDir == "" {
		return "", fmt.Errorf("file-based policy inputs are disabled (no policy_dir configured)")
	}
	cleaned, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	root := h.policyDir + string(os.PathSeparator)
	if cleaned != h.policyDir && !strings.HasPrefix(cleaned, root) {
		return "", fmt.Errorf("path %q is outside the allowed policy directory", p)
	}
	// Resolve symlinks on the target and re-check against the canonical
	// policy dir: the lexical check above passes for paths like
	// policyDir/link -> /etc/passwd.
	dir := h.policyDirReal
	if dir == "" {
		dir = h.policyDir
	}
	real, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path %q: %w", p, err)
	}
	realRoot := dir + string(os.PathSeparator)
	if real != dir && !strings.HasPrefix(real, realRoot) {
		return "", fmt.Errorf("path %q is outside the allowed policy directory", p)
	}
	return real, nil
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
	mux.HandleFunc("GET /v1/policy/history", h.handleListHistory)
	mux.HandleFunc("GET /v1/policy/history/entry", h.handleGetHistoryEntry)
	mux.HandleFunc("POST /v1/policy/rollback", h.handleRollback)
	mux.HandleFunc("POST /v1/policy/restore", h.handleRestore)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	validator := policy.NewValidator()

	var result *policy.ValidationResult
	var err error

	if len(req.PolicyData) > 0 {
		result, err = validator.ValidatePolicyData(req.PolicyData)
	} else if req.FilePath != "" {
		safePath, perr := h.resolvePolicyPath(req.FilePath)
		if perr != nil {
			api.JSONBadRequest(w, perr.Error())
			return
		}
		data, err := readFile(safePath)
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
			"valid":    result.Valid,
			"errors":   len(result.Errors),
			"warnings": len(result.Warnings),
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type SimulateRequest struct {
	Request         *models.ActionRequest `json:"request"`
	CandidatePolicy []byte                `json:"candidate_policy,omitempty"`
	CandidateFile   string                `json:"candidate_file,omitempty"`
	UseCurrent      bool                  `json:"use_current,omitempty"`
}

func (h *PolicyHandler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req SimulateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
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
			safePath, perr := h.resolvePolicyPath(req.CandidateFile)
			if perr != nil {
				api.JSONBadRequest(w, perr.Error())
				return
			}
			loaded, err := policy.LoadStoreFromFile(safePath, h.store.Version())
			if err != nil {
				api.JSONBadRequest(w, "failed to load candidate file: "+err.Error())
				return
			}
			candidateStore = loaded
		} else if cand := getCandidatePolicyStore(); cand != nil {
			candidateStore = cand
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
			"action_type": req.Request.ActionType,
			"environment": req.Request.Environment,
			"decision":    result.Decision,
			"changed":     result.DecisionChanged,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type SimulateBatchRequest struct {
	Requests        []*models.ActionRequest `json:"requests"`
	CandidatePolicy []byte                  `json:"candidate_policy,omitempty"`
	CandidateFile   string                  `json:"candidate_file,omitempty"`
	UseCurrent      bool                    `json:"use_current,omitempty"`
}

func (h *PolicyHandler) handleSimulateBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	var req SimulateBatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
		return
	}

	if len(req.Requests) == 0 {
		api.JSONBadRequest(w, "requests array is required")
		return
	}
	if len(req.Requests) > maxSimulateBatch {
		api.JSONBadRequest(w, fmt.Sprintf("requests exceeds maximum batch size of %d", maxSimulateBatch))
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
			safePath, perr := h.resolvePolicyPath(req.CandidateFile)
			if perr != nil {
				api.JSONBadRequest(w, perr.Error())
				return
			}
			loaded, err := policy.LoadStoreFromFile(safePath, h.store.Version())
			if err != nil {
				api.JSONBadRequest(w, "failed to load candidate file: "+err.Error())
				return
			}
			candidateStore = loaded
		} else if cand := getCandidatePolicyStore(); cand != nil {
			candidateStore = cand
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
			api.JSONBadRequest(w, "invalid request body: "+err.Error())
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
		safePath, perr := h.resolvePolicyPath(req.CandidateFile)
		if perr != nil {
			api.JSONBadRequest(w, perr.Error())
			return
		}
		loaded, err := policy.LoadStoreFromFile(safePath, h.store.Version())
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

// candidatePolicyStore is shared across handlers; candidatePolicyStoreMu
// guards all reads and writes so concurrent requests cannot race on it.
var (
	candidatePolicyStore   *policy.Store
	candidatePolicyStoreMu sync.RWMutex
)

func getCandidatePolicyStore() *policy.Store {
	candidatePolicyStoreMu.RLock()
	defer candidatePolicyStoreMu.RUnlock()
	return candidatePolicyStore
}

func setCandidatePolicyStore(s *policy.Store) {
	candidatePolicyStoreMu.Lock()
	defer candidatePolicyStoreMu.Unlock()
	candidatePolicyStore = s
}

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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)).Decode(&req); err != nil {
		api.JSONBadRequest(w, "invalid request body: "+err.Error())
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
		safePath, perr := h.resolvePolicyPath(req.FilePath)
		if perr != nil {
			api.JSONBadRequest(w, perr.Error())
			return
		}
		store, err = policy.LoadStoreFromFile(safePath, version)
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
			"error":    "validation failed",
			"errors":   vr.Errors,
			"warnings": vr.Warnings,
		})
		return
	}

	setCandidatePolicyStore(store)

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

	cand := getCandidatePolicyStore()
	if cand == nil {
		api.JSONBadRequest(w, "no candidate policy loaded")
		return
	}

	previousVersion := h.store.Version()
	h.history.SnapshotFromStore(h.store, policy.PolicySourcePromote, previousVersion, h.gatewayID)

	if err := h.store.ReloadFromStore(cand); err != nil {
		api.JSONBadRequest(w, "failed to promote candidate: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyPromoted)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"version":          cand.Version(),
			"rules":            len(cand.ListRules()),
			"previous_version": previousVersion,
		}
		h.eventStore.Append(evt)
	}

	setCandidatePolicyStore(nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "promoted",
		"version": h.store.Version(),
		"rules":   len(h.store.ListRules()),
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
	if cand := getCandidatePolicyStore(); cand != nil {
		candidateLoaded = true
		candidateVersion = cand.Version()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"version":           h.store.Version(),
		"rules":             rules,
		"candidate_loaded":  candidateLoaded,
		"candidate_version": candidateVersion,
	})
}

func (h *PolicyHandler) handleListHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	entries := h.history.List()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"history": entries,
		"count":   len(entries),
	})
}

func (h *PolicyHandler) handleGetHistoryEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		api.JSONBadRequest(w, "id query parameter is required")
		return
	}

	entry, ok := h.history.Get(id)
	if !ok {
		api.JSONNotFound(w, "policy history entry not found: "+id)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func (h *PolicyHandler) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	latest, ok := h.history.Latest()
	if !ok {
		api.JSONBadRequest(w, "no history available for rollback")
		return
	}

	previousVersion := h.store.Version()
	h.history.SnapshotFromStore(h.store, policy.PolicySourceRollback, previousVersion, h.gatewayID)

	restoredStore := policy.NewStore(latest.Version)
	restoredStore.ClearRules()
	for _, rule := range latest.Rules {
		restoredStore.AddRule(rule)
	}

	if err := h.store.ReloadFromStore(restoredStore); err != nil {
		api.JSONBadRequest(w, "failed to rollback: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyRolledBack)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"restored_version": latest.Version,
			"previous_version": previousVersion,
			"history_id":       latest.ID,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":           "rolled_back",
		"restored_version": latest.Version,
		"previous_version": previousVersion,
	})
}

func (h *PolicyHandler) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.JSONMethodNotAllowed(w)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		api.JSONBadRequest(w, "id query parameter is required")
		return
	}

	entry, ok := h.history.Get(id)
	if !ok {
		api.JSONNotFound(w, "policy history entry not found: "+id)
		return
	}

	previousVersion := h.store.Version()
	h.history.SnapshotFromStore(h.store, policy.PolicySourceRestore, previousVersion, h.gatewayID)

	restoredStore := policy.NewStore(entry.Version)
	restoredStore.ClearRules()
	for _, rule := range entry.Rules {
		restoredStore.AddRule(rule)
	}

	if err := h.store.ReloadFromStore(restoredStore); err != nil {
		api.JSONBadRequest(w, "failed to restore: "+err.Error())
		return
	}

	if h.eventStore != nil {
		evt := events.NewEvent(events.EventTypePolicyRestored)
		if h.gatewayID != "" {
			evt.WithGatewayID(h.gatewayID)
		}
		evt.Payload = map[string]any{
			"restored_version": entry.Version,
			"restored_from_id": entry.ID,
			"previous_version": previousVersion,
		}
		h.eventStore.Append(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":           "restored",
		"restored_version": entry.Version,
		"restored_from_id": entry.ID,
		"previous_version": previousVersion,
	})
}

func parsePolicyJSON(data []byte) (*policy.Store, error) {
	return policy.ParseStore(data, "candidate")
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
