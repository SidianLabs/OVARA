package state

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type ActionRecord struct {
	IsRisky  bool   `json:"is_risky"`
	Action   string `json:"action"`
	Timestamp time.Time `json:"timestamp"`
}

type ChainRecord struct {
	ChainHash string    `json:"chain_hash"`
	Depth     int       `json:"depth"`
	Timestamp time.Time `json:"timestamp"`
}

type AlertRecord struct {
	AgentID   string    `json:"agent_id"`
	AlertType string    `json:"alert_type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type AgentTrustState struct {
	AgentID          string         `json:"agent_id"`
	TrustScore       float64        `json:"trust_score"`
	TrustLevel       string         `json:"trust_level"`
	DriftWindow      []ActionRecord `json:"drift_window"`
	DegradationStreak int          `json:"degradation_streak"`
	ChainHistory     []ChainRecord  `json:"chain_history"`
	LastUpdated      time.Time      `json:"last_updated"`
}

type TrustState struct {
	AgentStates  map[string]*AgentTrustState `json:"agent_states"`
	AlertHistory []AlertRecord               `json:"alert_history"`
	UpdatedAt    time.Time                   `json:"updated_at"`
}

type Store interface {
	Save(state *TrustState) error
	Load() (*TrustState, error)
	GetAgentState(agentID string) (*AgentTrustState, error)
	UpdateAgentState(agentID string, state *AgentTrustState) error
}

type FileStore struct {
	mu       sync.RWMutex
	filePath string
	state    *TrustState
}

func NewFileStore(filePath string) *FileStore {
	return &FileStore{
		filePath: filePath,
		state: &TrustState{
			AgentStates:  make(map[string]*AgentTrustState),
			AlertHistory: make([]AlertRecord, 0),
			UpdatedAt:    time.Now().UTC(),
		},
	}
}

type checksummedState struct {
	State    *TrustState `json:"state"`
	Checksum string      `json:"checksum"`
}

func computeChecksum(state *TrustState) string {
	data, _ := json.Marshal(state)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

func (fs *FileStore) Save(state *TrustState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	state.UpdatedAt = time.Now().UTC()

	cs := checksummedState{
		State:    state,
		Checksum: computeChecksum(state),
	}

	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	tmpPath := fs.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, fs.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	fs.state = state
	return nil
}

func (fs *FileStore) Load() (*TrustState, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := os.ReadFile(fs.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fs.state, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var cs checksummedState
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	if cs.State == nil {
		return nil, fmt.Errorf("invalid state file: missing state")
	}

	expectedChecksum := computeChecksum(cs.State)
	if cs.Checksum != expectedChecksum {
		return nil, fmt.Errorf("state file corrupted: checksum mismatch")
	}

	if cs.State.AgentStates == nil {
		cs.State.AgentStates = make(map[string]*AgentTrustState)
	}
	if cs.State.AlertHistory == nil {
		cs.State.AlertHistory = make([]AlertRecord, 0)
	}

	fs.state = cs.State
	return fs.state, nil
}

func (fs *FileStore) GetAgentState(agentID string) (*AgentTrustState, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.state == nil || fs.state.AgentStates == nil {
		return nil, fmt.Errorf("agent state not found: %s", agentID)
	}

	state, ok := fs.state.AgentStates[agentID]
	if !ok {
		return nil, fmt.Errorf("agent state not found: %s", agentID)
	}

	return state, nil
}

func (fs *FileStore) UpdateAgentState(agentID string, state *AgentTrustState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.state == nil {
		fs.state = &TrustState{
			AgentStates:  make(map[string]*AgentTrustState),
			AlertHistory: make([]AlertRecord, 0),
			UpdatedAt:    time.Now().UTC(),
		}
	}

	if fs.state.AgentStates == nil {
		fs.state.AgentStates = make(map[string]*AgentTrustState)
	}

	state.LastUpdated = time.Now().UTC()
	fs.state.AgentStates[agentID] = state
	fs.state.UpdatedAt = time.Now().UTC()

	return nil
}
