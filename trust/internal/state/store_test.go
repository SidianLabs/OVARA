package state

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempFilePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "trust_state.json")
}

func TestStore_SaveAndLoadRoundtrip(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	state := &TrustState{
		AgentStates: map[string]*AgentTrustState{
			"agent1": {
				AgentID:    "agent1",
				TrustScore: 0.85,
				TrustLevel: "high",
				DriftWindow: []ActionRecord{
					{IsRisky: false, Action: "read", Timestamp: time.Now().UTC()},
					{IsRisky: true, Action: "write", Timestamp: time.Now().UTC()},
				},
				DegradationStreak: 2,
				ChainHistory: []ChainRecord{
					{ChainHash: "abc123", Depth: 3, Timestamp: time.Now().UTC()},
				},
				LastUpdated: time.Now().UTC(),
			},
		},
		AlertHistory: []AlertRecord{
			{AgentID: "agent1", AlertType: "drift", Severity: "medium", Message: "test alert", Timestamp: time.Now().UTC()},
		},
		UpdatedAt: time.Now().UTC(),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.AgentStates) != 1 {
		t.Errorf("expected 1 agent, got %d", len(loaded.AgentStates))
	}
	agent := loaded.AgentStates["agent1"]
	if agent == nil {
		t.Fatal("agent1 not found after load")
	}
	if agent.TrustScore != 0.85 {
		t.Errorf("trust score = %v, want 0.85", agent.TrustScore)
	}
	if agent.TrustLevel != "high" {
		t.Errorf("trust level = %v, want high", agent.TrustLevel)
	}
	if len(agent.DriftWindow) != 2 {
		t.Errorf("drift window len = %d, want 2", len(agent.DriftWindow))
	}
	if agent.DegradationStreak != 2 {
		t.Errorf("degradation streak = %d, want 2", agent.DegradationStreak)
	}
	if len(agent.ChainHistory) != 1 {
		t.Errorf("chain history len = %d, want 1", len(agent.ChainHistory))
	}
	if len(loaded.AlertHistory) != 1 {
		t.Errorf("alert history len = %d, want 1", len(loaded.AlertHistory))
	}
}

func TestStore_GetAgentState(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	state := &TrustState{
		AgentStates: map[string]*AgentTrustState{
			"agent1": {AgentID: "agent1", TrustScore: 0.9, TrustLevel: "high"},
			"agent2": {AgentID: "agent2", TrustScore: 0.3, TrustLevel: "low"},
		},
	}
	store.Save(state)

	got, err := store.GetAgentState("agent1")
	if err != nil {
		t.Fatalf("GetAgentState failed: %v", err)
	}
	if got.TrustScore != 0.9 {
		t.Errorf("score = %v, want 0.9", got.TrustScore)
	}

	_, err = store.GetAgentState("unknown")
	if err == nil {
		t.Error("expected error for unknown agent")
	}
}

func TestStore_UpdateAgentState(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	initial := &TrustState{
		AgentStates: map[string]*AgentTrustState{
			"agent1": {AgentID: "agent1", TrustScore: 0.9, TrustLevel: "high"},
		},
	}
	store.Save(initial)

	updated := &AgentTrustState{
		AgentID:    "agent1",
		TrustScore: 0.5,
		TrustLevel: "medium",
	}
	if err := store.UpdateAgentState("agent1", updated); err != nil {
		t.Fatalf("UpdateAgentState failed: %v", err)
	}

	got, _ := store.GetAgentState("agent1")
	if got.TrustScore != 0.5 {
		t.Errorf("score after update = %v, want 0.5", got.TrustScore)
	}
	if got.TrustLevel != "medium" {
		t.Errorf("level after update = %v, want medium", got.TrustLevel)
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	store.Save(&TrustState{
		AgentStates:  make(map[string]*AgentTrustState),
		AlertHistory: make([]AlertRecord, 0),
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agentID := "agent" + string(rune('0'+id%10))
			state := &AgentTrustState{
				AgentID:    agentID,
				TrustScore: float64(id) / 100.0,
				TrustLevel: "medium",
			}
			store.UpdateAgentState(agentID, state)
			store.GetAgentState(agentID)
		}(i)
	}
	wg.Wait()
}

func TestStore_FileCorruptionRecovery(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	store.Save(&TrustState{
		AgentStates: map[string]*AgentTrustState{
			"agent1": {AgentID: "agent1", TrustScore: 0.9},
		},
	})

	os.WriteFile(fp, []byte("corrupted data {{{"), 0644)

	_, err := store.Load()
	if err == nil {
		t.Error("expected error for corrupted file")
	}
}

func TestStore_EmptyState(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	state := &TrustState{
		AgentStates:  make(map[string]*AgentTrustState),
		AlertHistory: make([]AlertRecord, 0),
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("Save empty state failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load empty state failed: %v", err)
	}

	if len(loaded.AgentStates) != 0 {
		t.Errorf("expected 0 agents, got %d", len(loaded.AgentStates))
	}
	if len(loaded.AlertHistory) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(loaded.AlertHistory))
	}
}

func TestStore_LoadNonExistentFile(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "nonexistent.json")
	store := NewFileStore(fp)

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load nonexistent file should return empty state, got error: %v", err)
	}
	if len(loaded.AgentStates) != 0 {
		t.Errorf("expected 0 agents, got %d", len(loaded.AgentStates))
	}
}

func TestStore_ChecksumIntegrity(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	state := &TrustState{
		AgentStates: map[string]*AgentTrustState{
			"agent1": {AgentID: "agent1", TrustScore: 0.9},
		},
	}
	store.Save(state)

	data, _ := os.ReadFile(fp)
	content := string(data)
	content = content[:len(content)-5] + "XXXXX"
	os.WriteFile(fp, []byte(content), 0644)

	_, err := store.Load()
	if err == nil {
		t.Error("expected error when checksum is tampered")
	}
}

func TestStore_MultipleSaveLoadCycles(t *testing.T) {
	fp := tempFilePath(t)
	store := NewFileStore(fp)

	for i := 0; i < 5; i++ {
		state := &TrustState{
			AgentStates: map[string]*AgentTrustState{
				"agent1": {AgentID: "agent1", TrustScore: float64(i) / 5.0},
			},
		}
		if err := store.Save(state); err != nil {
			t.Fatalf("Save cycle %d failed: %v", i, err)
		}
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.AgentStates["agent1"].TrustScore != 0.8 {
		t.Errorf("final score = %v, want 0.8", loaded.AgentStates["agent1"].TrustScore)
	}
}
