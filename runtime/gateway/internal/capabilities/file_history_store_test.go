package capabilities

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileHistoryStore_AppendAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}
	defer store.Close()

	store.Append(LeaseTrackedEntry("cap_h_001", "gw1", "agent-1", "admin"))

	time.Sleep(10 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read history file: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("history file is empty")
	}
}

func TestFileHistoryStore_ReloadOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store1, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}

	store1.Append(LeaseTrackedEntry("cap_hr_001", "gw1", "agent-reload", "admin"))
	store1.Append(LeaseUsedEntry("cap_hr_001", "gw1"))
	store1.Append(LeaseRevokedEntry("cap_hr_001", "gw1", "security incident", "agent-reload", "admin"))
	store1.Close()

	time.Sleep(10 * time.Millisecond)

	store2, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore reload failed: %v", err)
	}
	defer store2.Close()

	entries := store2.ListByLeaseID("cap_hr_001")
	if len(entries) != 3 {
		t.Errorf("expected 3 entries after reload, got %d", len(entries))
	}
	if entries[0].Event != "tracked" {
		t.Errorf("expected first event 'tracked', got %s", entries[0].Event)
	}
	if entries[1].Event != "used" {
		t.Errorf("expected second event 'used', got %s", entries[1].Event)
	}
	if entries[2].Event != "revoked" {
		t.Errorf("expected third event 'revoked', got %s", entries[2].Event)
	}
	if entries[2].Reason != "security incident" {
		t.Errorf("expected reason 'security incident', got %s", entries[2].Reason)
	}
}

func TestFileHistoryStore_ListRecent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}
	defer store.Close()

	for i := 0; i < 10; i++ {
		store.Append(LeaseTrackedEntry("cap_recent_"+string(rune('a'+i)), "gw1", "agent", "admin"))
	}

	recent := store.ListRecent(5)
	if len(recent) != 5 {
		t.Errorf("expected 5 recent entries, got %d", len(recent))
	}
}

func TestFileHistoryStore_ListBySubject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}
	defer store.Close()

	store.Append(LeaseTrackedEntry("cap_s_001", "gw1", "agent-x", "admin"))
	store.Append(LeaseTrackedEntry("cap_s_002", "gw1", "agent-y", "admin"))
	store.Append(LeaseTrackedEntry("cap_s_003", "gw1", "agent-x", "admin"))

	entries := store.ListBySubject("agent-x")
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for agent-x, got %d", len(entries))
	}
}

func TestFileHistoryStore_Stats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}
	defer store.Close()

	store.Append(LeaseTrackedEntry("cap_stats_001", "gw1", "agent", "admin"))
	store.Append(LeaseUsedEntry("cap_stats_001", "gw1"))

	total, loaded := store.Stats()
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
	if loaded != 0 {
		t.Errorf("expected loaded=0 (fresh store), got %d", loaded)
	}
}

func TestFileHistoryStore_UsedEntryWithContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}
	defer store.Close()

	entry := LeaseUsedEntryWithContext("cap_ctx_001", "gw1", "shell", "shell:ls -la")
	store.Append(entry)

	entries := store.ListByLeaseID("cap_ctx_001")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "shell" {
		t.Errorf("expected action 'shell', got %s", entries[0].Action)
	}
	if entries[0].Resource != "shell:ls -la" {
		t.Errorf("expected resource 'shell:ls -la', got %s", entries[0].Resource)
	}
}

func TestFileHistoryStore_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}

	store.Append(LeaseTrackedEntry("cap_close_001", "gw1", "agent", "admin"))

	if err := store.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestFileHistoryStore_ReloadWithContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	store1, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore failed: %v", err)
	}

	store1.Append(LeaseUsedEntryWithContext("cap_ctx_reload", "gw1", "git.pull", "git:acme/api"))
	store1.Close()

	time.Sleep(10 * time.Millisecond)

	store2, err := NewFileBackedHistoryStore(path, 1000)
	if err != nil {
		t.Fatalf("NewFileBackedHistoryStore reload failed: %v", err)
	}
	defer store2.Close()

	entries := store2.ListByLeaseID("cap_ctx_reload")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after reload, got %d", len(entries))
	}
	if entries[0].Action != "git.pull" {
		t.Errorf("expected action 'git.pull', got %s", entries[0].Action)
	}
	if entries[0].Resource != "git:acme/api" {
		t.Errorf("expected resource 'git:acme/api', got %s", entries[0].Resource)
	}
}
