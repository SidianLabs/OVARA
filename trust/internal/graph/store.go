package graph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// GraphStore is a file-backed persistent store for TrustGraph snapshots.
type GraphStore struct {
	mu       sync.RWMutex
	filePath string
	graph    *TrustGraph
}

// NewGraphStore creates a file-backed store for a TrustGraph.
// If the file exists, the graph is loaded from it on creation.
func NewGraphStore(filePath string) (*GraphStore, *TrustGraph) {
	g := NewTrustGraph()
	gs := &GraphStore{
		filePath: filePath,
		graph:    g,
	}
	_ = gs.loadInto(g)
	return gs, g
}

// Graph returns the underlying TrustGraph for read/write operations.
func (gs *GraphStore) Graph() *TrustGraph {
	return gs.graph
}

// Save persists the current graph state to disk.
func (gs *GraphStore) Save() error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	snap := gs.graph.SnapshotV2()

	cs := checksummedGraphSnapshot{
		Snapshot:  snap,
		Timestamp: time.Now().UTC(),
		Checksum:  computeGraphChecksum(snap),
	}

	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal graph: %w", err)
	}

	tmpPath := gs.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, gs.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// loadInto populates the provided graph with persisted state (if any).
func (gs *GraphStore) loadInto(g *TrustGraph) error {
	data, err := os.ReadFile(gs.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist, start with empty graph
		}
		return fmt.Errorf("failed to read graph file: %w", err)
	}

	cs := checksummedGraphSnapshot{}
	if err := json.Unmarshal(data, &cs); err != nil {
		return fmt.Errorf("failed to parse graph file: %w", err)
	}

	expected := computeGraphChecksum(cs.Snapshot)
	if cs.Checksum != "" && cs.Checksum != expected {
		return fmt.Errorf("graph checksum mismatch: file corrupted")
	}

	return g.RestoreFromSnapshot(cs.Snapshot)
}

type checksummedGraphSnapshot struct {
	Snapshot  GraphSnapshot `json:"snapshot"`
	Timestamp time.Time     `json:"timestamp"`
	Checksum  string        `json:"checksum"`
}

func computeGraphChecksum(snap GraphSnapshot) string {
	data, _ := json.Marshal(snap)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
