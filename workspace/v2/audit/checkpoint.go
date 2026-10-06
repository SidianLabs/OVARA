package audit

import (
	"fmt"
	"time"
)

// Checkpoint is a signed Merkle commitment over records[0..TreeSize).
// It is the externally-verifiable anchor: holding a Checkpoint, a
// verifier can detect truncation (tree_size mismatch), reorder or
// rewrite (root mismatch), and prove chain state at a point in time.
type Checkpoint struct {
	TreeSize uint64    `json:"tree_size"`
	RootHash string    `json:"root_hash"`
	Epoch    uint64    `json:"epoch"`
	TS       time.Time `json:"ts"`
	Sig      string    `json:"sig"`
}

func (c *Checkpoint) canonical() string {
	return fmt.Sprintf("ckpt|%d|%s|%d|%d",
		c.TreeSize, c.RootHash, c.Epoch, c.TS.UnixNano())
}
