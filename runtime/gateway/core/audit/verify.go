package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VerifyResult reports what a file verification established. Callers
// must treat any non-nil error as "log untrusted" — there is no
// "mostly valid".
type VerifyResult struct {
	Total              int    `json:"total"`
	Valid              bool   `json:"valid"`
	LastSeq            uint64 `json:"last_seq"`
	AnchoredThroughSeq uint64 `json:"anchored_through_seq"` // records past this exist but are unanchored if LastSeq > this
	UnanchoredTail     int    `json:"unanchored_tail"`
}

// VerifyFile checks the whole log against the trusted public key.
// Unlike v1's verifier, there is NO sibling-pubkey fallback: the key
// must come from a trust root the caller already holds (SEC-0002).
// An empty or missing file is an error, not "valid, 0 records".
func VerifyFile(path string, pub ed25519.PublicKey, checkpointsDir string) (VerifyResult, error) {
	if pub == nil {
		return VerifyResult{}, errors.New("audit: verify requires an explicit trusted public key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return VerifyResult{}, errors.New("audit: empty log")
	}
	var recs []Record
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			return VerifyResult{}, fmt.Errorf("audit: corrupt record: %w", err)
		}
		recs = append(recs, r)
	}
	if err := verifyRecords(recs, pub); err != nil {
		return VerifyResult{Total: len(recs), Valid: false}, err
	}
	res := VerifyResult{Total: len(recs), Valid: true,
		LastSeq: recs[len(recs)-1].Seq}
	if checkpointsDir != "" {
		cp, err := LatestCheckpoint(checkpointsDir, pub)
		if err != nil {
			res.UnanchoredTail = len(recs)
			return res, fmt.Errorf("audit: no usable checkpoint: %w", err)
		}
		res.AnchoredThroughSeq = cp.TreeSize
		if cp.TreeSize > res.LastSeq {
			return res, fmt.Errorf("audit: checkpoint covers seq %d but log ends at %d — records missing", cp.TreeSize, res.LastSeq)
		}
		// Recompute the Merkle root over the covered prefix and match.
		var leaves [][]byte
		for _, r := range recs {
			if r.Seq > cp.TreeSize {
				break
			}
			h, _ := hex.DecodeString(r.Hash)
			leaves = append(leaves, h)
		}
		if merkleRoot(leaves) != cp.RootHash {
			return res, errors.New("audit: checkpoint root mismatch — chain was rewritten or reordered")
		}
		res.UnanchoredTail = int(res.LastSeq - cp.TreeSize)
	}
	return res, nil
}

// verifyRecords checks per-record signatures + hash-chain linkage.
func verifyRecords(recs []Record, pub ed25519.PublicKey) error {
	prev := strings.Repeat("0", 64)
	var expect uint64 = 1
	for i, r := range recs {
		if r.Seq != expect {
			return fmt.Errorf("audit: seq gap/reorder at index %d (got %d want %d)", i, r.Seq, expect)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("audit: chain break at seq %d", r.Seq)
		}
		want := computeHash(r.Seq, r.RecordID, r.Type, r.Payload, r.PrevHash, r.Timestamp)
		if want != r.Hash {
			return fmt.Errorf("audit: hash mismatch at seq %d (record modified)", r.Seq)
		}
		if !strings.HasPrefix(r.Sig, "edsig_v2:") {
			return fmt.Errorf("audit: bad sig scheme at seq %d", r.Seq)
		}
		sig, err := hex.DecodeString(r.Sig[9:])
		if err != nil || !ed25519.Verify(pub, []byte(r.canonical()), sig) {
			return fmt.Errorf("audit: signature invalid at seq %d", r.Seq)
		}
		prev = r.Hash
		expect++
	}
	return nil
}

// LatestCheckpoint finds the newest validly-signed checkpoint in dir.
// A checkpoint that fails signature verification is ignored (and
// counts as absent — caller treats absence as unanchored).
func LatestCheckpoint(dir string, pub ed25519.PublicKey) (Checkpoint, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Checkpoint{}, err
	}
	var best Checkpoint
	found := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "checkpoint_") {
			continue
		}
		b, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		var cp Checkpoint
		if json.Unmarshal(b, &cp) != nil {
			continue
		}
		if !strings.HasPrefix(cp.Sig, "edsig_v2:") {
			continue
		}
		sig, err := hex.DecodeString(cp.Sig[9:])
		if err != nil || !ed25519.Verify(pub, []byte(cp.canonical()), sig) {
			continue // forged checkpoint — drop silently, it's not ours
		}
		if !found || cp.TreeSize > best.TreeSize {
			best, found = cp, true
		}
	}
	if !found {
		return Checkpoint{}, errors.New("no signed checkpoint found")
	}
	return best, nil
}
