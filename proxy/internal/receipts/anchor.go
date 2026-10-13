package receipts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Anchor is an external snapshot of the chain head. A third party holding
// anchors can prove the chain was not rewritten after anchor time; they do
// not prove completeness (that rests on the egress boundary).
type Anchor struct {
	Seq  int       `json:"seq"`  // number of receipts in the chain at anchor time
	Head string    `json:"head"` // hash of receipt #Seq (the chain head)
	Time time.Time `json:"time"`
}

// SetAnchoring configures external anchoring: every `every` receipts the
// current head is appended as JSONL to file (if non-empty) and POSTed to
// url (if non-empty). Anchor failures are logged, never fatal — anchoring
// must not take the receipt log down with it.
func (c *Chain) SetAnchoring(file, url string, every int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anchorFile = file
	c.anchorURL = url
	if every < 1 {
		every = 1
	}
	c.anchorEvery = every
}

// emitAnchor is called from Record with the lock held, after prevHash/seq
// update. The file write is synchronous (cheap local append); the POST is
// fire-and-forget so a slow sink can't stall the data path.
func (c *Chain) emitAnchor() {
	if c.anchorFile == "" && c.anchorURL == "" {
		return
	}
	if c.seq%c.anchorEvery != 0 {
		return
	}
	a := Anchor{Seq: c.seq, Head: c.prevHash, Time: time.Now().UTC()}
	if c.anchorFile != "" {
		line, _ := json.Marshal(a)
		if err := os.MkdirAll(filepath.Dir(c.anchorFile), 0o700); err != nil {
			log.Printf("anchor: %v", err)
		} else if f, err := os.OpenFile(c.anchorFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err != nil {
			log.Printf("anchor: %v", err)
		} else {
			f.Write(append(line, '\n'))
			f.Close()
		}
	}
	if c.anchorURL != "" {
		body, _ := json.Marshal(a)
		go func() {
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Post(c.anchorURL, "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("anchor post: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// VerifyAnchorFile checks each anchor against a recomputed chain: head must
// equal the hash of the receipt at that sequence position. Returns the first
// divergence found, if any.
func VerifyAnchorFile(anchorPath, chainPath string, pubKey ed25519.PublicKey) *VerifyResult {
	return VerifyAnchorFileKeys(anchorPath, chainPath, SingleKey(pubKey))
}

// VerifyAnchorFileKeys is VerifyAnchorFile against a key history.
func VerifyAnchorFileKeys(anchorPath, chainPath string, ring *KeyRing) *VerifyResult {
	res, heads, _ := verifyChain(chainPath, ring)
	if !res.Valid {
		return res
	}
	data, err := os.ReadFile(anchorPath)
	if err != nil {
		res.Reason = "anchors: " + err.Error()
		return res
	}
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		if len(line) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(line, &a); err != nil {
			res.Valid = false
			res.Reason = fmt.Sprintf("unparseable anchor at %d", res.Anchors)
			return res
		}
		res.Anchors++
		if a.Seq < 1 || a.Seq > len(heads) || heads[a.Seq-1] != a.Head {
			res.Valid = false
			res.AnchorsValid = false
			res.FailAt = a.Seq
			res.Reason = fmt.Sprintf("anchor %d head does not match chain head at seq %d", res.Anchors-1, a.Seq)
			return res
		}
	}
	if res.Anchors > 0 {
		res.AnchorsValid = true
	}
	return res
}

// AnchorPathFor is where `ovara run` keeps the local anchors for a chain:
// anchors.jsonl next to the chain file.
func AnchorPathFor(chainPath string) string {
	return filepath.Join(filepath.Dir(chainPath), "anchors.jsonl")
}

// VerifyWithAnchors verifies the chain and, when an anchor file exists,
// checks the chain against every anchor in it. A chain that was cut short,
// had entries removed, or was cut and then continued no longer matches the
// anchors written while it grew, so it fails here even though each
// remaining entry is correctly signed and linked. anchored reports whether
// anchors were found at all: without them, truncation cannot be detected.
func VerifyWithAnchors(chainPath, anchorPath string, pubKey ed25519.PublicKey) (res *VerifyResult, anchored bool) {
	return VerifyWithAnchorsKeys(chainPath, anchorPath, SingleKey(pubKey))
}

// VerifyWithAnchorsKeys is VerifyWithAnchors against a key history.
func VerifyWithAnchorsKeys(chainPath, anchorPath string, ring *KeyRing) (res *VerifyResult, anchored bool) {
	if _, err := os.Stat(anchorPath); err != nil {
		return VerifyFileKeys(chainPath, ring), false
	}
	res = VerifyAnchorFileKeys(anchorPath, chainPath, ring)
	return res, res.Anchors > 0
}

// VerifySegmentWithAnchors verifies a chain file that is a cut of a longer
// chain (see Segment) against the anchors of the whole chain. Anchors
// before the cut are skipped, except one exactly at the cut, which must
// name the segment's starting prev_hash. An anchor past the segment's end
// means the segment was cut short.
func VerifySegmentWithAnchors(chainPath, anchorPath string, ring *KeyRing, seg Segment) (*VerifyResult, bool) {
	res, heads, _ := verifySegment(chainPath, ring, seg)
	if !res.Valid {
		return res, false
	}
	anchors, err := readAnchors(anchorPath)
	if err != nil {
		if os.IsNotExist(err) {
			return res, false
		}
		res.Valid = false
		res.Reason = "anchors: " + err.Error()
		return res, false
	}
	for i, a := range anchors {
		res.Anchors++
		local := a.Seq - seg.After
		switch {
		case local < 0:
			continue
		case local == 0:
			if seg.After > 0 && a.Head != seg.PrevHash {
				res.Valid = false
				res.Reason = fmt.Sprintf("anchor %d does not match the segment's start", i)
				return res, true
			}
		case local > len(heads) || heads[local-1] != a.Head:
			res.Valid = false
			res.FailAt = a.Seq
			res.Reason = fmt.Sprintf("anchor %d head does not match chain head at seq %d", i, a.Seq)
			return res, true
		}
	}
	res.AnchorsValid = res.Anchors > 0
	return res, res.Anchors > 0
}

func readAnchors(path string) ([]Anchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Anchor
	for i, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(line, &a); err != nil {
			return nil, fmt.Errorf("unparseable anchor at line %d", i+1)
		}
		out = append(out, a)
	}
	return out, nil
}

// CheckBeforeResume refuses to continue a chain that no longer matches the
// anchors written while it grew. Appending to a log that was cut short would
// start a new branch that verifies link by link, so a run must stop and let
// a person look first. A chain with no anchors yet is fine.
func CheckBeforeResume(chainPath, anchorPath, pubKeyFile string) error {
	if fi, err := os.Stat(anchorPath); err != nil || fi.Size() == 0 {
		return nil
	}
	ring, err := LoadKeyRing(pubKeyFile)
	if err != nil {
		return fmt.Errorf("receipt keys: %w", err)
	}
	res, _ := VerifyWithAnchorsKeys(chainPath, anchorPath, ring)
	if !res.Valid {
		return fmt.Errorf("the receipt log %s does not match its anchors (%s at entry %d): it was edited or cut short since the last run. Not appending to it. Keep a copy for investigation, then move %s and %s aside to start a new log", chainPath, res.Reason, res.FailAt, chainPath, anchorPath)
	}
	return nil
}
