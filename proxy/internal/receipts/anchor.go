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
		if err := os.MkdirAll(filepath.Dir(c.anchorFile), 0o755); err != nil {
			log.Printf("anchor: %v", err)
		} else if f, err := os.OpenFile(c.anchorFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
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
	res, heads := verifyChain(chainPath, pubKey)
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
