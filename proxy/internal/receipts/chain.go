// Package receipts maintains an append-only, hash-chained, ed25519-signed
// receipt log. Every request that reaches the proxy — allowed, denied, or
// escalated — is recorded. Because the boundary forces all egress through
// the proxy, the chain is a complete record of everything that touched the
// outside world, verifiable offline with only the public key.
package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Receipt struct {
	ReceiptID string    `json:"receipt_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Decision  string    `json:"decision"` // allow | deny | escalate | error
	Status    int       `json:"status"`   // upstream status, 0 if not forwarded
	PrevHash  string    `json:"prev_hash"`
	Signature string    `json:"signature"` // sig_v1:<hex ed25519>
}

// canonical payload: pipe-delimited, excludes signature itself.
func (r *Receipt) canonical() string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%d|%s",
		r.ReceiptID, r.SessionID, r.Timestamp.UnixNano(), r.Method,
		r.URL, r.Decision, r.Status, r.PrevHash)
}

func (r *Receipt) hash() string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Chain struct {
	mu        sync.Mutex
	key       ed25519.PrivateKey
	sessionID string
	path      string
	prevHash  string
	seq       int

	anchorFile  string
	anchorURL   string
	anchorEvery int
}

// LoadOrCreate opens (or creates) the receipt chain and signing key.
// The public key is written to pubKeyFile for verifier distribution.
func LoadOrCreate(path, keyFile, pubKeyFile string) (*Chain, error) {
	key, err := loadKey(keyFile)
	if err != nil {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := saveKey(keyFile, pubKeyFile, key); err != nil {
			return nil, err
		}
	}
	c := &Chain{key: key, sessionID: newID(), path: path}
	// Resume chain head and length so restarts continue the chain rather
	// than fork it.
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		c.seq = bytes.Count(data, []byte{'\n'})
		if data[len(data)-1] != '\n' {
			c.seq++
		}
		var last Receipt
		if json.Unmarshal(lastNonEmptyLine(data), &last) == nil {
			c.prevHash = last.hash()
		}
	}
	return c, nil
}

func lastNonEmptyLine(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' && i < len(data)-1 {
			return data[i+1:]
		}
	}
	return data
}

func loadKey(f string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(string(data))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad receipt key")
	}
	return ed25519.PrivateKey(raw), nil
}

func saveKey(keyFile, pubKeyFile string, key ed25519.PrivateKey) error {
	for _, f := range []string{keyFile, pubKeyFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	return os.WriteFile(pubKeyFile, []byte(hex.EncodeToString(pub)), 0o644)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func lastLine(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return lastNonEmptyLine(data), nil
}

// Record appends a receipt and returns it.
func (c *Chain) Record(method, url, decision string, status int) (*Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := &Receipt{
		ReceiptID: "rcpt_" + newID(),
		SessionID: c.sessionID,
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       url,
		Decision:  decision,
		Status:    status,
		PrevHash:  c.prevHash,
	}
	r.Signature = "sig_v1:" + hex.EncodeToString(ed25519.Sign(c.key, []byte(r.canonical())))
	line, _ := json.Marshal(r)
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	c.prevHash = r.hash()
	c.seq++
	c.emitAnchor()
	return r, nil
}

// VerifyResult reports the first chain violation found, if any.
type VerifyResult struct {
	Total        int  `json:"total"`
	Valid        bool `json:"valid"`
	FailAt       int  `json:"fail_at,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Anchors      int  `json:"anchors,omitempty"`
	AnchorsValid bool `json:"anchors_valid,omitempty"`
}

// VerifyFile re-verifies a chain file offline: signatures, linkage, order.
func VerifyFile(path string, pubKey ed25519.PublicKey) *VerifyResult {
	res, _ := verifyChain(path, pubKey)
	return res
}

// verifyChain walks the file, returning the result plus each head hash
// (heads[i] is the chain head after i+1 receipts) for anchor checks.
func verifyChain(path string, pubKey ed25519.PublicKey) (*VerifyResult, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return &VerifyResult{Reason: err.Error()}, nil
	}
	var prevHash string
	var heads []string
	total := 0
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
		var r Receipt
		if err := json.Unmarshal(line, &r); err != nil {
			return &VerifyResult{Total: total, FailAt: total, Reason: "unparseable receipt"}, heads
		}
		if r.PrevHash != prevHash {
			return &VerifyResult{Total: total, FailAt: total, Reason: "chain link broken (prev_hash mismatch)"}, heads
		}
		if !strings.HasPrefix(r.Signature, "sig_v1:") || !ed25519.Verify(pubKey, []byte(r.canonical()), mustHex(r.Signature[7:])) {
			return &VerifyResult{Total: total, FailAt: total, Reason: "signature invalid"}, heads
		}
		prevHash = r.hash()
		heads = append(heads, prevHash)
		total++
	}
	return &VerifyResult{Total: total, Valid: true}, heads
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
