// Package receipts maintains an append-only, hash-chained, ed25519-signed
// receipt log. Every request that reaches the proxy — allowed, denied, or
// escalated — is recorded. Because the boundary forces all egress through
// the proxy, the chain is a complete record of everything that touched the
// outside world, verifiable offline with only the public key(s).
//
// Two receipt versions exist. Version 1 (no "v" field, "sig_v1:" signature)
// signed a pipe-joined string, which is ambiguous when a field contains a
// pipe; it is still verified so existing logs keep verifying. Version 2
// ("v":2, "sig_v2:") signs a domain-separated, length-prefixed encoding of
// every field and carries the key id, so a key can be rotated or revoked.
// A chain may hold v1 receipts followed by v2 receipts, never the reverse.
//
// Every line must be exactly the bytes this package writes for the receipt
// it decodes to: unknown keys, duplicate keys, reordered keys or any other
// re-encoding fail verification, so no byte of a line is outside what the
// signature and the hash chain cover.
package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Receipt is one line of the chain. Field order matters: it is the order
// json.Marshal writes, and a line must re-encode to exactly its own bytes.
// The fields before ApprovalID are the v1 receipt; new fields go between
// ApprovalID and PrevHash and are omitted when empty, so a v1 line still
// re-encodes to itself.
type Receipt struct {
	V         int       `json:"v,omitempty"` // 0 = v1 (legacy), 2 = v2
	ReceiptID string    `json:"receipt_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Decision  string    `json:"decision"` // allow | deny | escalate | error
	Status    int       `json:"status"`   // upstream status, 0 if not forwarded
	// ApprovalID links an escalated-then-approved receipt to the approval
	// that authorized it.
	ApprovalID string `json:"approval_id,omitempty"`

	// --- v2 only ---
	// Phase is "attempt" for the receipt written (and synced to disk)
	// before any byte goes upstream, "outcome" for the receipt written once
	// the upstream answered or failed, and empty for a request that ended
	// without going upstream (denied, timed out, ...).
	Phase string `json:"phase,omitempty"`
	// Outcome says what happened: "sent" on an attempt, "not_sent" on an
	// outcome whose attempt was written but the request was then refused.
	Outcome string `json:"outcome,omitempty"`
	// AttemptID is, on an outcome receipt, the receipt_id of its attempt.
	AttemptID string `json:"attempt_id,omitempty"`
	// Agent identifies the client: a stable hash of the proxy credential
	// it presented ("pt_<sha256[:16]>"), or "" when client auth is off.
	Agent string `json:"agent,omitempty"`
	// Rule is the policy rule that decided, as the gateway named it.
	Rule string `json:"rule,omitempty"`
	// PolicyHash is the content hash of the policy the gateway decided under.
	PolicyHash string `json:"policy_hash,omitempty"`
	// Approver is who approved the request (the gateway's resolved_by).
	Approver string `json:"approver,omitempty"`
	// ReqBytes is the request body size; RespBytes the upstream response
	// size as the upstream declared it (-1 when it streamed without one).
	ReqBytes   int64    `json:"req_bytes,omitempty"`
	RespBytes  int64    `json:"resp_bytes,omitempty"`
	BodySHA256 string   `json:"body_sha256,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
	KeyID      string   `json:"kid,omitempty"`

	PrevHash  string `json:"prev_hash"`
	Signature string `json:"signature"` // sig_v1:<hex> (v1) | sig_v2:<hex> (v2)
}

const (
	sigV1Prefix = "sig_v1:"
	sigV2Prefix = "sig_v2:"
	// domainV2 separates v2 receipt signatures from every other use of an
	// Ed25519 key: no other message this key signs starts with it.
	domainV2 = "ovara-proxy-receipt-v2\n"
)

// canonicalV1 is the legacy payload: pipe-delimited, excludes the
// signature. Ambiguous (a "|" inside a field can move between fields);
// kept only to verify receipts written before v2.
func (r *Receipt) canonicalV1() string {
	c := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%d|%s",
		r.ReceiptID, r.SessionID, r.Timestamp.UnixNano(), r.Method,
		r.URL, r.Decision, r.Status, r.PrevHash)
	if r.ApprovalID != "" {
		c += "|" + r.ApprovalID
	}
	return c
}

// canonicalV2 is the v2 signing payload: the domain separator, then every
// field as a length-prefixed name and a length-prefixed value, in a fixed
// order. Length prefixes make the encoding injective: no two receipts
// share a payload.
func (r *Receipt) canonicalV2() []byte {
	b := []byte(domainV2)
	lp := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s))) //nolint:gosec // a receipt field is never 4 GiB (lines are capped far below)
		b = append(b, n[:]...)
		b = append(b, s...)
	}
	field := func(name, val string) { lp(name); lp(val) }
	field("v", strconv.Itoa(r.V))
	field("receipt_id", r.ReceiptID)
	field("session_id", r.SessionID)
	field("timestamp", strconv.FormatInt(r.Timestamp.UnixNano(), 10))
	field("method", r.Method)
	field("url", r.URL)
	field("decision", r.Decision)
	field("status", strconv.Itoa(r.Status))
	field("approval_id", r.ApprovalID)
	field("phase", r.Phase)
	field("outcome", r.Outcome)
	field("attempt_id", r.AttemptID)
	field("agent", r.Agent)
	field("rule", r.Rule)
	field("policy_hash", r.PolicyHash)
	field("approver", r.Approver)
	field("req_bytes", strconv.FormatInt(r.ReqBytes, 10))
	field("resp_bytes", strconv.FormatInt(r.RespBytes, 10))
	field("body_sha256", r.BodySHA256)
	field("reasons", strconv.Itoa(len(r.Reasons)))
	for _, s := range r.Reasons {
		lp(s)
	}
	field("kid", r.KeyID)
	field("prev_hash", r.PrevHash)
	return b
}

// hasV2Fields reports whether any field a v1 signature does not cover is set.
func (r *Receipt) hasV2Fields() bool {
	return r.Phase != "" || r.Outcome != "" || r.AttemptID != "" || r.Agent != "" ||
		r.Rule != "" || r.PolicyHash != "" || r.Approver != "" || r.ReqBytes != 0 ||
		r.RespBytes != 0 || r.BodySHA256 != "" || len(r.Reasons) > 0 || r.KeyID != ""
}

// hash is the chain link to this receipt: SHA-256 of its line. A line is
// always exactly json.Marshal of its receipt (parseLine enforces that).
func (r *Receipt) hash() string {
	b, _ := json.Marshal(r)
	return hashLine(b)
}

// LineHash is the chain link to a receipt line: the prev_hash the next
// receipt carries.
func LineHash(line []byte) string { return hashLine(line) }

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// parseLine decodes one chain line strictly: unknown keys are refused, and
// the line must be byte-for-byte the encoding of what it decodes to, which
// also refuses duplicate keys, reordered keys and alternative spellings.
// Without this, bytes outside the signature (an extra key, a second copy
// of a key that another parser would read first) would still verify.
func parseLine(line []byte) (*Receipt, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var r Receipt
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("unparseable receipt: %v", err)
	}
	if dec.More() {
		return nil, errors.New("unparseable receipt: trailing data")
	}
	again, err := json.Marshal(&r)
	if err != nil || !bytes.Equal(again, line) {
		return nil, errors.New("receipt line is not in canonical form (duplicate, reordered or extra keys)")
	}
	return &r, nil
}

// Entry is what the caller knows about one request. Append fills in the
// id, session, time, key id, chain link and signature.
type Entry struct {
	Method     string
	URL        string
	Decision   string
	Status     int
	ApprovalID string
	Phase      string
	Outcome    string
	AttemptID  string
	Agent      string
	Rule       string
	PolicyHash string
	Approver   string
	ReqBytes   int64
	RespBytes  int64
	BodySHA256 string
	Reasons    []string
}

type Chain struct {
	mu        sync.Mutex
	key       ed25519.PrivateKey
	keyID     string
	sessionID string
	path      string
	prevHash  string
	seq       int
	f         *os.File // the chain file, opened on first append
	size      int64    // bytes of whole lines in the file

	segmentBytes   int64 // rotate the current file into a compressed segment at this size (segments.go); 0 = never
	rotatedThrough int   // seq the last rotation synced to disk before compressing the file

	// Group commit: a durable append waits until an fsync that started
	// after its write has finished. Concurrent waiters share one fsync.
	syncMu sync.Mutex
	synced int // seq covered by the last finished fsync

	anchorFile  string
	anchorURL   string
	anchorEvery int
}

// LoadOrCreate opens (or creates) the receipt chain and signing key.
// The public key is written to pubKeyFile for verifier distribution.
func LoadOrCreate(path, keyFile, pubKeyFile string) (*Chain, error) {
	if err := repairInterruptedRotation(path); err != nil {
		return nil, fmt.Errorf("receipts %s: %w", path, err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("receipts %s: %w", path, readErr)
	}
	segs := SegmentFiles(path)
	key, err := loadKey(keyFile)
	if err != nil {
		// A missing key generates a fresh one; a corrupt one must never be
		// silently replaced — that would orphan every existing signature.
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("receipt key %s: %w (refusing to overwrite)", keyFile, err)
		}
		// A missing key next to existing receipts is not a fresh start: a
		// new key would replace the public key those receipts verify
		// against. Restore the key, or rotate it on purpose.
		if len(bytes.TrimSpace(data)) > 0 || len(segs) > 0 {
			return nil, fmt.Errorf("receipt key %s is missing but %s holds receipts: restore the key, or run `ovara keys rotate-receipt` to start a new one on purpose", keyFile, path)
		}
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := saveKey(keyFile, pubKeyFile, key); err != nil {
			return nil, err
		}
	}
	pub := key.Public().(ed25519.PublicKey)
	// A key that was rotated out or revoked must not sign anything more:
	// every receipt it signed from now on would fail verification.
	ring, err := LoadKeyRing(pubKeyFile)
	if err == nil {
		if rec := ring.record(KeyID(pub)); rec != nil && (rec.NotAfter != nil || rec.RevokedAt != nil) {
			return nil, fmt.Errorf("receipt key %s was rotated out or revoked: run `ovara keys rotate-receipt` to install a new one", keyFile)
		}
	}
	c := &Chain{key: key, keyID: KeyID(pub), sessionID: newID(), path: path}
	// Resume chain head and length so restarts continue the chain rather
	// than fork it: the head is the last receipt of the current file, or,
	// right after a rotation, of the newest segment.
	if len(data) > 0 {
		c.seq = bytes.Count(data, []byte{'\n'})
		if data[len(data)-1] != '\n' {
			c.seq++
		}
		// An unparseable tail means corruption or truncation; forking a new
		// chain over it would hide that. Refuse instead.
		lastLine := lastNonEmptyLine(data)
		if _, err := parseLine(lastLine); err != nil {
			return nil, fmt.Errorf("receipts %s: unparseable last line: %w (refusing to fork chain)", path, err)
		}
		c.prevHash = hashLine(lastLine)
	} else if len(segs) > 0 {
		lastLine, err := lastLineOf(segs[len(segs)-1])
		if err != nil {
			return nil, fmt.Errorf("receipts %s: %w (refusing to fork chain)", segs[len(segs)-1], err)
		}
		if _, err := parseLine(lastLine); err != nil {
			return nil, fmt.Errorf("receipts %s: unparseable last line: %w (refusing to fork chain)", segs[len(segs)-1], err)
		}
		c.prevHash = hashLine(lastLine)
	}
	// seq is the position in the whole chain, segments included
	c.seq += countLines(segs)
	return c, nil
}

func lastNonEmptyLine(data []byte) []byte {
	data = bytes.TrimRight(data, "\n")
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return data[i+1:]
	}
	return data
}

func loadKey(f string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad receipt key")
	}
	return ed25519.PrivateKey(raw), nil
}

func saveKey(keyFile, pubKeyFile string, key ed25519.PrivateKey) error {
	for _, f := range []string{keyFile, pubKeyFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
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

// clean makes s valid UTF-8. JSON cannot carry invalid UTF-8, so a field
// that held it would decode to different bytes than were signed.
func clean(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }

// Record appends a receipt and returns it. approvalID links the receipt to
// the gateway approval that authorized it ("" when none was involved).
func (c *Chain) Record(method, url, decision string, status int, approvalID string) (*Receipt, error) {
	return c.Append(Entry{Method: method, URL: url, Decision: decision, Status: status, ApprovalID: approvalID}, false)
}

// Append writes a v2 receipt for e. With durable set it returns only once
// the line is on disk (fsync), so a caller that refuses to act unless
// Append succeeds never acts without a durable receipt. Concurrent durable
// appends share fsyncs (group commit).
func (c *Chain) Append(e Entry, durable bool) (*Receipt, error) {
	reasons := make([]string, 0, len(e.Reasons))
	for _, s := range e.Reasons {
		reasons = append(reasons, clean(s))
	}
	if len(reasons) == 0 {
		reasons = nil
	}
	c.mu.Lock()
	r := &Receipt{
		V:          2,
		ReceiptID:  "rcpt_" + newID(),
		SessionID:  c.sessionID,
		Timestamp:  time.Now().UTC(),
		Method:     clean(e.Method),
		URL:        clean(e.URL),
		Decision:   clean(e.Decision),
		Status:     e.Status,
		ApprovalID: clean(e.ApprovalID),
		Phase:      e.Phase,
		Outcome:    e.Outcome,
		AttemptID:  e.AttemptID,
		Agent:      clean(e.Agent),
		Rule:       clean(e.Rule),
		PolicyHash: clean(e.PolicyHash),
		Approver:   clean(e.Approver),
		ReqBytes:   e.ReqBytes,
		RespBytes:  e.RespBytes,
		BodySHA256: e.BodySHA256,
		Reasons:    reasons,
		KeyID:      c.keyID,
		PrevHash:   c.prevHash,
	}
	r.Signature = sigV2Prefix + hex.EncodeToString(ed25519.Sign(c.key, r.canonicalV2()))
	line, err := json.Marshal(r)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	c.rotateIfFullLocked()
	if err := c.writeLocked(append(line, '\n')); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	c.prevHash = hashLine(line)
	c.seq++
	seq := c.seq
	c.emitAnchor()
	c.mu.Unlock()
	if durable {
		if err := c.syncThrough(seq); err != nil {
			return r, fmt.Errorf("receipt written but not synced to disk: %w", err)
		}
	}
	return r, nil
}

// writeLocked appends one whole line. A failed or short write is cut back
// off, so a full disk never leaves half a line that would break the chain
// for every later receipt. Called with c.mu held.
func (c *Chain) writeLocked(line []byte) error {
	if err := c.openLocked(); err != nil {
		return err
	}
	n, err := c.f.Write(line)
	if err == nil && n != len(line) {
		err = errors.New("short write")
	}
	if err != nil {
		if terr := c.f.Truncate(c.size); terr != nil {
			return fmt.Errorf("%v (and could not cut the partial line back off: %v)", err, terr)
		}
		return err
	}
	c.size += int64(n)
	return nil
}

// openLocked opens the chain file unless it is open. Called with c.mu held.
func (c *Chain) openLocked() error {
	if c.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	_, statErr := os.Stat(c.path)
	// 0600: receipts contain request URLs — not world-readable.
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if os.IsNotExist(statErr) {
		syncDir(filepath.Dir(c.path)) // the new file's name must survive a crash too
	}
	c.f, c.size = f, fi.Size()
	return nil
}

// syncThrough returns once the file is synced through receipt seq. The
// first waiter syncs everything written so far; waiters that arrive while
// it runs find their receipt covered and return without a second fsync.
func (c *Chain) syncThrough(seq int) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	if c.synced >= seq {
		return nil
	}
	c.mu.Lock()
	upto, f, rotated := c.seq, c.f, c.rotatedThrough
	c.mu.Unlock()
	if f == nil {
		// no file open: receipts up to the last rotation went to disk
		// before their segment was made
		if rotated >= seq {
			if rotated > c.synced {
				c.synced = rotated
			}
			return nil
		}
		return errors.New("receipt file not open")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	c.synced = upto
	return nil
}

// Close releases the chain file. A closed chain reopens it on next append.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	err := c.f.Close()
	c.f = nil
	return err
}

// KeyID returns the id this chain stamps on its receipts.
func (c *Chain) KeyID() string { return c.keyID }

// VerifyResult reports the first chain violation found, if any.
type VerifyResult struct {
	Total        int    `json:"total"`
	Valid        bool   `json:"valid"`
	FailAt       int    `json:"fail_at,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Anchors      int    `json:"anchors,omitempty"`
	AnchorsValid bool   `json:"anchors_valid,omitempty"`
	V1           int    `json:"v1,omitempty"` // legacy receipts among Total
}

// VerifyFile re-verifies a chain file offline against one public key:
// signatures, linkage, order, canonical form.
func VerifyFile(path string, pubKey ed25519.PublicKey) *VerifyResult {
	res, _, _ := verifyChain(path, SingleKey(pubKey))
	return res
}

// VerifyFileKeys is VerifyFile against a key history: each receipt must be
// signed by a key whose validity window (and revocation) admits its time.
func VerifyFileKeys(path string, ring *KeyRing) *VerifyResult {
	res, _, _ := verifyChain(path, ring)
	return res
}

// Verified is one receipt that passed verification, with its exact line.
type Verified struct {
	Receipt *Receipt
	Line    []byte
}

// ReadVerified verifies the chain and returns every receipt in it. It
// returns the receipts that verified before the first failure as well, so
// a caller can show what is trustworthy; res.Valid says whether all did.
func ReadVerified(path string, ring *KeyRing) (*VerifyResult, []Verified) {
	res, _, recs := verifyChain(path, ring)
	return res, recs
}

// verifyChain walks the file, returning the result plus each head hash
// (heads[i] is the chain head after i+1 receipts) for anchor checks.
func verifyChain(path string, ring *KeyRing) (*VerifyResult, []string, []Verified) {
	return verifySegment(path, ring, Segment{})
}

// Segment describes where a chain file starts when it is a cut of a longer
// chain (an incident bundle): After receipts came before it, and the first
// receipt's prev_hash must be PrevHash. The zero value is a whole chain.
type Segment struct {
	After    int    `json:"after"`
	PrevHash string `json:"prev_hash"`
}

func verifySegment(path string, ring *KeyRing, seg Segment) (*VerifyResult, []string, []Verified) {
	segs := segmentsOf(path)
	if n := missingSegment(segs); n != 0 {
		return &VerifyResult{Reason: fmt.Sprintf("receipt segment %06d is missing: the chain is cut at the front", n)}, nil, nil
	}
	if len(segs) == 0 {
		data, err := os.ReadFile(path)
		if err != nil {
			return &VerifyResult{Reason: err.Error()}, nil, nil
		}
		return verifyData(data, ring, seg)
	}
	// a rotated chain is read segment by segment, never all at once
	v := newChainVerifier(ring, seg)
	reason := ""
	err := ForEachLine(path, func(line []byte) error {
		if reason = v.step(line); reason != "" {
			return errStopWalk
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return v.fail(err.Error())
	}
	return v.result(reason)
}

// verifyData is verifySegment over chain bytes already read.
func verifyData(data []byte, ring *KeyRing, seg Segment) (*VerifyResult, []string, []Verified) {
	v := newChainVerifier(ring, seg)
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
		if reason := v.step(line); reason != "" {
			return v.fail(reason)
		}
	}
	return v.result("")
}

const reasonSignatureInvalid = "signature invalid"

// chainVerifier checks a chain one line at a time: links, signatures, key
// history, version order and the attempt/outcome pairing.
type chainVerifier struct {
	ring     *KeyRing
	seg      Segment
	prevHash string
	heads    []string
	recs     []Verified
	attempts map[string]bool
	total    int
	v1       int
	seenV2   bool
}

func newChainVerifier(ring *KeyRing, seg Segment) *chainVerifier {
	return &chainVerifier{ring: ring, seg: seg, prevHash: seg.PrevHash, attempts: map[string]bool{}}
}

// step verifies one line and returns why it fails, or "".
func (v *chainVerifier) step(line []byte) string {
	r, err := parseLine(line)
	if err != nil {
		return err.Error()
	}
	if r.PrevHash != v.prevHash {
		return "chain link broken (prev_hash mismatch)"
	}
	switch r.V {
	case 0:
		if v.seenV2 {
			return "legacy v1 receipt after v2 receipts"
		}
		if r.hasV2Fields() {
			return "v1 receipt carries fields its signature does not cover"
		}
		if !strings.HasPrefix(r.Signature, sigV1Prefix) {
			return reasonSignatureInvalid
		}
		if err := v.ring.verify(r, []byte(r.canonicalV1()), r.Signature[len(sigV1Prefix):]); err != nil {
			return err.Error()
		}
		v.v1++
	case 2:
		v.seenV2 = true
		if !strings.HasPrefix(r.Signature, sigV2Prefix) {
			return reasonSignatureInvalid
		}
		if err := v.ring.verify(r, r.canonicalV2(), r.Signature[len(sigV2Prefix):]); err != nil {
			return err.Error()
		}
		switch r.Phase {
		case "", "attempt":
		case "outcome":
			// In a segment the attempt may sit just before the cut.
			if !v.attempts[r.AttemptID] && v.seg.After == 0 {
				return "outcome receipt names no earlier attempt"
			}
			delete(v.attempts, r.AttemptID)
		default:
			return "unknown receipt phase"
		}
		if r.Phase == "attempt" {
			v.attempts[r.ReceiptID] = true
		}
	default:
		return fmt.Sprintf("unknown receipt version %d", r.V)
	}
	v.prevHash = hashLine(line)
	v.heads = append(v.heads, v.prevHash)
	v.recs = append(v.recs, Verified{Receipt: r, Line: append([]byte(nil), line...)})
	v.total++
	return ""
}

func (v *chainVerifier) fail(reason string) (*VerifyResult, []string, []Verified) {
	return &VerifyResult{Total: v.total, FailAt: v.total, Reason: reason, V1: v.v1}, v.heads, v.recs
}

// result is the verdict: a failure with its reason, or a whole valid chain.
func (v *chainVerifier) result(reason string) (*VerifyResult, []string, []Verified) {
	if reason != "" {
		return v.fail(reason)
	}
	return &VerifyResult{Total: v.total, Valid: true, V1: v.v1}, v.heads, v.recs
}

// syncDir fsyncs a directory so a file created in it survives a crash.
// Best effort: not every platform can sync a directory.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// LoadSigningKey reads the receipt signing key for the one other thing it
// signs: a run's attestation (internal/attest). The two never collide:
// every receipt payload starts with domainV2, every attestation payload
// with the DSSE prefix.
func LoadSigningKey(keyFile string) (ed25519.PrivateKey, error) { return loadKey(keyFile) }

// ReadVerifiedSegment is ReadVerified for a chain file that is a cut of a
// longer chain (seg says where it starts), as an incident bundle holds.
func ReadVerifiedSegment(path string, ring *KeyRing, seg Segment) (*VerifyResult, []Verified) {
	res, _, recs := verifySegment(path, ring, seg)
	return res, recs
}
