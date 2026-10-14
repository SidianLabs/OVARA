// Package attest turns a run's receipts into one signed statement another
// party can check without Ovara running: an in-toto v1 Statement in a DSSE
// envelope, signed with the deployment's receipt key. Its subjects are
// what came back (the commit the changes landed as) and the run's own
// receipts; its predicate says who ran, under which policy, what was asked
// and approved, which hosts were reached, and how it ended. Verification
// needs the chain file, the key history and the anchors: what the
// incident bundle carries.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/sandbox"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://ovara.dev/spec/0.1/attestation/run"
	PayloadType   = "application/vnd.in-toto+json"
	dsseVersion   = "DSSEv1"

	RuntimeBox = "ovara box"
	RuntimeRun = "ovara run"

	decisionAllow    = "allow"
	decisionEscalate = "escalate"
	decisionDeny     = "deny"
)

// Statement is an in-toto v1 statement.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject is one artifact the statement is about.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Predicate is what Ovara says about a run.
type Predicate struct {
	RunID     string          `json:"run_id"`
	Runtime   string          `json:"runtime"` // RuntimeBox or RuntimeRun
	Agent     string          `json:"agent"`   // the named agent, or "default"
	Started   time.Time       `json:"started"`
	Finished  time.Time       `json:"finished"`
	Manifest  *Digest         `json:"manifest,omitempty"` // the manifest the run was made from (ovara box)
	Policy    Policy          `json:"policy"`
	Receipts  Receipts        `json:"receipts"`
	Approvals []Approval      `json:"approvals"`
	Hosts     []Host          `json:"hosts"`
	Summary   sandbox.Summary `json:"summary"`
	// A run that is attested as it goes (attest_every_minutes) is a
	// sequence of statements: Sequence places this one (1 is the first;
	// 0 for a run attested once, at its end), Previous is the SHA-256 of
	// the previous statement's envelope file, and Interim says the run
	// went on after this statement, which covers the receipts since the
	// previous one.
	Sequence int     `json:"sequence,omitempty"`
	Previous *Digest `json:"previous,omitempty"`
	Interim  bool    `json:"interim,omitempty"`
}

// Digest names bytes by their SHA-256, hex.
type Digest struct {
	SHA256 string `json:"sha256"`
}

// Policy is what decided: every policy_hash the run's receipts carry, in
// the order first seen (more than one means the policy changed mid-run).
type Policy struct {
	Hashes []string `json:"hashes"`
}

// Receipts places the run's receipts in the chain and fixes their bytes.
type Receipts struct {
	After    int    `json:"after"`     // receipts in the chain before the run
	Count    int    `json:"count"`     // the run's receipts
	PrevHash string `json:"prev_hash"` // the link from the first of them to what came before ("" at the chain's start)
	Head     string `json:"head"`      // the hash of the last of them ("" when there are none)
	SHA256   string `json:"sha256"`    // over the run's lines, each with its newline
}

// Approval is one approval a person gave during the run.
type Approval struct {
	ID       string    `json:"id"`
	Resource string    `json:"resource"` // method and URL
	Approver string    `json:"approver,omitempty"`
	At       time.Time `json:"at"`
}

// Host is one destination and how its requests were decided.
type Host struct {
	Host    string `json:"host"`
	Allowed int    `json:"allowed"`
	Paused  int    `json:"paused"`
	Denied  int    `json:"denied"`
	Errors  int    `json:"errors,omitempty"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
}

// Run is what the launcher knows when a run ends.
type Run struct {
	ID       string
	Runtime  string
	Agent    string
	Started  time.Time
	Finished time.Time
	Manifest []byte // the manifest as `ovara box -print-manifest` writes it; nil for ovara run
	Branch   string // where the changes landed, with the full commit; empty otherwise
	Commit   string
	Summary  sandbox.Summary
	// A statement in a sequence (rolling attestation): its place, the
	// previous statement's envelope digest (hex), and whether the run goes on.
	Sequence int
	Previous string
	Interim  bool
}

// Build reads the run's receipts, the ones after the first `after` in the
// chain at chainPath, verified under the keys next to pubFile, and makes
// the statement. A chain that does not verify attests nothing.
func Build(run Run, chainPath, pubFile string, after int) (*Statement, error) {
	ring, err := receipts.LoadKeyRing(pubFile)
	if err != nil {
		return nil, fmt.Errorf("receipt key: %w", err)
	}
	res, recs := receipts.ReadVerified(chainPath, ring)
	if !res.Valid {
		return nil, fmt.Errorf("the receipt chain does not verify (entry %d: %s): nothing is attested", res.FailAt, res.Reason)
	}
	if after < 0 || after > len(recs) {
		return nil, fmt.Errorf("the run's receipts start after %d, but the chain holds %d", after, len(recs))
	}
	lines := recs[after:]
	prev := ""
	if after > 0 {
		prev = receipts.LineHash(recs[after-1].Line)
	}
	if run.Finished.IsZero() {
		run.Finished = time.Now()
	}
	p := Predicate{RunID: run.ID, Runtime: run.Runtime, Agent: agentName(run.Agent), Started: run.Started.UTC(), Finished: run.Finished.UTC(), Summary: run.Summary,
		Sequence: run.Sequence, Interim: run.Interim}
	if run.Previous != "" {
		p.Previous = &Digest{SHA256: run.Previous}
	}
	if len(run.Manifest) > 0 {
		p.Manifest = &Digest{SHA256: sha256Hex(run.Manifest)}
	}
	p.Receipts = receiptsRef(lines, after, prev)
	p.Policy.Hashes, p.Approvals, p.Hosts = derive(lines)
	st := &Statement{Type: StatementType, PredicateType: PredicateType, Predicate: p}
	if run.Commit != "" {
		st.Subject = append(st.Subject, Subject{Name: "refs/heads/" + run.Branch, Digest: map[string]string{"gitCommit": run.Commit}})
	}
	st.Subject = append(st.Subject, Subject{Name: receiptsSubject(run.ID), Digest: map[string]string{"sha256": p.Receipts.SHA256}})
	return st, nil
}

func receiptsSubject(runID string) string { return "ovara/run/" + runID + "/receipts.jsonl" }

func agentName(a string) string {
	if a == "" {
		return "default"
	}
	return a
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// receiptsRef fixes a run's lines: how many, where they sit, their bytes.
func receiptsRef(lines []receipts.Verified, after int, prev string) Receipts {
	r := Receipts{After: after, Count: len(lines), PrevHash: prev}
	h := sha256.New()
	for _, v := range lines {
		h.Write(v.Line)
		h.Write([]byte{'\n'})
	}
	r.SHA256 = hex.EncodeToString(h.Sum(nil))
	if len(lines) > 0 {
		r.PrevHash = lines[0].Receipt.PrevHash
		r.Head = receipts.LineHash(lines[len(lines)-1].Line)
	}
	return r
}

// derive reads the policy hashes, the approvals and the host table out of
// a run's receipts, in stable orders.
func derive(lines []receipts.Verified) (hashes []string, approvals []Approval, hosts []Host) {
	seenHash := map[string]bool{}
	byID := map[string]*Approval{}
	byHost := map[string]*Host{}
	hashes, approvals, hosts = []string{}, []Approval{}, []Host{}
	for _, v := range lines {
		r := v.Receipt
		if r.PolicyHash != "" && !seenHash[r.PolicyHash] {
			seenHash[r.PolicyHash] = true
			hashes = append(hashes, r.PolicyHash)
		}
		// an approval given: the request that then went through names it (a
		// held request names the approval it waited on, which nobody gave)
		if r.ApprovalID != "" && r.Decision == decisionAllow {
			if a := byID[r.ApprovalID]; a == nil {
				byID[r.ApprovalID] = &Approval{ID: r.ApprovalID, Resource: r.Method + " " + r.URL, Approver: r.Approver, At: r.Timestamp.UTC()}
			} else if a.Approver == "" && r.Approver != "" {
				a.Approver = r.Approver
			}
		}
		if name := hostOf(r.URL); name != "" {
			h := byHost[name]
			if h == nil {
				h = &Host{Host: name}
				byHost[name] = h
			}
			switch r.Decision {
			case decisionAllow:
				h.Allowed++
			case decisionEscalate:
				h.Paused++
			case decisionDeny:
				h.Denied++
			default:
				h.Errors++
			}
		}
	}
	for _, a := range byID {
		approvals = append(approvals, *a)
	}
	sort.Slice(approvals, func(i, j int) bool {
		if !approvals[i].At.Equal(approvals[j].At) {
			return approvals[i].At.Before(approvals[j].At)
		}
		return approvals[i].ID < approvals[j].ID
	})
	for _, h := range byHost {
		hosts = append(hosts, *h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return hashes, approvals, hosts
}

// hostOf is the authority of a receipt's URL, the way the run summary
// counts hosts.
func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	return u
}

// Tally counts a run's receipts the way its summary does.
func Tally(lines []receipts.Verified) (c sandbox.Counts, hosts int) {
	seen := map[string]bool{}
	for _, v := range lines {
		switch v.Receipt.Decision {
		case decisionAllow:
			c.Allowed++
		case decisionEscalate:
			c.Paused++
		case decisionDeny:
			c.Denied++
		}
		if h := hostOf(v.Receipt.URL); h != "" {
			seen[h] = true
		}
	}
	return c, len(seen)
}

// Sign wraps the statement in a DSSE envelope signed with the receipt key.
func Sign(st *Statement, keyFile string) (*Envelope, error) {
	key, err := receipts.LoadSigningKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("receipt key: %w", err)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, pae(PayloadType, payload))
	kid := receipts.KeyID(key.Public().(ed25519.PublicKey))
	return &Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: kid, Sig: base64.StdEncoding.EncodeToString(sig)}}}, nil
}

// pae is DSSE's pre-authentication encoding: what is actually signed.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("%s %d %s %d %s", dsseVersion, len(payloadType), payloadType, len(payload), payload))
}

// Dir is where a deployment keeps its attestations.
func Dir(deployment string) string { return filepath.Join(deployment, "var", "attestations") }

// Write stores the envelope as var/attestations/<run>.intoto.json under
// the deployment (<run>.<NNN>.intoto.json for a statement in a sequence),
// owner-only, never over an existing one, and returns the path relative
// to the deployment.
func Write(deployment, runID string, env *Envelope) (string, error) {
	if err := os.MkdirAll(Dir(deployment), 0o700); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	name := runID + ".intoto.json"
	if st, err := Decode(b); err == nil && st.Predicate.Sequence > 0 {
		name = fmt.Sprintf("%s.%03d.intoto.json", runID, st.Predicate.Sequence)
	}
	for i := 2; ; i++ {
		f, err := os.OpenFile(filepath.Join(Dir(deployment), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			name = fmt.Sprintf("%s-%d.intoto.json", runID, i)
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return filepath.ToSlash(filepath.Join("var", "attestations", name)), nil
	}
}

// Report is what verification found.
type Report struct {
	Valid     bool
	Problems  []string
	Statement *Statement
	KeyID     string
	Chain     *receipts.VerifyResult
	Anchored  bool
}

// Decode reads the statement out of an envelope without checking anything.
func Decode(envelope []byte) (*Statement, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("not a DSSE envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	return &st, nil
}

// Verify checks an envelope against the chain file (whole, or the cut seg
// describes), the key history next to pubFile and the anchors next to the
// chain. manifest, when given, must be the one the run was made from.
// Nothing here needs a running Ovara.
func Verify(envelope []byte, chainPath, pubFile string, seg receipts.Segment, manifest []byte) *Report {
	rep := &Report{}
	fail := func(format string, a ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, a...)) }
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		fail("not a DSSE envelope: %v", err)
		return rep
	}
	if env.PayloadType != PayloadType {
		fail("payloadType %q, want %s", env.PayloadType, PayloadType)
		return rep
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		fail("payload: %v", err)
		return rep
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		fail("statement: %v", err)
		return rep
	}
	rep.Statement = &st
	if st.Type != StatementType || st.PredicateType != PredicateType {
		fail("statement type %q with predicate %q: not a run attestation", st.Type, st.PredicateType)
		return rep
	}
	ring, err := receipts.LoadKeyRing(pubFile)
	if err != nil {
		fail("receipt keys: %v", err)
		return rep
	}
	msg := pae(env.PayloadType, payload)
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			fail("signature by %s: %v", s.KeyID, err)
			continue
		}
		if err := ring.VerifyAt(s.KeyID, st.Predicate.Finished, msg, sig); err != nil {
			fail("signature by %s: %v", s.KeyID, err)
			continue
		}
		rep.KeyID = s.KeyID
		break
	}
	if rep.KeyID == "" {
		fail("no signature verifies under the receipt keys")
	}
	res, anchored := receipts.VerifySegmentWithAnchors(chainPath, receipts.AnchorPathFor(chainPath), ring, seg)
	rep.Chain, rep.Anchored = res, anchored
	if !res.Valid {
		fail("receipt chain: %s", res.Reason)
		return rep
	}
	_, recs := receipts.ReadVerifiedSegment(chainPath, ring, seg)
	p := &st.Predicate
	start := p.Receipts.After - seg.After
	if start < 0 || p.Receipts.Count < 0 || start+p.Receipts.Count > len(recs) {
		fail("the chain file does not hold the run's receipts (%d after the first %d; the file holds %d after the first %d)", p.Receipts.Count, p.Receipts.After, len(recs), seg.After)
		return rep
	}
	lines := recs[start : start+p.Receipts.Count]
	prev := seg.PrevHash
	if start > 0 {
		prev = receipts.LineHash(recs[start-1].Line)
	}
	if got := receiptsRef(lines, p.Receipts.After, prev); got != p.Receipts {
		fail("the run's receipts are not the ones attested: found %+v, attested %+v", got, p.Receipts)
	}
	hashes, approvals, hosts := derive(lines)
	if !reflect.DeepEqual(hashes, p.Policy.Hashes) {
		fail("policy hashes: the receipts carry %v, the statement %v", hashes, p.Policy.Hashes)
	}
	if !sameJSON(approvals, p.Approvals) {
		fail("approvals: the receipts show %d, the statement %d, or they differ", len(approvals), len(p.Approvals))
	}
	if !sameJSON(hosts, p.Hosts) {
		fail("hosts: the receipts show %d, the statement %d, or they differ", len(hosts), len(p.Hosts))
	}
	if counts, n := Tally(lines); counts != p.Summary.Requests || n != p.Summary.Hosts {
		fail("summary: the receipts count %+v to %d host(s), the statement %+v to %d", counts, n, p.Summary.Requests, p.Summary.Hosts)
	}
	subjects := 0
	for _, s := range st.Subject {
		switch {
		case s.Name == receiptsSubject(p.RunID):
			subjects++
			if s.Digest["sha256"] != p.Receipts.SHA256 {
				fail("the receipts subject's digest is not the receipts' digest")
			}
		case strings.HasPrefix(s.Name, "refs/heads/"):
			if c := s.Digest["gitCommit"]; p.Summary.Commit == "" || !strings.HasPrefix(c, p.Summary.Commit) || s.Name != "refs/heads/"+p.Summary.Branch {
				fail("the commit subject %s %s does not match the summary (%s %s)", s.Name, c, p.Summary.Branch, p.Summary.Commit)
			}
		}
	}
	if subjects != 1 {
		fail("the statement does not name the run's receipts as a subject")
	}
	if manifest != nil {
		switch {
		case p.Manifest == nil:
			fail("the statement names no manifest, but one was given")
		case p.Manifest.SHA256 != sha256Hex(manifest):
			fail("the manifest given is not the one the run was made from")
		}
	}
	rep.Valid = len(rep.Problems) == 0
	return rep
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Describe is the statement in a few lines a person can read.
func Describe(st *Statement) string {
	p := st.Predicate
	var b strings.Builder
	fmt.Fprintf(&b, "run %s (%s) by agent %s, %s to %s\n", p.RunID, p.Runtime, p.Agent, p.Started.Format(time.RFC3339), p.Finished.Format(time.RFC3339))
	fmt.Fprintf(&b, "policy %s\n", strings.Join(p.Policy.Hashes, ", then "))
	fmt.Fprintf(&b, "%d request(s): %d allowed, %d paused, %d denied; %d host(s)", p.Receipts.Count, p.Summary.Requests.Allowed, p.Summary.Requests.Paused, p.Summary.Requests.Denied, p.Summary.Hosts)
	if p.Summary.Commands != nil {
		fmt.Fprintf(&b, "; commands: %d allowed, %d paused, %d approved, %d denied", p.Summary.Commands.Allowed, p.Summary.Commands.Paused, p.Summary.Commands.Approved, p.Summary.Commands.Denied)
	}
	b.WriteString("\n")
	for _, a := range p.Approvals {
		who := a.Approver
		if who == "" {
			who = "a person"
		}
		fmt.Fprintf(&b, "approved by %s: %s (%s)\n", who, a.Resource, a.ID)
	}
	switch {
	case p.Summary.Commit != "":
		fmt.Fprintf(&b, "outcome %s: changes on branch %s, commit %s\n", p.Summary.Outcome, p.Summary.Branch, p.Summary.Commit)
	case p.Summary.CommitBack != "":
		fmt.Fprintf(&b, "outcome %s (%s), agent exit %d\n", p.Summary.Outcome, p.Summary.CommitBack, p.Summary.ExitCode)
	default:
		fmt.Fprintf(&b, "outcome %s, exit %d\n", p.Summary.Outcome, p.Summary.ExitCode)
	}
	return b.String()
}

// VerifySequence checks that envelopes, the statements of one run in the
// order written, chain: the same run, runtime and agent throughout;
// sequence numbers 1, 2, ...; each statement's previous digest is the
// SHA-256 of the previous envelope's bytes; each statement's receipts
// start where the previous one's ended; every statement but the last is
// interim, and the last is not. It checks nothing a single statement's
// Verify checks: call that on each.
func VerifySequence(envelopes [][]byte) []string {
	var problems []string
	fail := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if len(envelopes) == 0 {
		return []string{"no statements"}
	}
	var prev *Statement
	prevDigest := ""
	for i, raw := range envelopes {
		st, err := Decode(raw)
		if err != nil {
			fail("statement %d: %v", i+1, err)
			return problems
		}
		p := st.Predicate
		if p.Sequence != i+1 {
			fail("statement %d carries sequence %d", i+1, p.Sequence)
		}
		if i == 0 {
			if p.Previous != nil {
				fail("the first statement names a previous one")
			}
		} else {
			q := prev.Predicate
			if p.RunID != q.RunID || p.Runtime != q.Runtime || p.Agent != q.Agent {
				fail("statement %d is about run %s (%s, agent %s), the one before about %s (%s, agent %s)", i+1, p.RunID, p.Runtime, p.Agent, q.RunID, q.Runtime, q.Agent)
			}
			if p.Previous == nil || p.Previous.SHA256 != prevDigest {
				fail("statement %d does not name the previous statement's digest", i+1)
			}
			if p.Receipts.After != q.Receipts.After+q.Receipts.Count {
				fail("statement %d starts at receipt %d, the one before ended at %d", i+1, p.Receipts.After, q.Receipts.After+q.Receipts.Count)
			}
			if !q.Interim {
				fail("statement %d follows one that said the run had ended", i+1)
			}
		}
		if i == len(envelopes)-1 && p.Interim {
			fail("the last statement says the run goes on: the sequence is not complete")
		}
		prev, prevDigest = st, sha256Hex(raw)
	}
	return problems
}
