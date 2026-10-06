// B-baseline: the same Phase-3A scenario corpus driven through the v1
// evaluator (system B). Translation is documented approximation, not
// emulation — v1 lacks request signatures and block-chained tokens, so
// those stages don't exist for B and rows record the stage v1 actually
// reached. Never t.Error on outcome: B rows are measurements.
//
// Honest translation rules:
//   - v2 policy rules → v1 rules (cross-product types×resources,
//     verbatim glob resources, require_capability → require_lease).
//     v1 has no policy default; unmatched requests escalate.
//   - v2 token → v1 CapabilityLease over the TAIL block scope (v1
//     scope grammar: single resource or "*"; when the tail can't be
//     expressed, the request resource is used iff it's in scope —
//     best-possible honest v1 representation).
//   - v1 leases are signed (internal/identity/canon.go lp format,
//     replicated below — the format is documented and implemented by
//     the Python SDK) under issuer key "issuer" in trustedKeys.
//   - attenuate chains → v1 DelegationChain authorities, hop-linked
//     signatures via the same lp format.
//   - request sig modes (none/forged/wrongkey) are no-ops: v1 has no
//     signature stage at all — that absence is the finding.
//   - approval redemption → approval.Service.ResumeAction, v1's real
//     path: approval binds (DecisionID, ActionType, Resource); the
//     returned bound action must equal the requested one.
package phase3

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	v1policy "ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/trust"
)

// --- replica of internal/identity/canon.go lp format (documented
// cross-language canonical encoding; kept local to leave v1 untouched)

type lpb struct{ buf []byte }

func (b *lpb) str(s string) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	b.buf = append(b.buf, l[:]...)
	b.buf = append(b.buf, s...)
	return b
}
func (b *lpb) strs(ss []string) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ss)))
	b.buf = append(b.buf, l[:]...)
	for _, s := range ss {
		b.str(s)
	}
	return b
}
func (b *lpb) i64(v int64) *lpb {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(v))
	b.buf = append(b.buf, l[:]...)
	return b
}
func (b *lpb) u32(v uint32) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], v)
	b.buf = append(b.buf, l[:]...)
	return b
}

func v1LeasePayload(l *models.CapabilityLease) []byte {
	return (&lpb{}).
		str(l.LeaseID).str(l.Issuer).str(l.Subject).str(l.Audience).
		strs(l.AllowedActions).str(l.ResourceScope).
		i64(l.Expiry.Unix()).i64(l.IssuedAt.Unix()).
		u32(uint32(l.DelegationDepth)).
		buf
}

func v1HopPayload(auths []models.Authority, i int, prevSig string) []byte {
	a := auths[i]
	return (&lpb{}).
		str(a.Issuer).str(a.SubjectID).str(a.Audience).str(a.ResourceScope).
		strs(a.Actions).
		i64(a.ExpiresAt.Unix()).i64(a.DelegatedAt.Unix()).
		str(a.Nonce).str(prevSig).
		buf
}

// --- translation

func v1PolicyStore(sc Scenario) *v1policy.Store {
	st := v1policy.NewStore("p3b")
	st.ClearRules()
	for _, r := range sc.Policy.Rules {
		types := r.Sel.Types
		if len(types) == 0 {
			types = []string{"*"}
		}
		res := r.Sel.Resources
		if len(res) == 0 {
			res = []string{""}
		}
		for _, t := range types {
			for _, rs := range res {
				vr := v1policy.Rule{ActionType: t, Environment: "*",
					Resource: rs}
				switch string(r.Effect) {
				case "allow":
					vr.Allow = true
				case "deny":
					vr.Deny = true
				case "escalate":
					vr.Escalate = true
				case "require_capability":
					// v1: an allow rule gated on a principal-bound
					// lease — closest honest semantic.
					vr.Allow = true
					vr.RequireLease = true
				}
				st.AddRule(vr)
			}
		}
	}
	return st
}

// v1ScopeText: v1 resource_scope is a single verbatim string ("*" or
// exact-match). Best-possible translation: if the request resource is
// in scope use it verbatim; else join (which will deny on mismatch —
// never widen to "*" unless scope itself is "*").
func v1ScopeText(resources []string, reqResource string) string {
	for _, r := range resources {
		if r == "*" {
			return "*"
		}
	}
	for _, r := range resources {
		if r == reqResource {
			return r
		}
	}
	return strings.Join(resources, ",")
}

// v1Lease builds a signed v1 lease from a v2 token spec (tail-block
// scope; attenuation shows up as a DelegationChain instead).
func v1Lease(id, subject, reqResource string,
	types, resources []string, depth int) *models.CapabilityLease {
	l := &models.CapabilityLease{
		LeaseID:         id,
		Issuer:          "issuer",
		Subject:         subject,
		AllowedActions:  types,
		ResourceScope:   v1ScopeText(resources, reqResource),
		Expiry:          time.Now().UTC().Add(time.Hour),
		IssuedAt:        time.Now().UTC(),
		DelegationDepth: depth,
	}
	l.Signature = ed25519.Sign(issuerKey, v1LeasePayload(l))
	return l
}

// v1Chain translates v2 attenuation hops into a v1 DelegationChain —
// hop i+1's issuer is hop i's subject (custody), and sign_with:"evil"
// produces a signature whose key doesn't match the claimed issuer's
// registered key, which v1 must reject the same way v2 does.
func v1Chain(hops []AttenuateSpec, tokSubject string,
	tokScope capability.Scope, reqResource string) *models.DelegationChain {
	keyFor := func(name string) ed25519.PrivateKey {
		switch name {
		case "issuer":
			return issuerKey
		case "evil":
			return evilKey
		default:
			return agentKey
		}
	}
	var auths []models.Authority
	prevSig := ""
	// hop 0 = the issue itself: issuer → token subject with root scope.
	root := models.Authority{
		Issuer: "issuer", SubjectID: tokSubject,
		ResourceScope: v1ScopeText(tokScope.Resources, reqResource),
		Actions:       tokScope.ActionTypes,
		Nonce:         "r0", DelegatedAt: time.Now().UTC(),
	}
	auths = append(auths, root)
	root.Signature = ed25519.Sign(issuerKey, v1HopPayload(auths, 0, ""))
	auths[0] = root
	prevSig = hex.EncodeToString(root.Signature)
	issuerName := tokSubject // custody: previous subject delegates
	for i, h := range hops {
		key := keyFor(issuerName) // honest delegation
		if h.SignWith == "evil" {
			key = evilKey // forgery: sig won't verify under Issuer's key
		}
		a := models.Authority{
			Issuer:        issuerName,
			SubjectID:     h.Subject,
			Actions:       h.Scope.ActionTypes,
			ResourceScope: v1ScopeText(h.Scope.Resources, reqResource),
			Nonce:         fmt.Sprintf("h%d", i+1),
			DelegatedAt:   time.Now().UTC(),
		}
		auths = append(auths, a)
		a.Signature = ed25519.Sign(key, v1HopPayload(auths, i+1, prevSig))
		auths[i+1] = a
		prevSig = hex.EncodeToString(a.Signature)
		issuerName = h.Subject
	}
	return &models.DelegationChain{Authorities: auths, Depth: len(auths)}
}

// stageForB maps a v1 decision back to the pipeline stage that produced
// it (v1 has no signature/capability blocks; "capability" covers lease
// + delegation checks which v1 does have).
func stageForB(req *models.ActionRequest, resp *models.DecisionResponse) string {
	if errs := req.Validate(); len(errs) > 0 {
		return "schema"
	}
	now := time.Now().UTC()
	if req.IssuedAt.Before(now.Add(-60*time.Second)) ||
		req.IssuedAt.After(now.Add(60*time.Second)) {
		return "freshness"
	}
	for _, rc := range resp.ReasonCodes {
		switch rc {
		case models.ReasonPolicyAllow, models.ReasonPolicyDeny,
			models.ReasonProductionDenied, models.ReasonPolicyEscalate,
			models.ReasonEscalate, models.ReasonLeaseRequired,
			models.ReasonAllowed, models.ReasonDeny:
			return "policy"
		case models.ReasonContainmentActive, models.ReasonTrustLow,
			models.ReasonTrustEscalate, models.ReasonAnomalyDetected,
			models.ReasonRepeatedRisk, models.ReasonRiskyShellPattern,
			models.ReasonRiskyGitPattern:
			return "interception" // v1 trust layer — no v2 analog
		case models.ReasonCapabilityExpiry,
			models.ReasonCapabilityNotAllowed,
			models.ReasonCapabilityScope, models.ReasonCapabilityRevoked,
			models.ReasonDelegationScope, models.ReasonResourceNotCovered,
			models.ReasonIdentityInvalid, models.ReasonMissingIdentity:
			return "capability"
		}
	}
	// ReasonActionNotAllowed post-checks → replay (the only remaining
	// source once schema/freshness are excluded).
	return "replay"
}

func decisionName(d models.Decision) string {
	switch d {
	case models.DecisionAllow:
		return "allow"
	case models.DecisionDeny:
		return "deny"
	case models.DecisionEscalate:
		return "escalate"
	default:
		return "reject"
	}
}

func TestBaselineV1(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(scenariosDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	sort.Strings(files)
	var recs []record
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var sc Scenario
		if err := json.Unmarshal(raw, &sc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		recs = append(recs, runV1(sc, raw))
	}
	out := filepath.Join(resultsDir, "phase3b.jsonl")
	w, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(w)
	for _, r := range recs {
		enc.Encode(r)
	}
	w.Close()
	t.Logf("%d v1 rows → %s", len(recs), out)

	// A floor: prompt-only control — no external gate exists, so every
	// scenario the attacker can express executes. The honest floor
	// against which both runtimes are measured.
	var arows []record
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var sc Scenario
		json.Unmarshal(raw, &sc)
		h := sha256.Sum256(raw)
		arows = append(arows, record{
			ExperimentID: fmt.Sprintf("p3A-%s", sc.ID),
			ScenarioID:   sc.ID, System: "A",
			RuntimeCommit: commitHash(), ModelID: "scripted",
			AttackerTier: sc.Tier, ScenarioClass: sc.Class,
			ScenarioHash: hex.EncodeToString(h[:8]),
			Outcome:      "allow", Stage: "none",
			Expected: sc.Expect.Outcome,
			Pass:     sc.Expect.Outcome == "allow",
			Note:     "prompt-level only — no runtime gate",
			At:       time.Now().UTC().Format(time.RFC3339),
		})
	}
	aout := filepath.Join(resultsDir, "phase3-prompt.jsonl")
	aw, _ := os.Create(aout)
	enc = json.NewEncoder(aw)
	for _, r := range arows {
		enc.Encode(r)
	}
	aw.Close()
	t.Logf("%d prompt-only rows → %s", len(arows), aout)
}

func runV1(sc Scenario, raw []byte) record {
	h := sha256.Sum256(raw)
	rec := record{
		ExperimentID: fmt.Sprintf("p3b-%s", sc.ID),
		ScenarioID:   sc.ID, System: "B",
		RuntimeCommit: commitHash(), ModelID: "scripted",
		AttackerTier: sc.Tier, ScenarioClass: sc.Class,
		ScenarioHash: hex.EncodeToString(h[:8]),
		Expected:     sc.Expect.Outcome,
		At:           time.Now().UTC().Format(time.RFC3339),
	}

	store := v1PolicyStore(sc)
	// prod wiring: policy store + shield; validator keyed by the
	// enrolled identities (issuer + subjects — v1's issuer registry).
	ev := evaluator.NewWithShield(store, trust.NewShieldStore())
	ev.SetValidator(identity.NewValidatorWithTrustedKeys(
		map[string][]byte{
			"issuer": issuerPub, "agent1": agentPub, "evil": evilPub}))

	req := &models.ActionRequest{
		ActionType:  models.ActionType(sc.Request.Type),
		Resource:    sc.Request.Resource, // raw wire form — v1 has no canonicalization
		Environment: models.Environment(sc.Request.Env),
		AgentIdentity: &models.AgentIdentity{
			Issuer: "issuer", SubjectID: sc.Request.Actor},
		IssuedAt: time.Now().UTC().Add(
			-time.Duration(sc.Request.IssuedAgeS) * time.Second),
	}
	if sc.Request.Nonce != "replay" && sc.Request.Nonce != "" {
		req.Nonce = sc.Request.Nonce
	} else {
		req.Nonce = "nonce-" + sc.ID
	}
	if sc.Request.Env == "prod" {
		// v1's production constant is "production"; scenario "prod"
		// stays verbatim — the v1 production-deny path keys on the
		// exact constant, and semantic divergence is a finding.
		rec.Note = "env prod ≠ v1 production constant"
	}

	for _, ts := range sc.Tokens {
		if ts.ID != sc.Request.Token {
			continue
		}
		scope := ts.Scope
		depth := 0
		if len(ts.Attenuate) > 0 {
			scope = ts.Attenuate[len(ts.Attenuate)-1].Scope
			depth = len(ts.Attenuate)
			req.DelegationChain = v1Chain(ts.Attenuate, ts.Subject,
				ts.Scope, sc.Request.Resource)
		}
		lease := v1Lease(ts.ID, ts.Subject, sc.Request.Resource,
			scope.ActionTypes, scope.Resources, depth)
		switch sc.Request.TokenMangle {
		case "widen_scope":
			// post-sign mutation — v1's lease signature must catch
			lease.AllowedActions = []string{"*"}
			lease.ResourceScope = "*"
		case "bump_epoch":
			// v1 leases have no epoch field: revocation liveness is
			// a separate checker; nothing on the lease to mangle.
			rec.Note = "bump_epoch: no v1 lease epoch"
		case "drop_block":
			if req.DelegationChain != nil &&
				len(req.DelegationChain.Authorities) > 1 {
				req.DelegationChain.Authorities =
					req.DelegationChain.Authorities[:1]
			}
		}
		req.CapabilityLease = lease
	}

	resp, err := ev.Evaluate(req)
	if err != nil || resp == nil {
		rec.Outcome = "reject"
		rec.Stage = "schema"
		rec.Pass = rec.Outcome == sc.Expect.Outcome
		return rec
	}
	outcome := decisionName(resp.Decision)
	rec.Stage = stageForB(req, resp)

	if ap := sc.Request.Approval; ap.ID != "" {
		// v1 approvals are minted from decisions only (provenance
		// binding); forged approval_ids fail closed at ConsumeResume.
		svc := approval.NewService(approval.NewInMemoryStore())
		at, rs := req.ActionType, req.Resource
		if ap.Bind == "other" {
			at, rs = "fs.delete", "/elsewhere"
		}
		apReq, err := svc.CreateApproval(&approval.CreateRequest{
			DecisionID: resp.DecisionID, ActionType: at,
			Resource: rs, Environment: req.Environment,
			AgentID: sc.Request.Actor})
		if err != nil {
			rec.FailureClass = "experimental_infrastructure"
		} else {
			useID := apReq.ApprovalID
			if ap.Forged {
				useID = "apr_forged" // unknown id — minting impossible
			}
			switch ap.Resolve {
			case "approve":
				svc.Approve(apReq.ApprovalID, "operator")
				res, err := svc.ResumeAction(useID)
				if err != nil {
					outcome = "deny" // never redeemable → action can't run
				} else if string(res.ActionType) != string(req.ActionType) ||
					res.Resource != req.Resource {
					outcome = "deny" // bound action ≠ claimed action
					rec.Note = "approval bound to different action"
				} else {
					outcome = "allow"
				}
				rec.Stage = "approval"
			case "deny":
				svc.Deny(apReq.ApprovalID, "operator", "denied")
				outcome = "deny"
				rec.Stage = "approval"
			case "none":
				// unresolved — stays escalated awaiting operator
				outcome = "escalate"
				rec.Stage = "approval"
			}
		}
	}
	if sc.Request.SendTwice || sc.Request.Nonce == "replay" {
		resp, err = ev.Evaluate(req)
		if err == nil && resp != nil {
			outcome = decisionName(resp.Decision)
			rec.Stage = stageForB(req, resp)
		}
	}
	rec.Outcome = outcome
	rec.Pass = rec.Outcome == sc.Expect.Outcome
	return rec
}
