// Package phase3 executes the Phase-3A deterministic adversarial
// corpus: every scenario JSON under workspace/research/phase3/scenarios/
// is run against the real decision engine and recorded as an
// experiment row (per the Phase-3 record schema). T0/T1 only —
// LLM tiers need keys, sandbox classes need Linux.
package phase3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"sort"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/decide"
	"ovara.runtime.gateway/core/policy"
)

var scenariosDir = filepath.Join("..", "..", "..", "..", "workspace",
	"research", "phase3", "scenarios")
var resultsDir = filepath.Join("..", "..", "..", "..", "workspace",
	"research", "phase3", "results")

// ---- scenario schema (see scenarios/FORMAT.md) ----

type Scenario struct {
	ID    string `json:"id"`
	Class string `json:"class"`
	Tier  string `json:"tier"`
	Title string `json:"title"`

	Policy struct {
		Default string        `json:"default"`
		Rules   []policy.Rule `json:"rules"`
	} `json:"policy"`

	Tokens []struct {
		ID       string              `json:"id"`
		Subject  string              `json:"subject"` // "agent1" | "evil"
		Epoch    uint64              `json:"epoch"`
		Scope    capability.Scope    `json:"scope"`
		Caveats  []capability.Caveat `json:"caveats"`
		Delegate bool                `json:"delegate"`
		// Attenuate chains another block onto this token.
		Attenuate []AttenuateSpec `json:"attenuate"`
	} `json:"tokens"`

	Request struct {
		Actor      string `json:"actor"`
		Type       string `json:"type"`
		Resource   string `json:"resource"`
		Env        string `json:"env"`
		Token      string `json:"token"`        // token id or ""
		Nonce      string `json:"nonce"`        // "fresh" | "replay" (same nonce twice)
		Sig        string `json:"sig"`          // "valid" | "none" | "forged" | "wrongkey"
		IssuedAgeS int    `json:"issued_age_s"` // seconds old (stale test)
		// TokenMangle: mutate the token post-issue (signature must
		// catch it). Values: widen_scope, bump_epoch, drop_block.
		TokenMangle string `json:"token_mangle"`
		// Canonicalize: honest signers canonicalize first; false
		// signs the raw wire form (post-canonical-enforcement test
		// expects reject regardless of signature validity).
		Canonicalize bool `json:"canonicalize"`
		// SendTwice replays the identical request after the first
		// decision (in-process replay probe).
		SendTwice bool `json:"send_twice"`
		// Approval exercises the operator-grant path: first eval
		// escalates, then a MemApprovalStore approval is created
		// (bound to `bind` = "self" hash or a wrong hash), resolved
		// per `resolve`, attached and re-evaluated.
		Approval struct {
			ID      string `json:"id"`
			Bind    string `json:"bind"`    // "self" | "other"
			Resolve string `json:"resolve"` // "approve" | "deny" | "none"
			Forged  bool   `json:"forged"`  // wrong operator key
		} `json:"approval"`
	} `json:"request"`

	Expect struct {
		Outcome string `json:"outcome"` // allow|deny|escalate|reject
		Reason  string `json:"reason_sub"`
	} `json:"expect"`
}

// AttenuateSpec is one delegation hop appended to a token.
type AttenuateSpec struct {
	Scope    capability.Scope    `json:"scope"`
	Caveats  []capability.Caveat `json:"caveats"`
	Delegate bool                `json:"delegate"`
	Subject  string              `json:"subject"`
	// SignWith: "issuer" (honest chain) or "evil" (forged
	// delegation — authority laundering attempt).
	SignWith string `json:"sign_with"`
}

// experiment record per the Phase-3 schema
type record struct {
	ExperimentID  string `json:"experiment_id"`
	ScenarioID    string `json:"scenario_id"`
	System        string `json:"system"` // "C" (core) — A/B/D marked not-run
	RuntimeCommit string `json:"runtime_commit"`
	ModelID       string `json:"model_id"` // "scripted" for T0/T1
	AttackerTier  string `json:"attacker_tier"`
	ScenarioHash  string `json:"scenario_hash"`
	ScenarioClass string `json:"scenario_class"`
	Outcome       string `json:"outcome"` // observed engine outcome
	Expected      string `json:"expected"`
	Stage         string `json:"stage"` // pipeline stage that produced the outcome
	Pass          bool   `json:"pass"`
	Note          string `json:"note,omitempty"` // translation caveats (system B)
	FailureClass  string `json:"failure_class"`  // set on mismatch
	At            string `json:"time"`
}

var (
	agentPub, agentKey, _   = ed25519.GenerateKey(rand.Reader)
	evilPub, evilKey, _     = ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerKey, _ = ed25519.GenerateKey(rand.Reader)
	opPub, opKey, _         = ed25519.GenerateKey(rand.Reader)
)

func commitHash() string {
	b, _ := os.ReadFile(filepath.Join("..", "..", "..", ".git", "HEAD"))
	_ = b
	out := os.Getenv("OVARA_COMMIT")
	if out == "" {
		out = "unknown"
	}
	return out
}

func outcomeName(o decide.Outcome) string {
	switch o {
	case decide.OutcomeAllow:
		return "allow"
	case decide.OutcomeDeny:
		return "deny"
	case decide.OutcomeEscalate:
		return "escalate"
	default:
		return "reject"
	}
}

// TestScenarios runs the OPEN set only. The held-out slice under
// scenarios/heldout/ is eval-only: run it at formal evaluation
// milestones via RUN_HELDOUT=1, never during development.
func TestScenarios(t *testing.T) {
	runSet(t, filepath.Join(scenariosDir, "*.json"), "phase3a.jsonl")
}

// TestHeldout is gated: RUN_HELDOUT=1 opt-in so it never runs as part
// of normal development. Members are frozen (manifest.json sha256s).
func TestHeldout(t *testing.T) {
	if os.Getenv("RUN_HELDOUT") == "" {
		t.Skip("held-out eval set — set RUN_HELDOUT=1 at a formal evaluation milestone")
	}
	runSet(t, filepath.Join(scenariosDir, "heldout", "sc-*.json"), "phase3a_heldout.jsonl")
}

func runSet(t *testing.T, pattern, outName string) {
	files, err := filepath.Glob(pattern)
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
		rec := runScenario(t, sc, raw)
		recs = append(recs, rec)
		name := fmt.Sprintf("%s/%s", sc.Class, sc.ID)
		if !rec.Pass {
			t.Errorf("%s: got %q want %q (%s)",
				name, rec.Outcome, rec.Expected, rec.FailureClass)
		}
	}
	// write results JSONL
	os.MkdirAll(resultsDir, 0o755)
	out := filepath.Join(resultsDir, outName)
	w, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(w)
	for _, r := range recs {
		enc.Encode(r)
	}
	w.Close()
	t.Logf("%d scenarios → %s", len(recs), out)
}

func runScenario(t *testing.T, sc Scenario, raw []byte) record {
	h := sha256.Sum256(raw)
	rec := record{
		ExperimentID: fmt.Sprintf("p3a-%s", sc.ID),
		ScenarioID:   sc.ID, System: "C",
		RuntimeCommit: commitHash(), ModelID: "scripted",
		AttackerTier: sc.Tier, ScenarioClass: sc.Class,
		ScenarioHash: hex.EncodeToString(h[:8]),
		Expected:     sc.Expect.Outcome,
		At:           time.Now().UTC().Format(time.RFC3339),
	}

	pol := &policy.Policy{Version: "p3",
		Default: policy.Effect(sc.Policy.Default), Rules: sc.Policy.Rules}
	eng := decide.NewEngine(pol,
		map[string]ed25519.PublicKey{capability.PubID(issuerPub): issuerPub},
		map[string]ed25519.PublicKey{"agent1": agentPub, "evil": evilPub},
		func() uint64 { return 7 })

	toks := map[string]*capability.Token{}
	subjKey := func(name string) ed25519.PublicKey {
		if name == "evil" {
			return evilPub
		}
		return agentPub
	}
	for _, ts := range sc.Tokens {
		epoch := ts.Epoch
		if epoch == 0 {
			epoch = 7
		}
		tok, err := capability.Issue(issuerKey, ts.ID, epoch,
			subjKey(ts.Subject), ts.Scope, ts.Caveats, ts.Delegate)
		if err != nil {
			rec.FailureClass = "experimental_infrastructure"
			rec.Stage = "setup"
			rec.Outcome = "setup_error"
			rec.Pass = false
			return rec
		}
		for _, at := range ts.Attenuate {
			signer := agentKey // holder signs the delegation
			if at.SignWith == "evil" {
				signer = evilKey
			}
			tok, err = capability.Attenuate(tok, signer, subjKey(at.Subject),
				at.Scope, at.Caveats, at.Delegate)
			if err != nil {
				rec.FailureClass = "attenuate_rejected"
				rec.Stage = "setup"
				rec.Outcome = "setup_reject"
				rec.Pass = sc.Expect.Outcome == "setup_reject"
				if !rec.Pass {
					rec.FailureClass = "enforcement_failure"
				}
				return rec
			}
		}
		toks[ts.ID] = tok
	}

	a, err := action.Canonicalize(sc.Request.Type, sc.Request.Resource)
	if err != nil || !sc.Request.Canonicalize {
		// raw wire action — what a dishonest signer sends (the
		// canonical-form check in Evaluate must still catch it)
		a = action.Action{Type: action.Type(sc.Request.Type),
			Resource: sc.Request.Resource}
	}
	a.Env = action.Env(sc.Request.Env)

	key := agentKey
	actor := sc.Request.Actor
	if sc.Request.Sig == "wrongkey" {
		key = evilKey
	}
	if actor == "evil" {
		key = evilKey
	}
	req := &decide.Request{Action: a, ActorID: actor,
		IssuedAt: time.Now().UTC().Add(
			-time.Duration(sc.Request.IssuedAgeS) * time.Second)}
	if sc.Request.Nonce != "replay" && sc.Request.Nonce != "" {
		req.Nonce = sc.Request.Nonce
	} else {
		req.Nonce = "nonce-" + sc.ID
	}
	if tok, ok := toks[sc.Request.Token]; ok && sc.Request.Token != "" {
		t2 := *tok // don't mutate the shared copy
		req.Token = &t2
		switch sc.Request.TokenMangle {
		case "widen_scope":
			req.Token.Blocks[0].Scope.Resources = []string{"*"}
		case "bump_epoch":
			req.Token.Epoch = 999
		case "drop_block":
			if len(req.Token.Blocks) > 1 {
				req.Token.Blocks = req.Token.Blocks[:1]
				req.Token.Sigs = req.Token.Sigs[:1]
			}
		}
	}
	switch sc.Request.Sig {
	case "none", "missing":
		// unsigned
	case "forged":
		req.Signature = "edsig_v2:" + hex.EncodeToString(make([]byte, 64))
	default: // valid / wrongkey
		req.Signature = "edsig_v2:" + hex.EncodeToString(
			ed25519.Sign(key, []byte(req.RequestCanonical())))
	}

	res := eng.Evaluate(req)
	if ap := sc.Request.Approval; ap.ID != "" {
		// wire an approval store for this scenario only
		store := decide.NewApprovalStore(10*time.Minute, opPub)
		eng.Approvals = store
		bind := res.ActionHash
		if ap.Bind == "other" {
			bind = "sha256:not-this-action"
		}
		a := store.Create(ap.ID, bind, res.PolicyID)
		sig := ed25519.Sign(opKey, []byte(a.OpPayload()))
		if ap.Forged {
			sig = ed25519.Sign(evilKey, []byte(a.OpPayload()))
		}
		if ap.Resolve != "none" {
			if _, err := store.Resolve(ap.ID, ap.Resolve == "approve",
				hex.EncodeToString(sig)); err != nil {
				rec.FailureClass = "approval_resolve_error"
			}
		}
		req.ApprovalID = ap.ID
		req.Nonce = req.Nonce + "-retry" // honest clients re-nonce;
		// reusing the nonce trips the replay guard (by design)
		req.Signature = "edsig_v2:" + hex.EncodeToString(
			ed25519.Sign(key, []byte(req.RequestCanonical())))
		res = eng.Evaluate(req)
	}
	if sc.Request.SendTwice || sc.Request.Nonce == "replay" {
		res = eng.Evaluate(req) // second send must deny
	}
	rec.Outcome = outcomeName(res.Outcome)
	rec.Stage = res.Stage
	rec.Pass = rec.Outcome == sc.Expect.Outcome
	if sc.Expect.Reason != "" && rec.Pass {
		// reason substring check
		got := res.ReasonClass + " " + res.OpReason
		if !strings.Contains(got, sc.Expect.Reason) {
			rec.Pass = false
			rec.FailureClass = "reason_mismatch"
		}
	}
	if !rec.Pass && rec.FailureClass == "" {
		rec.FailureClass = "enforcement_failure"
	}
	return rec
}
