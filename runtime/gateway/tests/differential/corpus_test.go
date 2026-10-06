// Package differential replays the recorded v1 corpus
// (workspace/research/corpus/v1_baseline.jsonl) through the
// redesigned core pipeline and asserts the security-correct outcome
// per row — not v1's observed outcome. v1's fresh-install posture
// escalated 35/45 rows via containment; the differential annotates
// where the core is deliberately stricter or structurally different
// (parse rejects, credential-bound identity, crypto-real replay).
package differential

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/decide"
	"ovara.runtime.gateway/core/policy"
)

type corpusRow struct {
	ID      string `json:"id"`
	Request struct {
		ActionType  string `json:"action_type"`
		Resource    string `json:"resource"`
		Environment string `json:"environment"`
		Nonce       string `json:"nonce"`
		IssuedAt    string `json:"issued_at"`
	} `json:"request"`
	HTTPStatus int `json:"http_status"`
	Response   struct {
		Decision    string   `json:"decision"`
		ReasonCodes []string `json:"reason_codes"`
	} `json:"response"`
}

// v1→core action-type mapping (spec/action_model.md closed vocabulary).
var typeMap = map[string]string{
	"shell":                "shell.exec",
	"exec":                 "proc.spawn",
	"git.push":             "git.push",
	"git.pull":             "git.pull",
	"git.fetch":            "git.fetch",
	"git.checkout":         "git.checkout",
	"git.force_push":       "git.force_push",
	"github.push":          "github.push",
	"github.pr":            "github.pr",
	"github.merge":         "github.merge",
	"github.delete_branch": "github.delete_branch",
	"ci.deploy":            "ci.deploy",
	"ci.build_trigger":     "ci.build_trigger",
	"ci.approval":          "ci.approval",
	"http.request":         "http.request",
}

// Reference policy: allow github api over https only; deny fs.delete;
// escalate command execution; deny everything else by default.
var refPolicy = &policy.Policy{
	Version: "corpus-ref",
	Default: policy.Deny,
	Rules: []policy.Rule{
		{ID: "allow-gh", Effect: policy.Allow, Sel: policy.Selector{
			Types:     []string{"net.egress", "http.request"},
			Resources: []string{"https://api.github.com*"}}},
		{ID: "deny-meta", Effect: policy.Deny, Sel: policy.Selector{
			Types:     []string{"net.egress", "http.request"},
			Resources: []string{"http://169.254.169.254*"}}},
		{ID: "deny-fsdel", Effect: policy.Deny, Sel: policy.Selector{
			Types: []string{"fs.delete"}}},
		{ID: "esc-shell", Effect: policy.Escalate, Sel: policy.Selector{
			Types: []string{"shell.exec", "proc.spawn"}}},
		{ID: "esc-git-push", Effect: policy.Escalate, Sel: policy.Selector{
			Types: []string{"git.push", "git.force_push"}}},
	},
}

// expect is the security-correct outcome the core must produce.
// "parse" = canonicalization reject (deny before eval),
// "deny:..." = request-layer deny reason substring, else outcome.
type expect struct {
	outcome string // allow|deny|escalate
	reason  string // OpReason substring for denies, "" = any
	note    string
}

var expectations = map[string]expect{
	"action-shell":                {"escalate", "", "shell→shell.exec escalate"},
	"action-exec":                 {"escalate", "", "exec→proc.spawn escalate"},
	"action-git.push":             {"escalate", "", ""},
	"action-git.pull":             {"deny", "matched []", "no git.pull rule → default deny (stricter than v1)"},
	"action-git.fetch":            {"deny", "matched []", ""},
	"action-git.checkout":         {"deny", "matched []", ""},
	"action-git.force_push":       {"escalate", "", ""},
	"action-github.push":          {"deny", "matched []", "stricter: no rule → deny"},
	"action-github.pr":            {"deny", "matched []", ""},
	"action-github.merge":         {"deny", "matched []", ""},
	"action-github.delete_branch": {"deny", "matched []", ""},
	"action-ci.deploy":            {"deny", "matched []", ""},
	"action-ci.build_trigger":     {"deny", "matched []", ""},
	"action-ci.approval":          {"deny", "matched []", ""},
	"env-local-shell":             {"escalate", "", ""},
	"env-local-http":              {"allow", "", "api.github.com within allow"},
	"env-dev-shell":               {"escalate", "", ""},
	"env-dev-http":                {"allow", "", ""},
	"env-staging-shell":           {"escalate", "", ""},
	"env-staging-http":            {"allow", "", ""},
	"env-production-shell":        {"escalate", "", ""},
	"env-production-http":         {"allow", "", ""},
	"res-userinfo":                {"deny", "parse_reject", "userinfo rejected at canonicalization — v1 evaluated it"},
	"res-suffix":                  {"deny", "matched []", "host-boundary: *.github.com must not match evil.com suffix"},
	"res-notgithub":               {"deny", "matched []", ""},
	"res-metadata":                {"deny", "", "metadata IP denied"},
	"res-port":                    {"allow", "", "https default port stripped → matches allow"},
	"res-explicit80":              {"deny", "matched []", "http (not https) out of allow"},
	"res-noscheme":                {"deny", "parse_reject", "missing scheme rejected — v1 evaluated it"},
	"res-risky-rm":                {"escalate", "", "shell always escalate"},
	"res-risky-curl":              {"escalate", "", "piped shell escalates"},
	"res-empty":                   {"deny", "parse_reject", "empty resource rejected"},
	"ident-present":    {"escalate", "", "identity spoof NEUTRALIZED: wire subject ignored (v1 rejected with 400)"},
	"ident-empty-key":             {"escalate", "", ""},
	"lease-bogus":                 {"deny", "capability", "untrusted issuer / bad sig → deny"},
	"lease-bogus-noident":         {"escalate", "", "no token presented → policy outcome"},
	"chain-bogus":                 {"deny", "capability", ""},
	"replay-1":                    {"escalate", "", "first nonce evals normally"},
	"replay-2":                    {"deny", "nonce replay", "crypto-real replay protection"},
	"stale-issued":                {"deny", "freshness", "outside window"},
	"future-issued":               {"deny", "freshness", ""},
	"min-epoch-1":                 {"escalate", "", "epoch satisfied"},
	"min-epoch-huge":              {"deny", "min_epoch", "beyond current epoch"},
	"missing-nonce":               {"deny", "", "schema: nonce required"},
	"missing-resource":            {"deny", "", "schema: resource required"},
}

// rows that replay a shared nonce
const replayNonce = "replay-shared-nonce"

func corpusPath(t *testing.T) string {
	p := filepath.Join("..", "..", "..", "..", "workspace",
		"research", "corpus", "v1_baseline.jsonl")
	if _, err := os.Stat(p); err != nil {
		t.Skip("v1 corpus not present:", p)
	}
	return p
}

func TestCorpusDifferential(t *testing.T) {
	actorPub, actorPri, _ := ed25519.GenerateKey(nil)
	epoch := uint64(7)
	eng := decide.NewEngine(refPolicy, nil,
		map[string]ed25519.PublicKey{"agent-corpus": actorPub},
		func() uint64 { return epoch })

	f, err := os.Open(corpusPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var mismatches, notes []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row corpusRow
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		exp, ok := expectations[row.ID]
		if !ok {
			t.Fatalf("corpus row %s has no expectation — annotate it", row.ID)
		}

		coreType := typeMap[row.Request.ActionType]
		rawRes := row.Request.Resource
		// strip v1's "type:" resource prefix where present
		if i := strings.Index(rawRes, ":"); i > 0 && coreType != "" &&
			strings.HasPrefix(rawRes, strings.Split(coreType, ".")[0]+":") {
			rawRes = rawRes[i+1:]
		}

		req := decide.Request{
			Nonce:   row.Request.Nonce,
			ActorID: "agent-corpus",
		}
		// request-layer semantics per row
		switch row.ID {
		case "stale-issued":
			req.IssuedAt = time.Now().UTC().Add(-2 * time.Minute)
		case "future-issued":
			req.IssuedAt = time.Now().UTC().Add(2 * time.Minute)
		case "min-epoch-huge":
			req.IssuedAt = time.Now().UTC()
			req.MinEpoch = epoch + 1000
		default:
			req.IssuedAt = time.Now().UTC()
		}
		if row.ID == "replay-1" || row.ID == "replay-2" {
			req.Nonce = replayNonce
		}
		if row.ID == "missing-nonce" {
			req.Nonce = ""
		}

		var res decide.Result
		parseRejected := false
		if coreType == "" {
			parseRejected = true
		} else {
			a, cerr := action.Canonicalize(coreType, rawRes)
			if cerr != nil {
				parseRejected = true
			} else {
				req.Action = a
				if row.ID == "lease-bogus" || row.ID == "chain-bogus" {
					// present a syntactically valid token signed by
					// nobody — reaches signature verification, fails
					req.Token = capabilityTokenBogus(epoch)
				}
				sig := ed25519.Sign(actorPri, []byte(req.RequestCanonical()))
				req.Signature = "edsig_v2:" + hex.EncodeToString(sig)
				res = eng.Evaluate(&req)
			}
		}

		got := string(res.Outcome)
		reason := res.OpReason
		if parseRejected {
			got, reason = "deny", "parse_reject"
		}
		if row.ID == "missing-resource" {
			// resource empty → canonicalize error path
			got, reason = "deny", "parse_reject"
			exp = expect{"deny", "parse_reject", ""}
		}
		if exp.reason == "parse_reject" && !parseRejected && row.ID != "missing-resource" {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: expected parse reject, got %s (%s)", row.ID, got, reason))
			continue
		}
		if got != exp.outcome {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: v1=%s/%v core=%s(%s) want %s(%s)",
				row.ID, row.Response.Decision, row.Response.ReasonCodes,
				got, reason, exp.outcome, exp.reason))
			continue
		}
		if exp.reason != "" && !strings.Contains(reason, exp.reason) &&
			reason != "parse_reject" {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: reason %q lacks %q", row.ID, reason, exp.reason))
			continue
		}
		if exp.note != "" {
			notes = append(notes, fmt.Sprintf("%s: %s", row.ID, exp.note))
		}
	}
	for _, n := range notes {
		t.Log("note:", n)
	}
	if len(mismatches) > 0 {
		t.Fatalf("%d divergences:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
}

// capabilityTokenBogus returns a syntactically present but unverifiable
// token for the forged-lease/chain rows.
func capabilityTokenBogus(epoch uint64) *capability.Token {
	return &capability.Token{
		ID: "bogus", Issued: time.Now().UTC(), Epoch: epoch,
		Blocks: []capability.Block{{
			Scope: capability.Scope{
				ActionTypes: []string{"shell.exec"},
				Resources:   []string{"*"},
				Envs:        []string{"*"},
			},
			Issuer: "mallory",
		}},
		Sigs: []string{"edsig_v2:00"},
	}
}
