package evaluator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// Policy-precedence conformance vectors for contract C2: a policy document
// and a request in, a decision and the deciding rule out. Generated from the
// reference evaluator so a second implementation can check its precedence
// resolution (order vs most-specific, deny breaks ties, the default). Pairs
// with the C1/C2 primitive vectors in internal/policy (match, canonical,
// specificity). See conformance/README.md.
//
//	OVARA_WRITE_CONFORMANCE=1 go test ./internal/evaluator -run TestConformancePrecedence

// precedenceCase is one policy and the requests run against it.
type precedenceCase struct {
	name   string
	policy string
	reqs   []precReq
}

type precReq struct {
	actionType  string
	environment string
	resource    string
}

var precedenceCorpus = []precedenceCase{
	{
		name: "order-deny-wins",
		// order precedence (the default): any matching deny wins, else the
		// first matching rule; no match falls to the default (escalate).
		policy: `{"version":"c2-order","rules":[
			{"action_type":"http.request","environment":"*","resource":"*github.com*","allow":true,"description":"reads from github"},
			{"action_type":"http.request","environment":"*","resource":"POST *","deny":true,"description":"no writes"}
		]}`,
		reqs: []precReq{
			{"http.request", "local", "GET https://api.github.com/x"},  // only allow matches
			{"http.request", "local", "POST https://api.github.com/x"}, // allow and deny match -> deny wins
			{"http.request", "local", "GET https://example.com/x"},     // nothing matches -> default escalate
		},
	},
	{
		name: "most-specific-wins",
		// most-specific precedence with an explicit deny default: the
		// highest-specificity matching rule decides.
		policy: `{"version":"c2-ms","precedence":"most-specific","default":"deny","rules":[
			{"action_type":"http.request","environment":"*","resource":"*","escalate":true,"description":"ask by default"},
			{"action_type":"http.request","environment":"*","resource":"GET https://pypi.org/*","allow":true,"description":"pypi reads"}
		]}`,
		reqs: []precReq{
			{"http.request", "local", "GET https://pypi.org/simple/x"}, // specific allow beats the "*" escalate
			{"http.request", "local", "GET https://example.com/x"},     // only "*" matches -> escalate
			{"shell", "local", "shell:rm -rf /"},                       // no http rule -> default deny
		},
	},
	{
		name: "most-specific-deny-breaks-tie",
		// two rules of equal specificity match; deny breaks the tie.
		policy: `{"version":"c2-tie","precedence":"most-specific","rules":[
			{"action_type":"http.request","environment":"*","resource":"POST *","allow":true,"description":"allow writes"},
			{"action_type":"http.request","environment":"*","resource":"POST *","deny":true,"description":"deny writes"}
		]}`,
		reqs: []precReq{
			{"http.request", "local", "POST https://example.com/x"}, // tie -> deny
		},
	},
}

type precedenceVector struct {
	Policy      string `json:"policy"`
	ActionType  string `json:"action_type"`
	Environment string `json:"environment"`
	Resource    string `json:"resource"`
	Decision    string `json:"decision"`
	MatchedRule string `json:"matched_rule,omitempty"`
}

func TestConformancePrecedence(t *testing.T) {
	var out []precedenceVector
	n := 0
	for _, c := range precedenceCorpus {
		store, err := policy.ParseStore([]byte(c.policy), "")
		if err != nil {
			t.Fatalf("%s: parse policy: %v", c.name, err)
		}
		ev := New(store)
		for _, r := range c.reqs {
			// A fresh timestamp and a unique nonce so the freshness and
			// replay checks pass and the policy is what decides; neither
			// value is part of the recorded vector.
			n++
			resp, err := ev.Evaluate(&models.ActionRequest{
				ActionType:  models.ActionType(r.actionType),
				Environment: models.Environment(r.environment),
				Resource:    r.resource,
				Nonce:       "conformance-" + strconv.Itoa(n),
				IssuedAt:    time.Now().UTC(),
				// A minimal identity so the request reaches policy; the
				// keyless reference validator only requires it be present.
				// Contract C2 is about the policy decision, not identity.
				AgentIdentity: &models.AgentIdentity{Issuer: "conformance", SubjectID: "agent"},
			})
			if err != nil {
				t.Fatalf("%s: evaluate %q: %v", c.name, r.resource, err)
			}
			out = append(out, precedenceVector{
				Policy: c.policy, ActionType: r.actionType, Environment: r.environment,
				Resource: r.resource, Decision: string(resp.Decision), MatchedRule: resp.MatchedRule,
			})
		}
	}

	file := struct {
		Comment string             `json:"comment"`
		Vectors []precedenceVector `json:"vectors"`
	}{
		Comment: "C2 policy-precedence conformance vectors generated from runtime/gateway/internal/evaluator; do not edit by hand (regenerate with OVARA_WRITE_CONFORMANCE=1 go test ./internal/evaluator -run TestConformancePrecedence). policy + (action_type, environment, resource) -> decision, matched_rule. See conformance/README.md.",
		Vectors: out,
	}
	buf, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	buf = append(buf, '\n')

	p := filepath.Join("..", "..", "..", "..", "conformance", "vectors", "precedence.json")
	if os.Getenv("OVARA_WRITE_CONFORMANCE") == "1" {
		if err := os.WriteFile(p, buf, 0o644); err != nil { //nolint:gosec // a committed, readable test fixture
			t.Fatalf("write %s: %v", p, err)
		}
		return
	}
	have, err := os.ReadFile(p) //nolint:gosec // a fixed in-repo path
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with OVARA_WRITE_CONFORMANCE=1)", p, err)
	}
	if !bytes.Equal(bytes.TrimRight(have, "\n"), bytes.TrimRight(buf, "\n")) {
		t.Fatalf("%s is out of date with the reference evaluator: regenerate with OVARA_WRITE_CONFORMANCE=1 go test ./internal/evaluator -run TestConformancePrecedence", p)
	}
}
