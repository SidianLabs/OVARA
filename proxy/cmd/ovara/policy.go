package main

// `ovara policy` explains the rules in plain English, and
// `ovara policy test "<METHOD URL>"` asks the running gateway what it
// would decide for that request (a dry run: nothing is sent anywhere,
// no approval is opened) and which rule decided.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ovara.proxy/internal/config"
)

type policyRule struct {
	ActionType  string `json:"action_type"`
	Environment string `json:"environment"`
	Resource    string `json:"resource"`
	Allow       bool   `json:"allow"`
	Deny        bool   `json:"deny"`
	Escalate    bool   `json:"escalate"`
	Description string `json:"description"`
}

func cmdPolicy(args []string) error {
	if len(args) > 0 && args[0] == "test" {
		return cmdPolicyTest(args[1:])
	}
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory (where `ovara init` wrote policy.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "policy.json"))
	if err != nil {
		return fmt.Errorf("cannot read policy.json in %s: %w", *dir, err)
	}
	var pol struct {
		Version string       `json:"version"`
		Rules   []policyRule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return fmt.Errorf("policy.json: %w", err)
	}
	explainPolicy(os.Stdout, pol.Rules)
	return nil
}

// explainPolicy prints rules grouped by effect, in the order the gateway
// applies them: blocks first, then allows, then "ask me".
func explainPolicy(w io.Writer, rules []policyRule) {
	groups := []struct {
		title string
		pick  func(policyRule) bool
	}{
		{"BLOCKED (always, no question asked)", func(r policyRule) bool { return r.Deny }},
		{"ALLOWED (goes straight through)", func(r policyRule) bool { return r.Allow && !r.Deny }},
		{"ASK ME FIRST (paused until you approve)", func(r policyRule) bool { return r.Escalate && !r.Allow && !r.Deny }},
	}
	for _, g := range groups {
		fmt.Fprintf(w, "%s\n", g.title)
		n := 0
		for _, r := range rules {
			if !g.pick(r) {
				continue
			}
			n++
			what := r.Resource
			if what == "" {
				what = "anything"
			}
			scope := ""
			if r.ActionType != "" && r.ActionType != "*" && r.ActionType != "http.request" {
				scope = " [" + r.ActionType + "]"
			}
			if r.Environment != "" && r.Environment != "*" {
				scope += " [env " + r.Environment + "]"
			}
			if r.Description != "" {
				fmt.Fprintf(w, "  • %s\n      matches: %s%s\n", r.Description, what, scope)
			} else {
				fmt.Fprintf(w, "  • %s%s\n", what, scope)
			}
		}
		if n == 0 {
			fmt.Fprintln(w, "  (none)")
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "If several rules match: blocked beats allowed, allowed beats ask-me.")
	fmt.Fprintln(w, "Anything no rule matches is ask-me. Edit policy.json; changes apply without a restart.")
	fmt.Fprintln(w, `Try one:  ovara policy test "POST https://api.github.com/repos/acme/app/pulls"`)
}

func cmdPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory")
	var request string
	var rest []string
	for _, a := range args {
		if request == "" && !strings.HasPrefix(a, "-") {
			request = a
			continue
		}
		rest = append(rest, a)
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if request == "" {
		return fmt.Errorf(`usage: ovara policy test "<METHOD> <URL>" [-dir .]   e.g. "GET https://pypi.org/simple/"`)
	}
	method, url, ok := strings.Cut(strings.TrimSpace(request), " ")
	if !ok || !strings.Contains(url, "://") {
		return fmt.Errorf("expected \"<METHOD> <URL>\", e.g. \"POST https://api.github.com/repos/o/r/pulls\"")
	}
	resource := strings.ToUpper(method) + " " + url

	env := "dev"
	if cfg, err := config.Load(filepath.Join(*dir, "proxy.json")); err == nil && cfg.Environment != "" {
		env = cfg.Environment
	}
	c, err := newAdminClient(*dir)
	if err != nil {
		return err
	}
	decision, rule, err := c.simulate(resource, env)
	if err != nil {
		return err
	}
	verdict := map[string]string{
		"allow":    "ALLOWED: it would go straight through",
		"deny":     "BLOCKED: it would be refused",
		"escalate": "ASK ME FIRST: it would pause until you approve",
	}[decision]
	if verdict == "" {
		verdict = decision
	}
	fmt.Printf("%s\n  → %s\n", describe(resource), verdict)
	if rule != "" {
		fmt.Printf("  because of the rule: %s\n", rule)
	} else if decision == "escalate" {
		fmt.Println("  because no rule matches it (unmatched requests always ask)")
	}
	return nil
}

// simulate asks the gateway to evaluate resource against the live policy
// without recording or executing anything.
func (c *adminClient) simulate(resource, env string) (decision, rule string, err error) {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	body := map[string]any{
		"use_current": true,
		"request": map[string]any{
			"action_type": "http.request",
			"resource":    resource,
			"environment": env,
			"agent_identity": map[string]string{
				"issuer": "ovara-cli", "subject_id": "policy-test",
			},
			"nonce":     hex.EncodeToString(nonce),
			"issued_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
	var out struct {
		Decision    string
		Reason      string
		MatchedRule string
	}
	if err := c.do("POST", "/v1/policy/simulate", body, &out); err != nil {
		return "", "", err
	}
	return out.Decision, out.MatchedRule, nil
}
