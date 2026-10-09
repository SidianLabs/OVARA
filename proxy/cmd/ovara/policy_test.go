package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The default policy, explained, must put each rule under the heading a
// person expects.
func TestExplainPolicy_DefaultPolicyGrouped(t *testing.T) {
	var rules []policyRule
	b, _ := json.Marshal(defaultPolicyRules())
	if err := json.Unmarshal(b, &rules); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	explainPolicy(&out, rules)
	s := out.String()
	blocked := s[strings.Index(s, "BLOCKED"):strings.Index(s, "ALLOWED")]
	allowed := s[strings.Index(s, "ALLOWED"):strings.Index(s, "ASK ME FIRST")]
	ask := s[strings.Index(s, "ASK ME FIRST"):]
	if !strings.Contains(blocked, "pastebin.com") {
		t.Errorf("pastebin not under BLOCKED:\n%s", s)
	}
	if !strings.Contains(allowed, "GET https://pypi.org/*") || !strings.Contains(allowed, "git-upload-pack") {
		t.Errorf("reads/fetch not under ALLOWED:\n%s", s)
	}
	if !strings.Contains(ask, "POST *") || !strings.Contains(ask, "anything") {
		t.Errorf("writes/catch-all not under ASK ME FIRST:\n%s", s)
	}
}

// The default policy must never allow a request to an arbitrary host
// without approval: a host-less allow rule is an exfiltration channel
// (the path and query of a read carry data just like a POST body).
func TestDefaultPolicyHasNoHostlessAllow(t *testing.T) {
	for _, r := range defaultPolicyRules() {
		if r["allow"] != true || r["action_type"] != "http.request" {
			continue // the commit-back path rules are not network rules
		}
		res, _ := r["resource"].(string)
		_, target, _ := strings.Cut(res, " ")
		if !strings.HasPrefix(target, "https://") {
			t.Errorf("allow rule %q is not pinned to an https host", res)
			continue
		}
		host, _, _ := strings.Cut(strings.TrimPrefix(target, "https://"), "/")
		if host == "" || strings.Contains(host, "*") {
			t.Errorf("allow rule %q does not name a single host", res)
		}
	}
}

func TestAdminClient_Simulate(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy/simulate" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", 404)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"Decision":"escalate","Reason":"policy_escalate","MatchedRule":"Writes need approval"}`))
	}))
	defer srv.Close()
	c := &adminClient{base: srv.URL, token: "tok", hc: srv.Client()}

	decision, rule, err := c.simulate("POST https://api.github.com/x", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if decision != "escalate" || rule != "Writes need approval" {
		t.Fatalf("got %q / %q", decision, rule)
	}
	req, _ := got["request"].(map[string]any)
	if got["use_current"] != true || req["resource"] != "POST https://api.github.com/x" || req["action_type"] != "http.request" {
		t.Fatalf("bad simulate body: %v", got)
	}
}
