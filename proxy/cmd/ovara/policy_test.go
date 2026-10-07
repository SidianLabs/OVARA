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
	if !strings.Contains(allowed, "GET *") || !strings.Contains(allowed, "git-upload-pack") {
		t.Errorf("reads/fetch not under ALLOWED:\n%s", s)
	}
	if !strings.Contains(ask, "POST *") || !strings.Contains(ask, "anything") {
		t.Errorf("writes/catch-all not under ASK ME FIRST:\n%s", s)
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
