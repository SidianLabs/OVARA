package proxy

import (
	"strings"
	"testing"

	"ovara.runtime.gateway/pkg/baseline"
)

// A refusal says which layer refused and what can change it.
func TestWithRule_SaysWhichLayerRefused(t *testing.T) {
	m := withRule(map[string]any{"error": "action denied"}, baseline.Label+"dump site")
	if m["rule"] != baseline.Label+"dump site" || !strings.Contains(m["hint"].(string), "organisation's baseline") {
		t.Fatalf("baseline refusal: %v", m)
	}
	m = withRule(map[string]any{"error": "action denied"}, "no other writes in CI")
	if !strings.Contains(m["hint"].(string), "project's policy") {
		t.Fatalf("project refusal: %v", m)
	}
	m = withRule(map[string]any{"error": "held for approval", "hint": "a person is deciding"}, "writes ask")
	if m["hint"] != "a person is deciding" || m["rule"] != "writes ask" {
		t.Fatalf("an existing hint is kept: %v", m)
	}
	m = withRule(map[string]any{"error": "approval timeout"}, "writes ask")
	if _, has := m["hint"]; has || m["rule"] != "writes ask" {
		t.Fatalf("a hold that ran out is not a refusal by a rule: %v", m)
	}
	m = withRule(map[string]any{"error": "action denied"}, "")
	if _, has := m["rule"]; has {
		t.Fatalf("no rule, no rule member: %v", m)
	}
	if _, has := m["hint"]; has {
		t.Fatalf("no rule, no hint: %v", m)
	}
}
