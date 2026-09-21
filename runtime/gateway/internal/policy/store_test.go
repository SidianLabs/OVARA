package policy

import (
	"testing"
)

func TestStore_RulesForAction(t *testing.T) {
	store := NewStore("v1")

	rules := store.RulesForAction("shell")
	if len(rules) == 0 {
		t.Error("expected rules for shell action")
	}
}

func TestStore_RulesForEnvironment(t *testing.T) {
	store := NewStore("v1")

	rules := store.RulesForEnvironment("local")
	if len(rules) == 0 {
		t.Error("expected rules for local environment")
	}
}

func TestStore_AddRule(t *testing.T) {
	store := NewStore("v1")
	initial := len(store.rules)

	store.AddRule(Rule{ActionType: "custom.action", Environment: "*", Allow: true})
	if len(store.rules) != initial+1 {
		t.Error("rule was not added")
	}
}

func TestPolicy_RuleTypes(t *testing.T) {
	r := Rule{ActionType: "shell", Environment: "local", Deny: true}
	if !r.Deny {
		t.Error("expected deny rule")
	}

	r2 := Rule{ActionType: "github.merge", Environment: "*", Escalate: true}
	if !r2.Escalate {
		t.Error("expected escalate rule")
	}
}
func TestMatchResource(t *testing.T) {
	cases := []struct {
		pattern, resource string
		want              bool
	}{
		{"", "GET https://anything.example/x", true},
		{"*https://api.github.com/*", "GET https://api.github.com/repos/o/r", true},
		{"*https://api.github.com/*", "POST https://api.github.com/x", true},
		{"*https://api.github.com/*", "GET https://evil.github.com.evil.com/x", false},
		{"GET https://pypi.org/*", "GET https://pypi.org/simple/", true},
		{"GET https://pypi.org/*", "POST https://pypi.org/simple/", false},
		{"GET https://pypi.org/*", "GET https://pypi.org/simple/", true},
		{"*webhook.site*", "POST https://webhook.site/abc", true},
		{"*webhook.site*", "POST https://github.com/x", false},
		{"exact", "exact", true},
		{"exact", "notexact", false},
		{"prefix*", "prefixsuffix", true},
		{"*suffix", "prefixsuffix", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
		{"*github.com*", "GET https://api.github.com/repos", true},
	}
	for _, c := range cases {
		if got := MatchResource(c.pattern, c.resource); got != c.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", c.pattern, c.resource, got, c.want)
		}
	}
}
