package evaluator

import (
	"testing"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// The precedence rules, checked against arbitrary patterns and resources:
//
//   - under order precedence, a request any part of which a deny matches
//     is denied;
//   - under most-specific precedence, a matching deny is overridden only by
//     an allow that matches the same part, is strictly more specific and
//     names the host at least as precisely;
//   - escalate never beats deny: with no allow in the policy, a matching
//     deny always denies;
//   - a push is never allowed when any one of its refs would not be.
func FuzzPrecedence(f *testing.F) {
	const push = "POST https://github.com/acme/app.git/git-receive-pack"
	seeds := [][4]string{
		{"POST *", "POST https://api.github.com/repos/acme/app/pulls", "POST https://api.github.com/*", "POST https://api.github.com/repos/acme/app/pulls"},
		{"*://pastebin.com/*", "GET https://*/*", "*", "GET https://pastebin.com:8443/x"},
		{"*://pastebin.com/*", "GET https://*/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*", "GET *", "GET https://pastebin.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{push + " refs/heads/release/*", push + " refs/heads/*", push + " *", push + " refs/heads/feature/x,refs/heads/release/1"},
		{push + " refs/heads/*(delete)", push + " refs/heads/feature/*", "", push + " refs/heads/feature/x(delete)"},
		{"GET https://api.github.com/*", "GET https://api.github.com/*", "GET https://api.github.com/*", "GET https://API.github.com./x"},
		{"", "*", "*", "shell:rm -rf /"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3], uint8(0))
	}
	f.Fuzz(func(t *testing.T, denyPat, allowPat, escPat, resource string, bits uint8) {
		env := models.EnvironmentDev
		if bits&1 != 0 {
			env = models.EnvironmentProduction
		}
		actionType := "http.request"
		scope := func(r policy.Rule, n uint) policy.Rule {
			if bits&(1<<n) != 0 {
				r.ActionType = "*"
			}
			if bits&(1<<(n+1)) != 0 {
				r.Environment = string(env)
			}
			return r
		}
		deny := scope(policy.Rule{ActionType: actionType, Environment: "*", Resource: denyPat, Deny: true}, 1)
		allow := scope(policy.Rule{ActionType: actionType, Environment: "*", Resource: allowPat, Allow: true}, 3)
		esc := scope(policy.Rule{ActionType: actionType, Environment: "*", Resource: escPat, Escalate: true}, 5)
		req := &models.ActionRequest{ActionType: models.ActionType(actionType), Resource: resource, Environment: env}

		parts := policy.SplitRefList(resource)
		denyHits := false
		for _, p := range parts {
			if ruleMatches(deny, p) {
				denyHits = true
			}
		}

		// Order precedence: any deny that matches decides.
		for _, withAllow := range []bool{true, false} {
			rules := []policy.Rule{esc, deny}
			if withAllow {
				rules = append([]policy.Rule{allow}, rules...)
			}
			st := storeOf(policy.PrecedenceOrder, rules...)
			o := New(st).evaluateRulesWithStore(st, req)
			if denyHits && !o.Denied {
				t.Fatalf("order: deny %q matched %q but outcome %+v", denyPat, resource, o)
			}
		}

		// Most-specific, no allow: escalate never softens a deny.
		st := storeOf(policy.PrecedenceMostSpecific, esc, deny)
		if o := New(st).evaluateRulesWithStore(st, req); denyHits && !o.Denied {
			t.Fatalf("most-specific: escalate %q beat deny %q on %q: %+v", escPat, denyPat, resource, o)
		}

		// Most-specific with an allow: an allowed request had, for every
		// part the deny matched, a matching allow that outranks it.
		st = storeOf(policy.PrecedenceMostSpecific, allow, esc, deny)
		o := New(st).evaluateRulesWithStore(st, req)
		if !o.Allowed {
			return
		}
		if o.Denied || o.Escalate {
			t.Fatalf("outcome both allowed and not: %+v", o)
		}
		key := func(r policy.Rule) [3]int {
			return [3]int{policy.Specificity(r.Resource), b2i(r.ActionType != "*"), b2i(r.Environment != "*")}
		}
		for _, p := range parts {
			if !ruleMatches(allow, p) {
				t.Fatalf("allowed %q although the allow %q does not match its part %q", resource, allowPat, p)
			}
			if !ruleMatches(deny, p) {
				continue
			}
			if !greater(key(allow), key(deny)) {
				t.Fatalf("allow %q beat a deny %q that is at least as specific on %q", allowPat, denyPat, p)
			}
			if policy.HostSpecificity(allowPat) < policy.HostSpecificity(denyPat) {
				t.Fatalf("allow %q beat deny %q naming the host less precisely on %q", allowPat, denyPat, p)
			}
		}
	})
}

func storeOf(precedence string, rules ...policy.Rule) *policy.Store {
	st := policy.NewStore("fuzz")
	st.ClearRules()
	st.SetPrecedence(precedence)
	for _, r := range rules {
		st.AddRule(r)
	}
	return st
}
