package evaluator

import (
	"testing"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

const receivePack = "POST https://github.com/acme/app.git/git-receive-pack"

// A push that updates several refs is decided ref by ref, and the push
// gets the strictest answer: an allow for feature branches must not carry
// a push to main along with it.
func TestGitPush_EachRefDecidedOnItsOwn(t *testing.T) {
	for _, prec := range []string{policy.PrecedenceMostSpecific, policy.PrecedenceOrder} {
		st := specificStore(
			rule(receivePack+" refs/heads/feature/*", "allow", "feature branches"),
			rule(receivePack+" refs/heads/release/*", "deny", "no release pushes"),
		)
		st.SetPrecedence(prec)
		cases := []struct {
			refs string
			want models.Decision
		}{
			{"refs/heads/feature/x", models.DecisionAllow},
			{"refs/heads/feature/x,refs/heads/feature/y", models.DecisionAllow},
			// main matches nothing → default escalate; the push escalates
			{"refs/heads/feature/x,refs/heads/main", models.DecisionEscalate},
			{"refs/heads/main,refs/heads/feature/x", models.DecisionEscalate},
			// any denied ref denies the whole push
			{"refs/heads/feature/x,refs/heads/release/1,refs/heads/main", models.DecisionDeny},
			// deleting a branch is not a push to it: the allow does not cover it
			{"refs/heads/feature/x(delete)", models.DecisionEscalate},
			{"refs/heads/feature/x,refs/heads/feature/y(delete)", models.DecisionEscalate},
		}
		for _, c := range cases {
			if d, _ := decide(t, st, models.EnvironmentDev, receivePack+" "+c.refs); d != c.want {
				t.Errorf("%s: %s: got %s, want %s", prec, c.refs, d, c.want)
			}
		}
	}
}

// A rule that names deletions still matches them, and deny rules still
// match any ref, including deletions.
func TestGitPush_DeleteRules(t *testing.T) {
	st := specificStore(
		rule(receivePack+" refs/heads/feature/*(delete)", "allow", "delete feature branches"),
		rule(receivePack+" refs/heads/feature/*", "allow", "feature branches"),
		rule(receivePack+" refs/heads/main*", "deny", "main is protected"),
	)
	if d, _ := decide(t, st, models.EnvironmentDev, receivePack+" refs/heads/feature/x(delete)"); d != models.DecisionAllow {
		t.Errorf("named deletion: %s", d)
	}
	if d, _ := decide(t, st, models.EnvironmentDev, receivePack+" refs/heads/feature/x(delete),refs/heads/main(delete)"); d != models.DecisionDeny {
		t.Errorf("deleting main: %s", d)
	}
}

// The proxy's markers for a push it could not read are matched as one
// resource, not split.
func TestGitPush_UnparsedMarkersNotSplit(t *testing.T) {
	st := specificStore(
		rule(receivePack+" refs/heads/*", "allow", "any branch"),
		rule(receivePack+" git-receive-pack*", "deny", "unreadable push"),
	)
	for _, m := range []string{"git-receive-pack", "git-receive-pack(truncated)"} {
		if d, _ := decide(t, st, models.EnvironmentDev, receivePack+" "+m); d != models.DecisionDeny {
			t.Errorf("%s: %s", m, d)
		}
	}
}

func TestSplitRefList(t *testing.T) {
	got := policy.SplitRefList(receivePack + " refs/heads/a,refs/heads/b(delete)")
	if len(got) != 2 || got[0] != receivePack+" refs/heads/a" || got[1] != receivePack+" refs/heads/b(delete)" {
		t.Fatalf("split: %q", got)
	}
	for _, r := range []string{
		receivePack + " refs/heads/a",
		receivePack + " git-receive-pack(truncated)",
		receivePack,
		"shell:git push a,b",
		receivePack + " refs/heads/a,https://evil.example/",
	} {
		if got := policy.SplitRefList(r); len(got) != 1 || got[0] != r {
			t.Errorf("%q split into %q", r, got)
		}
	}
}
