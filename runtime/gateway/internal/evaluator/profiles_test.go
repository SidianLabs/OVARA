package evaluator

import (
	"testing"

	"ovara.runtime.gateway/internal/models"
)

// The balanced and observe profiles (proxy/cmd/ovara/profiles.go) add
// catch-all read allows, and observe catch-all write denies, on top of the
// strict rules. Under most-specific precedence the strict guards keep
// deciding: a credentialed read of secrets still asks, a dump site is still
// refused, the trusted hosts match their own rule (so the proxy does not
// count them as open reads), and the model API stays reachable next to the
// write deny.
func TestMostSpecific_OpenReadProfilesKeepTheGuards(t *testing.T) {
	const open = "[profile observe] [open read] any public host"
	st := specificStore(
		rule("GET *", "allow", open),
		rule("HEAD *", "allow", open),
		rule("POST *", "deny", "[profile observe] no writes"),
		rule("GET https://api.github.com/user/emails", "escalate", "secrets need approval"),
		rule("GET https://slack.com/api/*", "escalate", "slack rpc"),
		rule("*://pastebin.com/*", "deny", "dump site"),
		rule("POST https://api.anthropic.com/v1/messages", "allow", "the model"),
		rule("GET https://pypi.org/*", "allow", "trusted reads"),
	)
	cases := []struct {
		res  string
		want models.Decision
		rule string // "" = not checked
	}{
		{"GET https://docs.example.org/page", models.DecisionAllow, open},
		{"HEAD https://docs.example.org/page", models.DecisionAllow, open},
		{"GET https://pypi.org/simple/", models.DecisionAllow, "trusted reads"},
		{"GET https://api.github.com/user/emails", models.DecisionEscalate, "secrets need approval"},
		{"GET https://slack.com/api/chat.postMessage", models.DecisionEscalate, "slack rpc"},
		{"GET https://pastebin.com/raw/abc", models.DecisionDeny, "dump site"},
		{"POST https://api.anthropic.com/v1/messages", models.DecisionAllow, "the model"},
		{"POST https://docs.example.org/upload", models.DecisionDeny, "[profile observe] no writes"},
		{"POST https://pastebin.com/api/post", models.DecisionDeny, ""},
	}
	for _, c := range cases {
		d, r := decide(t, st, models.EnvironmentDev, c.res)
		if d != c.want || (c.rule != "" && r != c.rule) {
			t.Errorf("%s: got %s / %q, want %s / %q", c.res, d, r, c.want, c.rule)
		}
	}
}
