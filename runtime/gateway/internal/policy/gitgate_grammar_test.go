package policy

import "testing"

// The proxy's git gate emits these exact forms. If the gateway's resource
// grammar rejects them, canonicalization fails and ref-specific rules (for
// example "require approval for any branch deletion") can never match.
func TestCanonicalResourceAcceptsGitGateForms(t *testing.T) {
	const url = "POST https://github.com/acme/app.git/git-receive-pack"
	for _, suffix := range []string{
		" refs/heads/main",
		" refs/heads/main,refs/tags/v1",
		" refs/heads/old(delete)",
		" refs/heads/a,refs/heads/b(delete)",
		" git-receive-pack",
		" git-receive-pack(truncated)",
	} {
		if _, ok := CanonicalResource(url + suffix); !ok {
			t.Errorf("CanonicalResource rejected the proxy's own form %q", suffix)
		}
	}
}

// Anything that is not one of those forms must still be refused: the slot
// after the URL is where a second URL would hide.
func TestCanonicalResourceStillRejectsSmuggling(t *testing.T) {
	const url = "POST https://github.com/acme/app.git/git-receive-pack"
	for _, suffix := range []string{
		" https://evil.example/",
		" refs/heads/main https://evil.example/",
		" git-receive-pack-evil",
		" (delete)",
		" refs/heads/x(delete)(delete)x",
		" notrefs/heads/main",
	} {
		if _, ok := CanonicalResource(url + suffix); ok {
			t.Errorf("CanonicalResource accepted %q", suffix)
		}
	}
}

func TestDeleteRuleMatchesDeletions(t *testing.T) {
	res := "POST https://github.com/acme/app.git/git-receive-pack refs/heads/old(delete)"
	if !MatchResource("POST https://github.com/*(delete)", res) {
		t.Error("a rule on the (delete) marker should match a branch deletion")
	}
	plain := "POST https://github.com/acme/app.git/git-receive-pack refs/heads/old"
	if MatchResource("POST https://github.com/*(delete)", plain) {
		t.Error("a deletion rule matched an ordinary push")
	}
}
