package policy

import "testing"

// Attack matrix for SEC-0010: authorization must be decided on the
// canonical destination, not the raw request string.
func TestMatchResource_CanonicalAttacks(t *testing.T) {
	allowGH := "*https://api.github.com/*"
	cases := []struct {
		name    string
		pattern string
		res     string
		want    bool
	}{
		// --- legitimate matches ---
		{"basic", allowGH, "GET https://api.github.com/x", true},
		{"explicit :443 normalizes", allowGH, "GET https://api.github.com:443/x", true},
		{"uppercase host", allowGH, "GET https://API.GITHUB.COM/x", true},
		{"uppercase scheme", allowGH, "GET HTTPS://api.github.com/x", true},
		{"trailing dot host", allowGH, "GET https://api.github.com./x", true},
		{"no path", allowGH, "GET https://api.github.com", true},
		{"query preserved", allowGH, "GET https://api.github.com/x?a=b", true},
		{"wildcard host allows subdomain", "https://*.github.com/*", "GET https://api.github.com/x", true},
		{"wildcard host allows apex? no", "https://*.github.com/*", "GET https://github.com/x", false},
		{"star-host allows subdomain", "*://*api.github.com/*", "GET https://sub.api.github.com/x", true},

		// --- host-boundary: exact-literal patterns reject subdomains ---
		{"subdomain needs wildcard", allowGH, "GET https://sub.api.github.com/x", false},

		// --- host-boundary bypasses must fail ---
		{"suffix host", allowGH, "GET https://api.github.com.evil.com/", false},
		{"evil path embeds host", allowGH, "GET https://evil.com/api.github.com/", false},
		{"userinfo allowed-host@evil", allowGH, "GET https://api.github.com@evil.com/", false},
		{"userinfo evil@allowed", allowGH, "GET https://evil.com@api.github.com/", false},
		{"wrong port", allowGH, "GET https://api.github.com:444/", false},
		{"prefix host", allowGH, "GET https://notapi.github.com.evil.com/", false},
		{"lookalike host", allowGH, "GET https://api-github.com/", false},
		{"IP literal", allowGH, "GET https://140.82.121.4/", false},
		{"IPv6 literal", allowGH, "GET https://[2606:4700::1]/", false},

		// --- method scoping ---
		{"method matches", "GET https://api.github.com/*", "GET https://api.github.com/x", true},
		{"method mismatch", "GET https://api.github.com/*", "POST https://api.github.com/x", false},
		{"method case", "GET https://api.github.com/*", "get https://api.github.com/x", true},

		// --- scheme scoping ---
		{"http not https", allowGH, "GET http://api.github.com/x", false},

		// --- malformed inputs never match URL patterns ---
		{"schemeless", allowGH, "api.github.com/x", false},
		{"empty resource", allowGH, "", false},
		{"garbage", allowGH, "not a url at all", false},

		// --- space-truncation smuggling (red-team V1): the first
		// space-segment must be a real method token, and a second
		// segment must be a git ref list — not a smuggled URL ---
		{"evil URL in method slot", allowGH, "https://evil.com/?x= https://api.github.com/", false},
		{"two URLs space-joined", allowGH, "GET https://evil.com https://api.github.com/", false},
		{"URL then bare word", allowGH, "GET https://api.github.com/x bogus", false},
		{"arbitrary method still scoped by host", allowGH, "ANYTHING https://api.github.com/x", true},
		{"arbitrary method to evil", allowGH, "ANYTHING https://evil.com/x", false},
		{"crafted method literal pattern", "GET https://api.github.com/*", "ANYTHING https://api.github.com/x", false},

		// --- git ref suffix (red-team V5): refs appended after the URL
		// are preserved verbatim so ref-scoped rules can match ---
		{"git ref deny matches", "*git-receive-pack refs/heads/prod*", "POST https://github.com/o/r.git/git-receive-pack refs/heads/prod", true},
		{"git ref allow scoped", "*github.com/o/r.git/* refs/heads/main", "POST https://github.com/o/r.git/git-receive-pack refs/heads/main", true},
		{"git ref wrong ref", "*github.com* refs/heads/prod*", "POST https://github.com/o/r.git/x refs/heads/dev", false},
		{"ref list comma", "*refs/tags/v1*", "GET https://github.com/o/r.git/x refs/heads/main,refs/tags/v1", true},
		{"fake ref slot", allowGH, "GET https://api.github.com/x notrefs/y", false},

		// --- empty pattern stays compatible ---
		{"empty pattern", "", "anything at all", true},

		// --- encoded dot segments (P1.1 gate): decoded ".." must not
		// survive canonicalization — it would pass prefix-scoped checks
		// while traversing upward for a decoding downstream ---
		{"encoded dotdot", allowGH, "GET https://api.github.com/foo/%2e%2e/bar/x", false},
		{"encoded dot", allowGH, "GET https://api.github.com/foo/%2e/bar", false},
		{"raw dotdot rejected", allowGH, "GET https://api.github.com/foo/../bar/x", false},
		{"double-encoded stays literal", allowGH, "GET https://api.github.com/foo/%252e%252e/bar/x", true},
		{"encoded in in-scope path", allowGH, "GET https://api.github.com/%2e%2e/x", false},

		// --- non-URL patterns stay glob (legacy) ---
		{"plain glob", "*internal*", "POST https://internal.corp/x", true},
		{"plain glob miss", "*internal*", "POST https://external.com/x", false},
	}
	for _, c := range cases {
		if got := MatchResource(c.pattern, c.res); got != c.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", c.pattern, c.res, got, c.want)
		}
	}
}
