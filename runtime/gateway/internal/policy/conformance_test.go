package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Conformance vectors for contract C1 (resource model) and the matching core
// of C2 (policy), written to /conformance/vectors so a second implementation
// can check itself against the reference without importing Go. The vectors
// are generated from the reference functions in this package; this test both
// writes them (OVARA_WRITE_CONFORMANCE=1) and, on every run, fails if the
// committed vectors no longer match what the reference produces — the same
// drift guard the receipt vectors use (proxy/internal/receipts).
//
//	OVARA_WRITE_CONFORMANCE=1 go test ./internal/policy -run TestConformanceVectors
//
// conformance/README.md says what each field means for an implementer.

// matchCorpus is the (pattern, resource) corpus for MatchResource: the
// red-team attack matrix (host boundaries, userinfo, encoded dot segments,
// method and git-ref smuggling) plus legitimate matches. The expected
// result is filled in from the reference, never by hand.
var matchCorpus = [][2]string{
	{"*https://api.github.com/*", "GET https://api.github.com/x"},
	{"*https://api.github.com/*", "GET https://api.github.com:443/x"},
	{"*https://api.github.com/*", "GET https://API.GITHUB.COM/x"},
	{"*https://api.github.com/*", "GET HTTPS://api.github.com/x"},
	{"*https://api.github.com/*", "GET https://api.github.com./x"},
	{"*https://api.github.com/*", "GET https://api.github.com"},
	{"*https://api.github.com/*", "GET https://api.github.com/x?a=b"},
	{"https://*.github.com/*", "GET https://api.github.com/x"},
	{"https://*.github.com/*", "GET https://github.com/x"},
	{"*://*api.github.com/*", "GET https://sub.api.github.com/x"},
	{"*https://api.github.com/*", "GET https://sub.api.github.com/x"},
	{"*https://api.github.com/*", "GET https://api.github.com.evil.com/"},
	{"*https://api.github.com/*", "GET https://evil.com/api.github.com/"},
	{"*https://api.github.com/*", "GET https://api.github.com@evil.com/"},
	{"*https://api.github.com/*", "GET https://evil.com@api.github.com/"},
	{"*https://api.github.com/*", "GET https://api.github.com:444/"},
	{"*https://api.github.com/*", "GET https://notapi.github.com.evil.com/"},
	{"*https://api.github.com/*", "GET https://api-github.com/"},
	{"*https://api.github.com/*", "GET https://140.82.121.4/"},
	{"*https://api.github.com/*", "GET https://[2606:4700::1]/"},
	{"GET https://api.github.com/*", "GET https://api.github.com/x"},
	{"GET https://api.github.com/*", "POST https://api.github.com/x"},
	{"GET https://api.github.com/*", "get https://api.github.com/x"},
	{"*https://api.github.com/*", "GET http://api.github.com/x"},
	{"*https://api.github.com/*", "api.github.com/x"},
	{"*https://api.github.com/*", ""},
	{"*https://api.github.com/*", "not a url at all"},
	{"*https://api.github.com/*", "https://evil.com/?x= https://api.github.com/"},
	{"*https://api.github.com/*", "GET https://evil.com https://api.github.com/"},
	{"*https://api.github.com/*", "GET https://api.github.com/x bogus"},
	{"*https://api.github.com/*", "ANYTHING https://api.github.com/x"},
	{"*https://api.github.com/*", "ANYTHING https://evil.com/x"},
	{"GET https://api.github.com/*", "ANYTHING https://api.github.com/x"},
	{"*git-receive-pack refs/heads/prod*", "POST https://github.com/o/r.git/git-receive-pack refs/heads/prod"},
	{"*github.com/o/r.git/* refs/heads/main", "POST https://github.com/o/r.git/git-receive-pack refs/heads/main"},
	{"*github.com* refs/heads/prod*", "POST https://github.com/o/r.git/x refs/heads/dev"},
	{"*refs/tags/v1*", "GET https://github.com/o/r.git/x refs/heads/main,refs/tags/v1"},
	{"*https://api.github.com/*", "GET https://api.github.com/x notrefs/y"},
	{"", "anything at all"},
	{"*https://api.github.com/*", "GET https://api.github.com/foo/%2e%2e/bar/x"},
	{"*https://api.github.com/*", "GET https://api.github.com/foo/%2e/bar"},
	{"*https://api.github.com/*", "GET https://api.github.com/foo/../bar/x"},
	{"*https://api.github.com/*", "GET https://api.github.com/foo/%252e%252e/bar/x"},
	{"*https://api.github.com/*", "GET https://api.github.com/%2e%2e/x"},
	{"*internal*", "POST https://internal.corp/x"},
	{"*internal*", "POST https://external.com/x"},
	// non-URL action resources are matched as globs (shell:, mcp:, tcp:, ...)
	{"shell:rm -rf *", "shell:rm -rf /tmp/x"},
	{"shell:git push*", "shell:git status"},
	{"mcp:*/delete_*", "mcp:https://srv/mcp/delete_everything"},
	{"tcp:*:5432", "tcp:db.internal:5432"},
	{"tcp:*:5432", "tcp:db.internal:5433"},
}

// canonicalCorpus is the input corpus for CanonicalResource (C1 §2). The
// expected canonical form, or that the input is not canonical, comes from
// the reference.
var canonicalCorpus = []string{
	"GET https://api.github.com/x",
	"GET https://api.github.com:443/x",
	"get HTTPS://API.GITHUB.COM./x",
	"https://api.github.com",
	"GET https://api.github.com/a//b",
	"GET https://api.github.com/x?a=b#frag",
	"GET http://host:80/x",
	"GET http://host:8080/x",
	"GET https://api.github.com/foo/../bar",
	"GET https://api.github.com/foo/%2e%2e/bar",
	"GET https://user@api.github.com/x",
	"POST https://github.com/o/r.git/git-receive-pack refs/heads/main",
	"api.github.com/x",
	"",
	"GET https://[::1]:8443/x",
	"lower://x/y",
}

// specificityCorpus is the input corpus for Specificity (C2 precedence key).
var specificityCorpus = []string{
	"", "*", "POST *", "GET https://pypi.org/*", "*://pastebin.com/*",
	"GET https://api.github.com/x", "shell:rm -rf *", "tcp:*:5432",
}

type matchVector struct {
	Pattern  string `json:"pattern"`
	Resource string `json:"resource"`
	Match    bool   `json:"match"`
}

type canonicalVector struct {
	Input     string  `json:"input"`
	Canonical *string `json:"canonical"` // null when the input is not canonical
}

type specificityVector struct {
	Pattern     string `json:"pattern"`
	Specificity int    `json:"specificity"`
}

type vectorFile struct {
	Comment string `json:"comment"`
	Vectors any    `json:"vectors"`
}

func TestConformanceVectors(t *testing.T) {
	match := make([]matchVector, 0, len(matchCorpus))
	for _, pr := range matchCorpus {
		match = append(match, matchVector{pr[0], pr[1], MatchResource(pr[0], pr[1])})
	}
	canon := make([]canonicalVector, 0, len(canonicalCorpus))
	for _, in := range canonicalCorpus {
		var c *string
		if out, ok := CanonicalResource(in); ok {
			s := out
			c = &s
		}
		canon = append(canon, canonicalVector{in, c})
	}
	spec := make([]specificityVector, 0, len(specificityCorpus))
	for _, p := range specificityCorpus {
		spec = append(spec, specificityVector{p, Specificity(p)})
	}

	const note = "C1/C2 conformance vectors generated from runtime/gateway/internal/policy; do not edit by hand (regenerate with OVARA_WRITE_CONFORMANCE=1 go test ./internal/policy -run TestConformanceVectors). See conformance/README.md."
	files := map[string]vectorFile{
		"match.json":       {Comment: note + " MatchResource(pattern, resource).", Vectors: match},
		"canonical.json":   {Comment: note + " CanonicalResource(input); canonical=null means not canonical.", Vectors: canon},
		"specificity.json": {Comment: note + " Specificity(pattern): the precedence key, higher wins.", Vectors: spec},
	}

	dir := filepath.Join("..", "..", "..", "..", "conformance", "vectors")
	write := os.Getenv("OVARA_WRITE_CONFORMANCE") == "1"
	for name, f := range files {
		buf, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, '\n')
		p := filepath.Join(dir, name)
		if write {
			if err := os.WriteFile(p, buf, 0o644); err != nil { //nolint:gosec // a committed, readable test fixture
				t.Fatalf("write %s: %v", p, err)
			}
			continue
		}
		have, err := os.ReadFile(p) //nolint:gosec // a fixed in-repo path
		if err != nil {
			t.Fatalf("read %s: %v (regenerate with OVARA_WRITE_CONFORMANCE=1)", p, err)
		}
		if !bytes.Equal(bytes.TrimRight(have, "\n"), bytes.TrimRight(buf, "\n")) {
			t.Fatalf("%s is out of date with the reference implementation: regenerate with OVARA_WRITE_CONFORMANCE=1 go test ./internal/policy -run TestConformanceVectors", p)
		}
	}
}
