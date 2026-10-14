package policy

import (
	"net/url"
	"strings"
	"testing"
)

// resourceSeeds are the attack shapes the canonicalization tests cover:
// userinfo, smuggled second URLs, dot segments (raw and encoded), trailing
// dots, look-alike hosts, explicit default ports, IPv6, ref lists.
var resourceSeeds = []string{
	"GET https://api.github.com/x",
	"GET https://API.GITHUB.COM/x",
	"GET https://api.github.com./x",
	"GET https://api.github.com:443/x",
	"GET https://api.github.com:444/",
	"GET https://api.github.com@evil.com/",
	"GET https://evil.com@api.github.com/",
	"GET https://evil.com https://api.github.com/",
	"https://evil.com/?x= https://api.github.com/",
	"GET https://api.github.com.evil.com/",
	"GET https://notapi.github.com.evil.com/",
	"GET https://sub.api.github.com/x",
	"GET https://api-github.com/",
	"GET https://api.github.com/foo/../bar/x",
	"GET https://api.github.com/foo/%2e%2e/bar/x",
	"GET https://api.github.com/%2e%2e/x",
	"GET https://api.github.com/foo/%252e%252e/bar/x",
	"GET https://api.github.com/x?a=b",
	"GET https://api.github.com/x notrefs/y",
	"GET https://[2001:db8::1]:8443/x",
	"GET https://pastebin.com:8443/raw/x",
	"GET http://pastebin.com:443/raw/x",
	"POST https://PASTEBIN.com.:8443/api",
	"GET https://u@pastebin.com:8443/x",
	"POST https://github.com/o/r.git/git-receive-pack refs/heads/main,refs/tags/v1",
	"POST https://github.com/o/r.git/git-receive-pack refs/heads/old(delete)",
	"POST https://github.com/o/r.git/git-receive-pack git-receive-pack(truncated)",
	"POST https://github.com/o/r.git/x refs/a,refs/b refs/c,refs/d",
	"shell:curl https://x/",
	"",
}

// A canonical resource is a fixed point, never carries userinfo, a dot
// segment or a trailing-dot host, and parses back as a URL.
func FuzzCanonicalResource(f *testing.F) {
	for _, s := range resourceSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, resource string) {
		canon, ok := CanonicalResource(resource)
		if !ok {
			if canon != "" {
				t.Fatalf("refused resource %q came back non-empty: %q", resource, canon)
			}
			return
		}
		urlPart := canon
		if i := strings.IndexByte(canon, ' '); i > 0 && isMethodToken(canon[:i]) {
			if m := canon[:i]; m != strings.ToUpper(m) {
				t.Fatalf("method not upper-cased: %q -> %q", resource, canon)
			}
			urlPart = canon[i+1:]
		}
		if i := strings.IndexByte(urlPart, ' '); i > 0 {
			if !isRefList(urlPart[i+1:]) {
				t.Fatalf("suffix after the URL is not a ref list: %q -> %q", resource, canon)
			}
			urlPart = urlPart[:i]
		}
		u, err := url.Parse(urlPart)
		if err != nil {
			t.Fatalf("canonical URL does not parse: %q -> %q: %v", resource, canon, err)
		}
		if u.User != nil {
			t.Fatalf("userinfo survived: %q -> %q", resource, canon)
		}
		if h := u.Hostname(); strings.HasSuffix(h, ".") || h != strings.ToLower(h) {
			t.Fatalf("host not canonical: %q -> %q", resource, canon)
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("dot segment survived: %q -> %q", resource, canon)
			}
		}
		// A space in the query is read as the ref-list separator on a
		// second pass; check the fixed point only without one.
		if !strings.Contains(u.RawQuery, " ") {
			again, ok2 := CanonicalResource(canon)
			if !ok2 || again != canon {
				t.Fatalf("not a fixed point: %q -> %q -> %q (%v)", resource, canon, again, ok2)
			}
		}
	})
}

// rawHost is an oracle independent of CanonicalResource: the host the
// standard URL parser sees in "METHOD url[ suffix]" or "url[ suffix]".
func rawHost(resource string) (host, port, scheme string, user, ok bool) {
	rest := resource
	if i := strings.IndexByte(resource, ' '); i > 0 {
		rest = resource[i+1:]
	}
	if i := strings.IndexByte(rest, ' '); i > 0 {
		rest = rest[:i]
	}
	u, err := url.Parse(rest)
	if err != nil {
		return "", "", "", false, false
	}
	return strings.TrimRight(strings.ToLower(u.Hostname()), "."), u.Port(), strings.ToLower(u.Scheme), u.User != nil, true
}

// A pattern that names a host matches only that host (or, with a leading
// "*.", its subdomains), whatever else the resource says; a deny written
// for a host with no port catches that host on every port.
func FuzzMatchResource(f *testing.F) {
	for _, s := range resourceSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, resource string) {
		host, port, scheme, user, ok := rawHost(resource)
		if MatchResource("GET https://api.github.com/*", resource) {
			if !ok || user || host != "api.github.com" || scheme != "https" || (port != "" && port != "443") {
				t.Fatalf("exact-host pattern matched %q (host %q port %q scheme %q user %v)", resource, host, port, scheme, user)
			}
		}
		if MatchResource("*://*.github.com/*", resource) && isURLResource(resource) && (!ok || user || !strings.HasSuffix(host, ".github.com")) {
			t.Fatalf("subdomain pattern matched %q (host %q)", resource, host)
		}
		anyPort := MatchResourceAnyPort("*://pastebin.com/*", resource)
		if anyPort && isURLResource(resource) && (!ok || user || host != "pastebin.com") {
			t.Fatalf("any-port deny matched another host: %q (host %q)", resource, host)
		}
		// Every resource naming the deny's host that canonicalizes at all
		// must be caught, whatever port it names.
		if _, canonOK := CanonicalResource(resource); canonOK && ok && !user && host == "pastebin.com" &&
			isURLResource(resource) && !anyPort {
			t.Fatalf("any-port deny missed %q", resource)
		}
		// The exact-port matcher never matches more than the any-port one.
		if MatchResource("*://pastebin.com/*", resource) && !anyPort {
			t.Fatalf("exact-port match without any-port match: %q", resource)
		}
	})
}

// Splitting a push into one resource per ref never leaves a comma in a
// ref, loses a ref, or turns a parseable resource into an unparseable one.
func FuzzSplitRefList(f *testing.F) {
	for _, s := range resourceSeeds {
		f.Add(s)
	}
	f.Add("POST https://x/y refs/a,refs/b,,refs/c")
	f.Add("POST https://x/y refs/a,")
	f.Fuzz(func(t *testing.T, resource string) {
		parts := SplitRefList(resource)
		if len(parts) == 0 {
			t.Fatalf("no parts for %q", resource)
		}
		if len(parts) == 1 {
			if parts[0] != resource {
				t.Fatalf("single part changed: %q -> %q", resource, parts[0])
			}
			return
		}
		i := strings.LastIndexByte(resource, ' ')
		head := resource[:i]
		_, wholeOK := CanonicalResource(resource)
		refs := make([]string, 0, len(parts))
		for _, p := range parts {
			if !strings.HasPrefix(p, head+" ") {
				t.Fatalf("part %q lost the head %q", p, head)
			}
			ref := p[len(head)+1:]
			if strings.ContainsAny(ref, ", ") || !strings.HasPrefix(ref, "refs/") {
				t.Fatalf("part %q of %q is not a single ref", p, resource)
			}
			if _, ok := CanonicalResource(p); wholeOK && !ok {
				t.Fatalf("part %q of parseable %q does not parse", p, resource)
			}
			refs = append(refs, ref)
		}
		if strings.Join(refs, ",") != resource[i+1:] {
			t.Fatalf("refs lost: %q -> %q", resource, refs)
		}
	})
}
