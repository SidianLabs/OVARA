package policy

import "testing"

// Found by FuzzCanonicalResource. A host made only of dots canonicalized to
// an empty host ("https:///api.github.com/x"); the host-literal check gives
// up on an empty host, so the glob alone decided and a host-wildcard allow
// matched a path that merely spelled the host. A '%' or a stray ':' in the
// decoded host produced a canonical string that no longer parsed.
func TestCanonicalResource_RefusesHostsItCannotWriteBack(t *testing.T) {
	for _, r := range []string{
		"GET https://./api.github.com/x",
		"GET https://../x",
		"GET https://0%25/x",
		"GET https://api.github.com%25.evil.com/",
		"GET https://::/x",
	} {
		if c, ok := CanonicalResource(r); ok {
			t.Errorf("%q canonicalized to %q", r, c)
		}
	}
	if MatchResource("GET https://*api.github.com/*", "GET https://./api.github.com/x") {
		t.Error("a dots-only host matched a host-wildcard pattern through its path")
	}
	// Every trailing dot goes, as the proxy's host normalization does, so a
	// deny on a host still applies to "host..".
	if !MatchResourceAnyPort("*://pastebin.com/*", "GET https://pastebin.com../x") {
		t.Error(`deny missed "pastebin.com.."`)
	}
	// Real IPv6 literals still work.
	if c, ok := CanonicalResource("GET https://[2001:db8::1]:8443/x"); !ok || c != "GET https://[2001:db8::1]:8443/x" {
		t.Errorf("IPv6: %q %v", c, ok)
	}
}
