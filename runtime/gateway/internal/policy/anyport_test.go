package policy

import "testing"

// A host-style pattern without a port must match the host on any port when
// used to refuse something: a paste site on :8443 is still the paste site.
func TestMatchResourceAnyPort(t *testing.T) {
	cases := []struct {
		pattern, res string
		want         bool
	}{
		{"*://pastebin.com/*", "GET https://pastebin.com/x", true},
		{"*://pastebin.com/*", "GET https://pastebin.com:8443/raw/x", true},
		{"*://pastebin.com/*", "GET http://pastebin.com:443/raw/x", true},
		{"*://pastebin.com/*", "POST https://PASTEBIN.com.:8443/api", true},
		{"*://*.requestbin.com/*", "GET https://x.requestbin.com:9000/", true},
		{"https://[2001:db8::1]/*", "GET https://[2001:db8::1]:8443/x", true},
		// the host boundary still holds
		{"*://pastebin.com/*", "GET https://pastebin.com.evil:8443/x", false},
		{"*://pastebin.com/*", "GET https://notpastebin.com:8443/x", false},
		// a pattern that names a port keeps meaning that port
		{"*://pastebin.com:8443/*", "GET https://pastebin.com:8443/x", true},
		{"*://pastebin.com:8443/*", "GET https://pastebin.com:9443/x", false},
		{"*://pastebin.com:8443/*", "GET https://pastebin.com/x", false},
		// non-URL patterns and resources are unchanged
		{"shell:sudo*", "shell:sudo id", true},
		{"", "GET https://pastebin.com:8443/x", true},
		// a malformed resource still never matches
		{"*://pastebin.com/*", "GET https://u@pastebin.com:8443/x", false},
	}
	for _, c := range cases {
		if got := MatchResourceAnyPort(c.pattern, c.res); got != c.want {
			t.Errorf("MatchResourceAnyPort(%q, %q) = %v, want %v", c.pattern, c.res, got, c.want)
		}
	}
	// The ordinary matcher keeps ports strict; allows go through it.
	if MatchResource("https://github.com/*", "GET https://github.com:8443/x") {
		t.Error("MatchResource let a port-less pattern match a non-default port")
	}
}
