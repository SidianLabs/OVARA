package policy

import (
	"strings"
	"testing"
)

// A rule missing action_type or environment never matches. It must be
// refused at load, not loaded and left silently inert (a deny that does
// nothing is worse than an error).
func TestParseStoreRefusesRulesThatCanNeverMatch(t *testing.T) {
	cases := map[string]string{
		"no action_type":             `{"version":"v","rules":[{"environment":"*","resource":"*://pastebin.com/*","deny":true}]}`,
		"no environment":             `{"version":"v","rules":[{"action_type":"http.request","resource":"*://pastebin.com/*","deny":true}]}`,
		"neither (README shorthand)": `{"version":"v","rules":[{"resource":"POST https://pastebin.com/*","deny":true}]}`,
	}
	for name, doc := range cases {
		if _, err := ParseStore([]byte(doc), ""); err == nil || !strings.Contains(err.Error(), "never match") {
			t.Errorf("%s: want a load error explaining the rule would never match, got %v", name, err)
		}
	}
	ok := `{"version":"v","rules":[{"action_type":"*","environment":"*","resource":"*://pastebin.com/*","deny":true}]}`
	if _, err := ParseStore([]byte(ok), ""); err != nil {
		t.Fatalf("a complete rule must load: %v", err)
	}
}
