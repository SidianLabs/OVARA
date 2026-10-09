package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpecificity(t *testing.T) {
	for pat, want := range map[string]int{"": 0, "*": 0, "POST *": 5, "GET https://pypi.org/*": 21, "*://pastebin.com/*": 16} {
		if got := Specificity(pat); got != want {
			t.Errorf("%q: %d, want %d", pat, got, want)
		}
	}
}

func TestParseStore_PrecedenceAndDefault(t *testing.T) {
	st, err := ParseStore([]byte(`{"version":"x","precedence":"most-specific","default":"deny","rules":[]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Precedence() != PrecedenceMostSpecific || st.DefaultDecision() != DefaultDeny {
		t.Fatalf("%q %q", st.Precedence(), st.DefaultDecision())
	}
	// absent → the original behaviour
	st, err = ParseStore([]byte(`{"version":"x","rules":[]}`), "")
	if err != nil || st.Precedence() != PrecedenceOrder || st.DefaultDecision() != DefaultEscalate {
		t.Fatalf("defaults: %v %q %q", err, st.Precedence(), st.DefaultDecision())
	}
	for _, bad := range []string{
		`{"version":"x","precedence":"newest","rules":[]}`,
		`{"version":"x","default":"allow","rules":[]}`,
	} {
		if _, err := ParseStore([]byte(bad), ""); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// Same scope and pattern, different effects: the file still loads (adding
// "POST * deny" on top of the default "POST * escalate" is the normal way
// to say "deny every other write"), and the validator names the winner.
func TestShadowedRules_LoadAndWarn(t *testing.T) {
	doc := `{"version":"x","precedence":"most-specific","rules":[
	  {"action_type":"http.request","environment":"*","resource":"POST *","escalate":true},
	  {"action_type":"http.request","environment":"*","resource":"POST *","deny":true}]}`
	if _, err := ParseStore([]byte(doc), ""); err != nil {
		t.Fatalf("composed policy refused: %v", err)
	}
	res, err := NewValidator().ValidatePolicyData([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "rule[1] decides") {
		t.Fatalf("validator: valid=%v warnings=%v", res.Valid, res.Warnings)
	}
	// no warning without most-specific precedence, or for identical duplicates
	res, _ = NewValidator().ValidatePolicyData([]byte(strings.Replace(doc, `"precedence":"most-specific",`, "", 1)))
	for _, w := range res.Warnings {
		if strings.Contains(w, "same scope and pattern") {
			t.Fatalf("order precedence warned: %v", res.Warnings)
		}
	}
	dup := strings.Replace(doc, `"escalate":true`, `"deny":true`, 1)
	res, _ = NewValidator().ValidatePolicyData([]byte(dup))
	for _, w := range res.Warnings {
		if strings.Contains(w, "same scope and pattern") {
			t.Fatalf("identical duplicates warned: %v", res.Warnings)
		}
	}
}

func TestWriteFile_KeepsPrecedenceAndDefault(t *testing.T) {
	st, err := ParseStore([]byte(`{"version":"x","precedence":"most-specific","default":"deny","rules":[]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := st.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	again, err := LoadStoreFromFile(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Precedence() != PrecedenceMostSpecific || again.DefaultDecision() != DefaultDeny {
		t.Fatalf("lost on round trip: %q %q", again.Precedence(), again.DefaultDecision())
	}
}

// A hot reload must carry the file's precedence and default, not only its
// rules: a policy that drops the field goes back to the order-based rule,
// and one that adds it switches over, without a restart.
func TestReload_CarriesPrecedenceAndDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	write := func(doc string) {
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":"a","precedence":"most-specific","default":"deny","rules":[]}`)
	st, err := LoadStoreFromFile(p, "")
	if err != nil {
		t.Fatal(err)
	}
	write(`{"version":"b","rules":[]}`)
	if err := st.Reload(); err != nil {
		t.Fatal(err)
	}
	if st.Precedence() != PrecedenceOrder || st.DefaultDecision() != DefaultEscalate {
		t.Fatalf("after dropping the fields: %q %q", st.Precedence(), st.DefaultDecision())
	}
	other, err := ParseStore([]byte(`{"version":"c","precedence":"most-specific","default":"deny","rules":[]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReloadFromStore(other); err != nil {
		t.Fatal(err)
	}
	if st.Precedence() != PrecedenceMostSpecific || st.DefaultDecision() != DefaultDeny {
		t.Fatalf("after ReloadFromStore: %q %q", st.Precedence(), st.DefaultDecision())
	}
}

// A command line or path that contains "://" is not a URL resource: it is
// matched as a plain glob, so "shell:*" covers `curl http://x`.
func TestMatchResource_URLShapeNotSubstring(t *testing.T) {
	yes := map[string]string{
		"shell:*":                "shell:bash -c curl http://127.0.0.1:9100/v1",
		"shell:*rm -rf*":         "shell:export A=http://x; rm -rf /tmp/y",
		"path:*":                 "path:docs/links://weird",
		"GET https://pypi.org/*": "GET https://pypi.org/simple/",
		"*://pastebin.com/*":     "POST https://pastebin.com/api",
	}
	for pat, res := range yes {
		if !MatchResource(pat, res) {
			t.Errorf("%q should match %q", pat, res)
		}
	}
	if MatchResource("shell:sudo*", "shell:curl http://sudo.example/") {
		t.Error("glob matched where it should not")
	}
	// URL resources keep their strict handling: userinfo never matches
	if MatchResource("GET https://pypi.org/*", "GET https://pypi.org@evil.example/") {
		t.Error("userinfo URL matched")
	}
	for _, r := range []string{"GET https://x/", "https://x/", "git+ssh://x/"} {
		if !isURLResource(r) {
			t.Errorf("%q is a URL resource", r)
		}
	}
	for _, r := range []string{"shell:curl https://x/", "path:a://b", "commit:proj (2 files)", "shell:ls"} {
		if isURLResource(r) {
			t.Errorf("%q is not a URL resource", r)
		}
	}
}
