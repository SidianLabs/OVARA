package policy

import (
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
