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

func TestParseStore_RefusesShadowedRulesUnderMostSpecific(t *testing.T) {
	doc := `{"version":"x","precedence":"most-specific","rules":[
	  {"action_type":"http.request","environment":"*","resource":"POST *","allow":true},
	  {"action_type":"http.request","environment":"*","resource":"POST *","deny":true}]}`
	if _, err := ParseStore([]byte(doc), ""); err == nil || !strings.Contains(err.Error(), "same scope and pattern") {
		t.Fatalf("shadowed rules accepted: %v", err)
	}
	// the same file is legal under order precedence (deny simply wins)
	if _, err := ParseStore([]byte(strings.Replace(doc, `"precedence":"most-specific",`, "", 1)), ""); err != nil {
		t.Fatal(err)
	}
	// identical duplicates are harmless
	dup := `{"version":"x","precedence":"most-specific","rules":[
	  {"action_type":"http.request","environment":"*","resource":"POST *","deny":true},
	  {"action_type":"http.request","environment":"*","resource":"POST *","deny":true}]}`
	if _, err := ParseStore([]byte(dup), ""); err != nil {
		t.Fatal(err)
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
