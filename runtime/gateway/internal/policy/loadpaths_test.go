package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// SEC-0005 regression: every production load path must preserve the
// resource field. Today LoadStoreFromFile silently drops it (fileRule
// lacks the field), so a rule the operator believes is host-scoped
// applies globally — the failure mode is silent permissiveness, not an
// error. This test FAILS until fileRule carries Resource.
func TestLoadStoreFromFile_PreservesResource(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "policy.json")
	content := `{"version":"v-test","rules":[
		{"action_type":"http.request","environment":"dev","resource":"*https://api.github.com/*","allow":true},
		{"action_type":"*","environment":"*","escalate":true}
	]}`
	if err := os.WriteFile(fp, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStoreFromFile(fp, "")
	if err != nil {
		t.Fatal(err)
	}
	rules := store.RulesForAction("http.request")
	var scoped *Rule
	for i := range rules {
		if rules[i].Allow {
			scoped = &rules[i]
		}
	}
	if scoped == nil {
		t.Fatal("no allow rule found")
	}
	if scoped.Resource == "" {
		t.Fatal("resource field dropped during file load — rule applies to ALL resources")
	}
	if !MatchResource(scoped.Resource, "GET https://api.github.com/x") {
		t.Fatal("loaded resource no longer matches expected host")
	}
}
