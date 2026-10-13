package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The policy hash is over the parsed policy, so formatting does not
// change it and any change to what is enforced does.
func TestPolicyHash(t *testing.T) {
	a := `{"version":"v1","precedence":"most-specific","rules":[
	  {"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`
	b := "{\n  \"rules\": [ {\"escalate\": true, \"resource\": \"POST *\", \"environment\": \"*\", \"action_type\": \"http.request\"} ],\n  \"precedence\": \"most-specific\", \"version\": \"v1\"\n}"
	sa, err := ParseStore([]byte(a), "")
	if err != nil {
		t.Fatal(err)
	}
	sb, err := ParseStore([]byte(b), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sa.Hash(), "sha256:") || len(sa.Hash()) != len("sha256:")+64 {
		t.Fatalf("hash format: %q", sa.Hash())
	}
	if sa.Hash() != sb.Hash() {
		t.Fatalf("same policy, different hash: %s vs %s", sa.Hash(), sb.Hash())
	}
	for name, doc := range map[string]string{
		"effect":     strings.Replace(a, `"escalate":true`, `"deny":true`, 1),
		"resource":   strings.Replace(a, `"POST *"`, `"PUT *"`, 1),
		"precedence": strings.Replace(a, `"most-specific"`, `"order"`, 1),
		"default":    strings.Replace(a, `"rules"`, `"default":"deny","rules"`, 1),
	} {
		s, err := ParseStore([]byte(doc), "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Hash() == sa.Hash() {
			t.Errorf("%s change kept the hash", name)
		}
	}

	// in-memory changes and reloads move the hash too
	h := sa.Hash()
	sa.AddRule(Rule{ActionType: "shell", Environment: "*", Deny: true})
	if sa.Hash() == h {
		t.Error("AddRule kept the hash")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(a), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStoreFromFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	before := st.Hash()
	if err := os.WriteFile(path, []byte(strings.Replace(a, `"POST *"`, `"PUT *"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Reload(); err != nil {
		t.Fatal(err)
	}
	if st.Hash() == before {
		t.Error("Reload kept the hash")
	}
}
