package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.runtime.gateway/pkg/baseline"
)

func TestLoadBaseline_SignatureAndTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	doc := `{"version":"org-2026-10","precedence":"most-specific","rules":[{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true,"description":"writes ask"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := baseline.KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	// a key is pinned but nothing is signed yet
	if _, err := LoadBaseline(path, pub, ""); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("unsigned with a pinned key: %v", err)
	}
	sig, _ := baseline.Sign([]byte(doc), priv)
	if err := os.WriteFile(baseline.SigPath(path), []byte(sig+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadBaseline(path, pub, "")
	if err != nil || st.Version() != "org-2026-10" || len(st.ListRules()) != 1 || st.FilePath() != path {
		t.Fatalf("signed: %v %+v", err, st)
	}
	// a loosened file no longer verifies
	if err := os.WriteFile(path, []byte(strings.Replace(doc, `"escalate":true`, `"allow":true`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(path, pub, ""); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered: %v", err)
	}
	// without a pinned key the file loads as it is (the doctor warns)
	if st, err := LoadBaseline(path, "", ""); err != nil || len(st.ListRules()) != 1 {
		t.Fatalf("unsigned, no key: %v", err)
	}
	if _, err := LoadBaseline(path, "nothex", ""); err == nil {
		t.Fatal("a bad key loaded")
	}
	// a baseline that is not a policy is refused like any policy file
	if err := os.WriteFile(path, []byte(`{"version":"x","rules":[{"resource":"*","allow":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(path, "", ""); err == nil || !strings.Contains(err.Error(), "action_type") {
		t.Fatalf("rule that never matches: %v", err)
	}
}
