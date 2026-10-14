package main

import (
	"os"
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/pkg/baseline"
)

func TestDoctor_Baseline(t *testing.T) {
	dir := t.TempDir()
	if st := statuses(auditBaseline(dir, "baseline.json", "")); st["policy baseline"] != checkFail {
		t.Fatalf("missing file: %v", st)
	}
	doc := []byte(`{"version":"org","precedence":"most-specific","rules":[{"action_type":"http.request","environment":"*","resource":"POST *","escalate":true}]}`)
	if err := os.WriteFile(filepath.Join(dir, "baseline.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := statuses(auditBaseline(dir, "baseline.json", "")); st["policy baseline"] != checkWarn {
		t.Fatalf("unsigned: %v", st)
	}
	pub, priv, _ := baseline.KeyGen()
	if st := statuses(auditBaseline(dir, "baseline.json", pub)); st["policy baseline"] != checkFail {
		t.Fatalf("key pinned, no signature: %v", st)
	}
	sig, _ := baseline.Sign(doc, priv)
	if err := os.WriteFile(filepath.Join(dir, "baseline.json.sig"), []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := statuses(auditBaseline(dir, "baseline.json", pub)); st["policy baseline"] != checkPass {
		t.Fatalf("signed: %v", st)
	}
	other, _, _ := baseline.KeyGen()
	if st := statuses(auditBaseline(dir, "baseline.json", other)); st["policy baseline"] != checkFail {
		t.Fatalf("another key pinned: %v", st)
	}
}
