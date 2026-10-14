package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyBaseline_KeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(in, []byte(`{"version":"org","precedence":"most-specific","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys") // made by keygen
	if err := cmdPolicyBaseline([]string{"keygen", "-out", keys}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(keys, "baseline.key")); err != nil || (filepath.Separator == '/' && st.Mode().Perm() != 0o600) {
		t.Fatalf("private key: %v %v", err, st)
	}
	if err := cmdPolicyBaseline([]string{"keygen", "-out", keys}); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("a second keygen over the first: %v", err)
	}
	if err := cmdPolicyBaseline([]string{"verify", "-pub", filepath.Join(keys, "baseline.pub"), "-in", in}); err == nil {
		t.Fatal("verified without a signature")
	}
	if err := cmdPolicyBaseline([]string{"sign", "-key", filepath.Join(keys, "baseline.key"), "-in", in}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPolicyBaseline([]string{"verify", "-pub", filepath.Join(keys, "baseline.pub"), "-in", in}); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(keys, "baseline.pub"))
	if err := cmdPolicyBaseline([]string{"verify", "-pub", strings.TrimSpace(string(pub)), "-in", in}); err != nil {
		t.Fatalf("the hex itself as -pub: %v", err)
	}
	if err := os.WriteFile(in, []byte(`{"version":"org","precedence":"most-specific","rules":[ ]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPolicyBaseline([]string{"verify", "-pub", filepath.Join(keys, "baseline.pub"), "-in", in}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a changed file: %v", err)
	}
	if err := cmdPolicyBaseline(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatal(err)
	}
}
