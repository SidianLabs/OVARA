package runallow

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunAllowances(t *testing.T) {
	p := filepath.Join(t.TempDir(), "var", "run-allowances.json")
	if _, ok := Find(p, "shell", "shell:make"); ok {
		t.Fatal("missing file allowed something")
	}
	if err := Reset(p, "run1"); err != nil {
		t.Fatal(err)
	}
	if err := Add(p, Allowance{ActionType: "http.request", Resource: "POST https://example.org/a", ApprovalID: "apr_1"}); err != nil {
		t.Fatal(err)
	}
	_ = Add(p, Allowance{ActionType: "http.request", Resource: "POST https://example.org/a", ApprovalID: "apr_2"}) // duplicate
	a, ok := Find(p, "http.request", "POST https://example.org/a")
	if !ok || a.ApprovalID != "apr_1" || a.At.IsZero() {
		t.Fatalf("find: %+v %v", a, ok)
	}
	// exact only: another path, another method, another action type
	for _, r := range [][2]string{
		{"http.request", "POST https://example.org/b"},
		{"http.request", "GET https://example.org/a"},
		{"shell", "POST https://example.org/a"},
	} {
		if _, ok := Find(p, r[0], r[1]); ok {
			t.Fatalf("%v allowed", r)
		}
	}
	if n := len(List(p)); n != 1 {
		t.Fatalf("list: %d", n)
	}
	if st, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("mode: %v %v", st.Mode(), err)
	}
	// a new run forgets everything
	if err := Reset(p, "run2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := Find(p, "http.request", "POST https://example.org/a"); ok {
		t.Fatal("allowance survived the run")
	}
	// a corrupt file allows nothing
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Find(p, "http.request", "POST https://example.org/a"); ok {
		t.Fatal("corrupt file allowed something")
	}
}
