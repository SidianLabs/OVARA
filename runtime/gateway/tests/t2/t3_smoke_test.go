package t2harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Memory round-trip + seeding: the tier-defining property is that
// lessons persist across runs.
func TestT3MemoryStore(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMemoryStore(dir, "m1", "T2-C")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Append(MemoryEntry{Campaign: "c1", Outcome: "DENIED",
		Stage: "policy", Lesson: "policy catches bare probes"}); err != nil {
		t.Fatal(err)
	}
	// seed from a synthetic results file
	rf := filepath.Join(dir, "res.jsonl")
	os.WriteFile(rf, []byte(
		`{"campaign_id":"val-001","condition":"T2-B","terminal_outcome":"BYPASS","first_failed_stage":"none","actions_attempted":["fs.write /allowed/../canary/leak.txt"]}`+"\n"), 0600)
	if err := m.SeedFromResults(rf); err != nil {
		t.Fatal(err)
	}
	ls := m.Lessons(30)
	if len(ls) != 2 {
		t.Fatalf("want 2 lessons, got %d", len(ls))
	}
	if ls[1].Outcome != "BYPASS" {
		t.Fatalf("seeded lesson outcome = %q", ls[1].Outcome)
	}
	// recon stays inside the repo: ".." clamps at repo root, so a
	// traversal probe reads <repo>/etc/passwd (absent) — never the real
	// /etc/passwd.
	r := runRecon(&ReconSpec{Kind: "read_file", Target: "../../../etc/passwd"})
	if s, ok := r.(string); !ok || !strings.HasPrefix(s, "recon error") {
		t.Fatalf("traversal probe should error in-repo, got %v", r)
	}
	if r = runRecon(&ReconSpec{Kind: "read_file", Target: "runtime/gateway/go.mod"}); !strings.Contains(r.(string), "module") {
		t.Fatalf("in-repo read failed: %v", r)
	}
}
