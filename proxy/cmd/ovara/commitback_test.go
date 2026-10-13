package main

import (
	"errors"
	"strings"
	"testing"

	"ovara.proxy/internal/workspace"
)

func TestPlanCommitBack(t *testing.T) {
	changes := []workspace.Change{
		{Path: "src/a.go", Status: "modified"},
		{Path: ".claude/settings.json", Status: "added"},
		{Path: "package.json", Status: "modified"},
		{Path: "assets/logo.png", Status: "added", Binary: true},
		{Path: "old.bin", Status: "deleted", Binary: true},
		{Path: "ci.yml", OldPath: ".github/workflows/ci.yml", Status: "renamed"},
	}
	policy := func(path, status string) (string, error) {
		switch {
		case strings.HasPrefix(path, ".claude/"), strings.HasPrefix(path, ".github/"):
			return decisionDeny, nil
		case path == "package.json":
			return decisionEscalate, nil
		}
		return decisionAllow, nil
	}
	p, err := planCommitBack(changes, policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.allowed, ","); got != "src/a.go,package.json,old.bin" {
		t.Errorf("allowed = %s", got)
	}
	if got := strings.Join(p.flagged, ","); got != "package.json" {
		t.Errorf("flagged = %s", got)
	}
	// a rename whose old path policy protects is kept out at both ends
	if got := strings.Join(p.revert, ","); got != ".claude/settings.json,assets/logo.png,ci.yml,.github/workflows/ci.yml" {
		t.Errorf("revert = %s", got)
	}
	if got := strings.Join(p.binary, ","); got != "assets/logo.png" {
		t.Errorf("binary = %s", got)
	}
	if !strings.Contains(strings.Join(p.keptOut, "\n"), "assets/logo.png (binary file") {
		t.Errorf("kept out = %v", p.keptOut)
	}

	p, _ = planCommitBack(changes, policy, true)
	if len(p.binary) != 0 || !strings.Contains(strings.Join(p.allowed, ","), "assets/logo.png") {
		t.Errorf("-allow-binary: binary=%v allowed=%v", p.binary, p.allowed)
	}

	// an answer policy cannot give keeps the file out; an error stops everything
	odd := func(string, string) (string, error) { return "maybe", nil }
	if p, _ := planCommitBack(changes[:1], odd, false); len(p.allowed) != 0 {
		t.Errorf("unknown decision let a file through: %v", p.allowed)
	}
	boom := func(string, string) (string, error) { return "", errors.New("gateway down") }
	if _, err := planCommitBack(changes, boom, false); err == nil {
		t.Error("gateway error ignored")
	}
}

func TestCommitBackContext_SaysWhatIsNotShown(t *testing.T) {
	p := &commitBackPlan{allowed: []string{"a.txt", "b.txt", "c.txt"}, flagged: []string{"c.txt"}, keptOut: []string{"x.png (binary file: ...)"}}
	snap := &workspace.Snapshot{Tree: "0123456789abcdef0123456789abcdef01234567"}
	rev := &workspace.Review{Stat: " 3 files changed", Patch: "diff --git a/a.txt", TotalBytes: 9000, ShownBytes: 1000, Cut: "a.txt", Hidden: []string{"b.txt", "c.txt"}}
	c := commitBackContext(p, snap, rev, "ovara/box-1", "/var/lib/ovara/runs/1/commit-back.diff")
	if c["tree"] != snap.Tree {
		t.Errorf("tree = %q", c["tree"])
	}
	for _, want := range []string{"8000 of 9000 bytes", "3 file(s)", "/var/lib/ovara/runs/1/commit-back.diff", "cut short: a.txt", "not shown: b.txt", "not shown: c.txt"} {
		if !strings.Contains(c["diff_not_shown"], want) {
			t.Errorf("diff_not_shown lacks %q:\n%s", want, c["diff_not_shown"])
		}
	}
	if !strings.Contains(c["diff"], "cut here") {
		t.Errorf("the diff itself does not say where it stops:\n%s", c["diff"])
	}
	rev.ShownBytes = rev.TotalBytes
	if _, ok := commitBackContext(p, snap, rev, "b", "f")["diff_not_shown"]; ok {
		t.Error("a whole diff reported as cut")
	}
}

// What the person reads for a commit-back: sensitive files and an
// incomplete diff before anything else, every kept-out path with its
// reason, and the tree that will land.
func TestContextLines_CommitBack(t *testing.T) {
	a := sanitizeApproval(pendingApproval{ActionType: "fs.commit_back", Resource: "commit:proj (3 files, tree 0123456789ab)", Context: map[string]string{
		"files":          "3 path(s): a.txt, b.txt, CLAUDE.md",
		"sensitive":      "CLAUDE.md\nscripts/x.sh",
		"diff_not_shown": "8000 of 9000 bytes of the diff, in 2 file(s); the whole diff is in /r/commit-back.diff\nnot shown: b.txt",
		"kept_out":       ".mcp.json (policy)\nlogo.png (binary file: its content cannot be reviewed; -allow-binary brings it back)",
		"tree":           "0123456789abcdef",
		"branch":         "ovara/box-1",
		"diff":           " 3 files changed\n+hello",
	}})
	lines := contextLines(a)
	text := strings.Join(lines, "\n")
	for _, want := range []string{
		"⚠ sensitive file changed: CLAUDE.md",
		"⚠ sensitive file changed: scripts/x.sh",
		"⚠ diff not shown: 8000 of 9000 bytes",
		"    not shown: b.txt",
		"kept out: .mcp.json (policy)",
		"kept out: logo.png (binary file",
		"reviewed tree: 0123456789abcdef",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if !strings.HasPrefix(lines[0], "⚠ sensitive file changed") {
		t.Errorf("warnings are not first:\n%s", text)
	}
}
