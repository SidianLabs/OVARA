// Package workspace gives an agent a copy of a project to work in, and
// brings its changes back as a reviewable commit.
//
// The copy is a real git clone (full history for log/blame/diff) made
// without hardlinks, so the host's .git is never in the box and the
// agent cannot touch the host's object files. The host's uncommitted
// changes are copied on top so the agent sees the project as the person
// left it. Files that look like secrets are left out. The clone's origin
// points at a dead URL: a `git push` from the box goes nowhere; changes
// come back only through CommitBack, which lands them on a new branch in
// the real repository and never touches its working tree.
package workspace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DeadOrigin is what the workspace's origin remote is set to.
const DeadOrigin = "ovara-box://changes-come-back-through-ovara"

// secretPatterns are matched against each path's base name and against
// the repo-relative path. They are deliberately broad: a false positive
// costs the agent a file it can ask for; a false negative hands it a key.
var secretPatterns = []string{
	".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
	"id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*", "*.ppk",
	".netrc", "_netrc", ".npmrc", ".pypirc", ".yarnrc", ".docker/config.json",
	".aws/*", ".ssh/*", ".gnupg/*", ".config/gh/*", ".config/gcloud/*", ".kube/config",
	"*.tfvars", "*.tfstate", "*.tfstate.backup",
	"credentials", "credentials.*", "secrets.*", "*.secret", "*.secrets", "secret.*",
	"service-account*.json", "*-credentials.json", "*.credentials.json",
	".ovara/*", "ovara.json", "proxy.json", "config.json",
}

// Workspace is one agent run's copy of a project.
type Workspace struct {
	Dir      string    `json:"dir"`       // the copy the agent works in
	Project  string    `json:"project"`   // the real repository (its top level)
	HostHead string    `json:"host_head"` // the project's HEAD when the copy was made
	Baseline string    `json:"baseline"`  // the commit in Dir that CommitBack diffs against
	Excluded []string  `json:"excluded"`  // secret-looking paths left out of the copy
	Created  time.Time `json:"created"`
}

// Options for Create.
type Options struct {
	// ExtraExcludes are globs added to the built-in secret patterns
	// (the project's .ovaraignore is read as well).
	ExtraExcludes []string
}

// Create copies project into dir. project must be inside a git repository
// with at least one commit; dir must not exist.
func Create(project, dir string, opts Options) (*Workspace, error) {
	top, err := gitOut(project, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("%s is not inside a git repository (the box needs one so changes can come back as a commit): %w", project, err)
	}
	top = strings.TrimSpace(top)
	head, err := gitOut(top, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("%s has no commits yet; make one first", top)
	}
	head = strings.TrimSpace(head)
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists", dir)
	}
	excludes := append([]string{}, secretPatterns...)
	excludes = append(excludes, opts.ExtraExcludes...)
	excludes = append(excludes, readIgnore(filepath.Join(top, ".ovaraignore"))...)

	// 1. the clone: history without the host's .git, objects copied not linked
	if _, err := gitOut("", "clone", "--quiet", "--no-hardlinks", "--no-local", top, dir); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	ws := &Workspace{Dir: dir, Project: top, HostHead: head, Created: time.Now().UTC()}
	cleanup := func() { os.RemoveAll(dir) }
	if _, err := gitOut(dir, "remote", "set-url", "origin", DeadOrigin); err != nil {
		cleanup()
		return nil, err
	}
	// a detached HEAD on the host clones as a branchless checkout; make sure
	// the agent has a branch to commit on
	if _, err := gitOut(dir, "checkout", "--quiet", "-B", "ovara-box"); err != nil {
		cleanup()
		return nil, fmt.Errorf("checkout: %w", err)
	}

	// 2. the host's uncommitted state, file by file
	changed, err := gitStatusPaths(top)
	if err != nil {
		cleanup()
		return nil, err
	}
	for _, c := range changed {
		dst := filepath.Join(dir, c.path)
		if c.deleted {
			os.RemoveAll(dst)
			continue
		}
		if isExcluded(c.path, excludes) {
			continue // handled in step 3 (it may also be tracked)
		}
		if err := copyFile(filepath.Join(top, c.path), dst); err != nil {
			cleanup()
			return nil, fmt.Errorf("copy %s: %w", c.path, err)
		}
	}

	// 3. secrets out, tracked or not
	tracked, err := gitOut(dir, "ls-files", "-z")
	if err != nil {
		cleanup()
		return nil, err
	}
	seen := map[string]bool{}
	for _, p := range strings.Split(tracked, "\x00") {
		if p != "" && isExcluded(p, excludes) {
			seen[p] = true
		}
	}
	for _, c := range changed {
		if !c.deleted && isExcluded(c.path, excludes) {
			seen[c.path] = true
		}
	}
	// also anything the clone brought that matches a directory pattern
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if isExcluded(rel, excludes) {
			seen[rel] = true
		}
		return nil
	})
	for p := range seen {
		os.RemoveAll(filepath.Join(dir, p))
		ws.Excluded = append(ws.Excluded, p)
	}
	sort.Strings(ws.Excluded)

	// 4. the baseline the agent's changes are measured against
	if _, err := gitOut(dir, "add", "-A"); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := gitRun(dir, "commit", "--quiet", "--allow-empty", "-m", "ovara box: workspace baseline (the project as the person left it, secrets left out)"); err != nil {
		cleanup()
		return nil, fmt.Errorf("baseline commit: %w", err)
	}
	base, err := gitOut(dir, "rev-parse", "HEAD")
	if err != nil {
		cleanup()
		return nil, err
	}
	ws.Baseline = strings.TrimSpace(base)
	if err := ws.save(); err != nil {
		cleanup()
		return nil, err
	}
	return ws, nil
}

// MetaFile is where a workspace's record lives: next to it, not inside it,
// so the agent cannot edit it.
func MetaFile(dir string) string { return dir + ".json" }

func (w *Workspace) save() error {
	b, _ := json.MarshalIndent(w, "", "  ")
	return os.WriteFile(MetaFile(w.Dir), b, 0o600)
}

// Load reads the record Create wrote.
func Load(dir string) (*Workspace, error) {
	b, err := os.ReadFile(MetaFile(dir))
	if err != nil {
		return nil, err
	}
	var w Workspace
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// Change is one path the agent touched, relative to the workspace.
type Change struct {
	Path   string
	Status string // added | modified | deleted | renamed
}

// Changes lists what differs between the workspace and its baseline,
// including the agent's own commits and uncommitted work.
func (w *Workspace) Changes() ([]Change, error) {
	if _, err := gitOut(w.Dir, "add", "-A"); err != nil {
		return nil, err
	}
	out, err := gitOut(w.Dir, "diff", "--cached", "--name-status", "-z", "-M", w.Baseline)
	if err != nil {
		return nil, err
	}
	var changes []Change
	fields := strings.Split(out, "\x00")
	for i := 0; i < len(fields); i++ {
		st := fields[i]
		if st == "" {
			continue
		}
		var c Change
		switch st[0] {
		case 'A':
			c.Status = "added"
		case 'M', 'T':
			c.Status = "modified"
		case 'D':
			c.Status = "deleted"
		case 'R', 'C':
			c.Status = "renamed"
			i++ // the old name
		default:
			c.Status = "modified"
		}
		if i+1 < len(fields) {
			i++
			c.Path = fields[i]
		}
		if c.Path != "" {
			changes = append(changes, c)
		}
	}
	return changes, nil
}

var secretValue = regexp.MustCompile(`(?i)((?:api[_-]?key|secret|token|password|passwd|authorization|bearer)\s*[=:]\s*["']?)([^\s"']+)`)

// Preview is the diff against the baseline for a person to read: the stat
// summary and the patch, cut at limit bytes, with values that look like
// credentials masked. It never changes the workspace.
func (w *Workspace) Preview(limit int) (string, error) {
	if _, err := gitOut(w.Dir, "add", "-A"); err != nil {
		return "", err
	}
	stat, err := gitOut(w.Dir, "diff", "--cached", "--stat", "-M", w.Baseline)
	if err != nil {
		return "", err
	}
	patch, err := gitOut(w.Dir, "diff", "--cached", "-M", "--no-color", w.Baseline)
	if err != nil {
		return "", err
	}
	patch = secretValue.ReplaceAllString(patch, "${1}[MASKED]")
	if len(patch) > limit {
		patch = patch[:limit] + fmt.Sprintf("\n... (%d more bytes not shown)\n", len(patch)-limit)
	}
	return stat + "\n" + patch, nil
}

// CommitBack lands the workspace's changes on a new branch in the real
// repository: the branch starts at the host's HEAD, carries the baseline
// (the host's own uncommitted state) if there was one, then one commit
// with the agent's changes. Paths in exclude are reverted to the baseline
// first (a policy denied them); paths Create left out as secrets are
// restored to the host's version so the branch never deletes them. The
// host's working tree and current branch are not touched.
func (w *Workspace) CommitBack(branch string, exclude []string) (commit string, err error) {
	if _, err := gitOut(w.Dir, "add", "-A"); err != nil {
		return "", err
	}
	for _, p := range exclude {
		if _, err := gitRun(w.Dir, "checkout", "--quiet", w.Baseline, "--", p); err != nil {
			// not in the baseline: an added file; drop it
			os.RemoveAll(filepath.Join(w.Dir, p))
			gitRun(w.Dir, "rm", "--quiet", "--cached", "--ignore-unmatch", "--", p)
		}
	}
	for _, p := range w.Excluded {
		if _, err := gitRun(w.Dir, "checkout", "--quiet", w.HostHead, "--", p); err != nil {
			// it was untracked on the host: nothing to restore in git terms
			continue
		}
	}
	if _, err := gitOut(w.Dir, "add", "-A"); err != nil {
		return "", err
	}
	changes, err := w.Changes()
	if err != nil {
		return "", err
	}
	if len(changes) == 0 {
		return "", nil
	}
	msg := fmt.Sprintf("ovara box: %d file(s) changed by the agent\n\n", len(changes))
	for _, c := range changes {
		msg += fmt.Sprintf("%s %s\n", c.Status, c.Path)
	}
	if _, err := gitRun(w.Dir, "commit", "--quiet", "-m", msg); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	out, err := gitOut(w.Dir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	commit = strings.TrimSpace(out)
	// into the real repo as a new branch only; refuse to move an existing one
	if _, err := gitOut(w.Project, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch); err == nil {
		return "", fmt.Errorf("branch %s already exists in %s; it is not moved", branch, w.Project)
	}
	if _, err := gitRun(w.Project, "fetch", "--quiet", "--no-tags", w.Dir, commit+":refs/heads/"+branch); err != nil {
		return "", fmt.Errorf("creating branch %s in %s: %w", branch, w.Project, err)
	}
	// secret files the baseline removed must not be absent on the branch
	for _, p := range w.Excluded {
		if _, err := gitOut(w.Project, "cat-file", "-e", w.HostHead+":"+p); err != nil {
			continue // untracked on the host; it was never in the branch's history
		}
		if _, err := gitOut(w.Project, "cat-file", "-e", commit+":"+p); err != nil {
			return "", fmt.Errorf("internal: excluded file %s is missing from the branch", p)
		}
	}
	return commit, nil
}

// --- helpers ---------------------------------------------------------------

type statusPath struct {
	path    string
	deleted bool
}

// gitStatusPaths lists the host's uncommitted paths (staged, unstaged and
// untracked, ignored files left alone).
func gitStatusPaths(top string) ([]statusPath, error) {
	out, err := gitOut(top, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, err
	}
	var paths []statusPath
	for _, ent := range strings.Split(out, "\x00") {
		if len(ent) < 4 {
			continue
		}
		xy, p := ent[:2], ent[3:]
		deleted := xy[0] == 'D' || xy[1] == 'D'
		paths = append(paths, statusPath{p, deleted})
	}
	return paths, nil
}

func isExcluded(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
		// directory patterns ("x/*") apply to any depth
		if strings.HasSuffix(pat, "/*") {
			d := strings.TrimSuffix(pat, "/*")
			if rel == d || strings.HasPrefix(rel, d+"/") || strings.Contains(rel, "/"+d+"/") {
				return true
			}
		}
	}
	return false
}

func readIgnore(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, info.Mode().Perm())
}

var gitEnv = []string{
	"GIT_AUTHOR_NAME=ovara-box", "GIT_AUTHOR_EMAIL=box@ovara.invalid",
	"GIT_COMMITTER_NAME=ovara-box", "GIT_COMMITTER_EMAIL=box@ovara.invalid",
	"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
}

func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), gitEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New("git " + strings.Join(args, " ") + ": " + msg)
	}
	return out.String(), nil
}

func gitRun(dir string, args ...string) (string, error) { return gitOut(dir, args...) }
