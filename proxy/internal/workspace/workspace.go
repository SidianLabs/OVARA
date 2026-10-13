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
//
// Everything the agent can write is untrusted, and that includes the
// workspace's own .git: its config can name programs (fsmonitor, hooks,
// filter and diff drivers) that git runs for whoever calls it, and the
// launcher calls git as root. So once the agent has started, the launcher
// never runs git on the agent's .git. It keeps a repository of its own
// next to the workspace (Control), out of the agent's reach, reads the
// agent's files into it as plain content, and builds the commit there.
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
	// Control is the launcher's own bare repository, next to Dir and never
	// inside it. It holds the baseline and every tree a person reviews.
	Control string `json:"control"`
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
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error { // best effort: a missing file is not a secret
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel) // the same key git uses, on every OS
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
	// 5. the launcher's own repository, made before the agent runs: it
	// borrows the host's objects (no second copy of the history) and takes
	// the baseline from the fresh clone
	ws.Control = dir + ".git-ovara"
	if err := ws.initControl(top); err != nil {
		cleanup()
		os.RemoveAll(ws.Control)
		return nil, fmt.Errorf("control repository: %w", err)
	}
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

// initControl makes the launcher's bare repository. Its objects/info/
// alternates points at the host's object store, which only the person can
// write, so the history is not copied twice; the baseline commit (the
// host's uncommitted state) is fetched from the fresh clone before the
// agent has touched it.
func (w *Workspace) initControl(top string) error {
	if _, err := gitOut("", "init", "--quiet", "--bare", w.Control); err != nil {
		return err
	}
	if err := os.Chmod(w.Control, 0o700); err != nil {
		return err
	}
	common, err := gitOut(top, "rev-parse", "--git-common-dir")
	if err != nil {
		return err
	}
	common = strings.TrimSpace(common)
	if !filepath.IsAbs(common) {
		common = filepath.Join(top, common)
	}
	alt := filepath.Join(w.Control, "objects", "info", "alternates")
	if err := os.WriteFile(alt, []byte(filepath.Join(common, "objects")+"\n"), 0o600); err != nil {
		return err
	}
	_, err = w.ctl("", "fetch", "--quiet", "--no-tags", w.Dir, "+HEAD:"+baselineRef)
	return err
}

const (
	baselineRef = "refs/ovara/baseline"
	commitRef   = "refs/ovara/commit-back"
)

// Change is one path the agent touched, relative to the workspace.
type Change struct {
	Path    string
	OldPath string // for a rename: the path it came from
	Status  string // added | modified | deleted | renamed
	// Binary is set when git cannot show the content as text: a person
	// reading the diff sees only "binary files differ".
	Binary bool
}

// Snapshot is the agent's work frozen into trees in the control
// repository. What a person reviews is a Snapshot, and commit-back lands
// exactly its Tree: nothing the agent does after the snapshot is taken
// reaches the branch.
type Snapshot struct {
	// Tree is what lands on the branch.
	Tree string
	// Shown is the tree whose diff against the baseline a person reads:
	// Tree without the host's committed secrets, which are put back on the
	// branch unchanged and are not the agent's change to show.
	Shown string
	// Changes lists the paths that differ between the baseline and Shown.
	Changes []Change
}

// Snapshot reads the workspace's files as they are now (the agent's own
// commits and uncommitted work alike) into a tree. Only the working tree
// is read; the agent's .git is not used.
func (w *Workspace) Snapshot() (*Snapshot, error) {
	if w.Control == "" {
		return nil, errors.New("this workspace was made by an older Ovara (no control repository); bring its changes back by hand")
	}
	return w.buildSnapshot("", nil)
}

// Without returns s with paths (and, for renames, where they came from)
// put back as they are in the baseline. It works on s's own trees and does
// not read the workspace again.
func (w *Workspace) Without(s *Snapshot, paths []string) (*Snapshot, error) {
	if len(paths) == 0 {
		return s, nil
	}
	return w.buildSnapshot(s.Shown, paths)
}

// buildSnapshot fills a temporary index from start (a tree) or, when start
// is empty, from the workspace's files, puts revert back to the baseline,
// and writes the Shown and final trees.
func (w *Workspace) buildSnapshot(start string, revert []string) (*Snapshot, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(w.Control), ".ovara-index-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	idx := filepath.Join(tmp, "index")
	if start == "" {
		if _, err := w.ctl(idx, "read-tree", baselineRef); err != nil {
			return nil, err
		}
		if _, err := w.ctl(idx, "--work-tree="+w.Dir, "add", "-A", "."); err != nil {
			return nil, err
		}
	} else if _, err := w.ctl(idx, "read-tree", start); err != nil {
		return nil, err
	}
	if err := w.resetPaths(idx, baselineRef, revert); err != nil {
		return nil, err
	}
	// the host's committed secrets: never shown, never deleted
	var tracked []string
	for _, p := range w.Excluded {
		if _, err := w.ctl("", "cat-file", "-e", w.HostHead+":"+p); err == nil {
			tracked = append(tracked, p)
		}
	}
	if err := w.resetPaths(idx, baselineRef, tracked); err != nil {
		return nil, err
	}
	shown, err := w.ctl(idx, "write-tree")
	if err != nil {
		return nil, err
	}
	if err := w.resetPaths(idx, w.HostHead, tracked); err != nil {
		return nil, err
	}
	final, err := w.ctl(idx, "write-tree")
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Tree: strings.TrimSpace(final), Shown: strings.TrimSpace(shown)}
	if s.Changes, err = w.treeChanges(s.Shown); err != nil {
		return nil, err
	}
	return s, nil
}

// resetPaths sets each of paths in the index idx to what it is in commit
// from: that version, or absent. (A plain reset refuses to run in a bare
// repository, so this uses the plumbing.)
func (w *Workspace) resetPaths(idx, from string, paths []string) error {
	zero := strings.Repeat("0", len(w.Baseline)) // the object id length of this repository
	for len(paths) > 0 {
		chunk := paths[:min(len(paths), 500)]
		paths = paths[len(chunk):]
		out, err := w.ctl("", append([]string{"ls-tree", "-z", "--full-tree", from, "--"}, chunk...)...)
		if err != nil {
			return err
		}
		found := map[string]string{}
		for _, ent := range strings.Split(out, "\x00") {
			meta, p, ok := strings.Cut(ent, "\t")
			if f := strings.Fields(meta); ok && len(f) == 3 {
				found[p] = f[0] + " " + f[2]
			}
		}
		var info bytes.Buffer
		for _, p := range chunk {
			if e, ok := found[p]; ok {
				fmt.Fprintf(&info, "%s\t%s\x00", e, p)
			} else {
				fmt.Fprintf(&info, "0 %s\t%s\x00", zero, p)
			}
		}
		if _, err := w.ctlIn(idx, info.Bytes(), "update-index", "-z", "--index-info"); err != nil {
			return err
		}
	}
	return nil
}

// treeChanges lists what differs between the baseline and tree.
func (w *Workspace) treeChanges(tree string) ([]Change, error) {
	out, err := w.ctl("", "diff", "--name-status", "-z", "-M", baselineRef, tree)
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
			if i+1 < len(fields) {
				i++
				c.OldPath = fields[i]
			}
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
	// binary: numstat says "-" for lines added and removed
	num, err := w.ctl("", "diff", "--numstat", "-z", "--no-renames", baselineRef, tree)
	if err != nil {
		return nil, err
	}
	binary := map[string]bool{}
	for _, ent := range strings.Split(num, "\x00") {
		if rest, ok := strings.CutPrefix(ent, "-\t-\t"); ok {
			binary[rest] = true
		}
	}
	for i := range changes {
		changes[i].Binary = binary[changes[i].Path]
	}
	return changes, nil
}

// Changes lists what differs between the workspace and its baseline,
// including the agent's own commits and uncommitted work.
func (w *Workspace) Changes() ([]Change, error) {
	s, err := w.Snapshot()
	if err != nil {
		return nil, err
	}
	return s.Changes, nil
}

var secretValue = regexp.MustCompile(`(?i)((?:api[_-]?key|secret|token|password|passwd|authorization|bearer)\s*[=:]\s*["']?)([^\s"']+)`)

// Review is a snapshot's diff prepared for a person to read.
type Review struct {
	Stat string // git diff --stat
	// Patch is what is shown: the full patch, or its first Limit bytes.
	Patch string
	// Full is the whole patch (credentials masked), for a file the person
	// can open when Patch is cut.
	Full string
	// TotalBytes and ShownBytes measure the patch; they differ when it is
	// cut.
	TotalBytes, ShownBytes int
	// Cut is the file whose diff is shown only in part; Hidden are the
	// files whose diff is not shown at all.
	Cut    string
	Hidden []string
}

// Truncated reports whether a person reading Patch misses part of the diff.
func (r *Review) Truncated() bool { return r.ShownBytes < r.TotalBytes }

// Review is the diff between the baseline and s for a person to read: the
// stat summary and the patch, cut at limit bytes, with values that look
// like credentials masked. When it is cut it says which files are not
// shown, so the person knows what they did not read.
func (w *Workspace) Review(s *Snapshot, limit int) (*Review, error) {
	stat, err := w.ctl("", "diff", "--stat", "-M", baselineRef, s.Shown)
	if err != nil {
		return nil, err
	}
	patch, err := w.ctl("", "diff", "-M", "--no-color", "--no-ext-diff", "--no-textconv", baselineRef, s.Shown)
	if err != nil {
		return nil, err
	}
	patch = secretValue.ReplaceAllString(patch, "${1}[MASKED]")
	r := &Review{Stat: stat, Full: patch, Patch: patch, TotalBytes: len(patch), ShownBytes: len(patch)}
	if len(patch) <= limit {
		return r, nil
	}
	r.Patch, r.ShownBytes = patch[:limit], limit
	// the patch has one "diff --git" section per changed path, in the same
	// order as the name-status list
	starts := []int{}
	for i := 0; i < len(patch); {
		j := strings.Index(patch[i:], "diff --git ")
		if j < 0 {
			break
		}
		if i+j == 0 || patch[i+j-1] == '\n' {
			starts = append(starts, i+j)
		}
		i += j + 1
	}
	if len(starts) != len(s.Changes) {
		// cannot tell the files apart: say only that some are not shown
		r.Hidden = []string{"(the files after the cut)"}
		return r, nil
	}
	for k, c := range s.Changes {
		end := len(patch)
		if k+1 < len(starts) {
			end = starts[k+1]
		}
		switch {
		case starts[k] >= limit:
			r.Hidden = append(r.Hidden, c.Path)
		case end > limit:
			r.Cut = c.Path
		}
	}
	return r, nil
}

// CommitTree lands s on a new branch in the real repository: one commit
// whose tree is exactly s.Tree, on top of the baseline (which sits on the
// host's HEAD and carries the host's own uncommitted state). The commit is
// built in the control repository, checked to hold that tree, and only then
// fetched into the real repository as a new branch. The host's working tree
// and current branch are not touched.
func (w *Workspace) CommitTree(branch string, s *Snapshot) (commit string, err error) {
	if len(s.Changes) == 0 {
		return "", nil
	}
	msg := fmt.Sprintf("ovara box: %d file(s) changed by the agent\n\n", len(s.Changes))
	for _, c := range s.Changes {
		msg += fmt.Sprintf("%s %s\n", c.Status, c.Path)
	}
	out, err := w.ctl("", "commit-tree", s.Tree, "-p", baselineRef, "-m", msg)
	if err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	commit = strings.TrimSpace(out)
	got, err := w.ctl("", "rev-parse", commit+"^{tree}")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(got) != s.Tree {
		return "", fmt.Errorf("the commit holds tree %s, not the reviewed %s; nothing comes back", strings.TrimSpace(got), s.Tree)
	}
	if _, err := w.ctl("", "update-ref", commitRef, commit); err != nil {
		return "", err
	}
	// into the real repo as a new branch only; refuse to move an existing one
	if _, err := gitOut(w.Project, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch); err == nil {
		return "", fmt.Errorf("branch %s already exists in %s; it is not moved", branch, w.Project)
	}
	// write into the real repository as its owner, so a launcher running
	// under sudo leaves no root-owned objects behind; the owner reads the
	// control repository, which is theirs from now on
	uid, gid := ownerOf(w.Project)
	if err := chownTree(w.Control, uid, gid); err != nil {
		return "", err
	}
	if _, err := gitAs([2]int{uid, gid}, w.Project, "fetch", "--quiet", "--no-tags", w.Control, commitRef+":refs/heads/"+branch); err != nil {
		return "", fmt.Errorf("creating branch %s in %s: %w", branch, w.Project, err)
	}
	if got, err := gitOut(w.Project, "rev-parse", "refs/heads/"+branch); err != nil || strings.TrimSpace(got) != commit {
		return "", fmt.Errorf("branch %s in %s does not point at the reviewed commit %s", branch, w.Project, commit)
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

// CommitBack is Snapshot, Without(exclude) and CommitTree in one step, for
// callers that do not show the diff in between.
func (w *Workspace) CommitBack(branch string, exclude []string) (string, error) {
	s, err := w.Snapshot()
	if err != nil {
		return "", err
	}
	if s, err = w.Without(s, exclude); err != nil {
		return "", err
	}
	return w.CommitTree(branch, s)
}

// ctl runs git on the control repository. Its config is the launcher's;
// hooks and fsmonitor are off in any case, pathspecs are literal (a file
// the agent named "*" means that file), and index, when set, is a
// temporary index so the control repository's own state is never shared.
func (w *Workspace) ctl(index string, args ...string) (string, error) {
	return w.ctlIn(index, nil, args...)
}

// ctlIn is ctl with stdin.
func (w *Workspace) ctlIn(index string, stdin []byte, args ...string) (string, error) {
	full := append([]string{
		"--git-dir=" + w.Control,
		"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
		"-c", "safe.directory=" + w.Control, "-c", "safe.directory=" + w.Dir,
	}, args...)
	env := []string{"GIT_LITERAL_PATHSPECS=1"}
	if index != "" {
		env = append(env, "GIT_INDEX_FILE="+index)
	}
	dir := filepath.Dir(w.Control)
	for _, a := range args {
		if strings.HasPrefix(a, "--work-tree=") {
			dir = w.Dir // pathspecs ("." for add) are relative to the work tree
		}
	}
	return gitExec(dir, env, stdin, full...)
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
	ents := strings.Split(out, "\x00")
	paths := make([]statusPath, 0, len(ents))
	for _, ent := range ents {
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
	return gitExec(dir, nil, nil, args...)
}

// gitExec runs git in dir with extra environment and, when stdin is not
// nil, that input.
func gitExec(dir string, env []string, stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(append(os.Environ(), gitEnv...), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
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
