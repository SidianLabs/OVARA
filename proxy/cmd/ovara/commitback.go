package main

import (
	"fmt"
	"strconv"
	"strings"

	"ovara.proxy/internal/workspace"
)

// What `ovara box` brings back to the real repository, and what it tells
// the person who approves it. Kept apart from box.go (Linux only) so the
// rules can be tested anywhere.

// gateway decisions
const (
	decisionAllow    = "allow"
	decisionDeny     = "deny"
	decisionEscalate = "escalate"
)

// commitBackPlan sorts the agent's changes before anyone is asked.
type commitBackPlan struct {
	allowed []string // paths that come back
	revert  []string // paths put back as they were (both ends of a rename)
	keptOut []string // "path (why)", for the person
	policy  []string // kept out by a policy deny
	binary  []string // kept out because the content cannot be reviewed
	flagged []string // come back, but the person should look at them first
}

// planCommitBack asks policy about each changed path (fs.commit_back.path)
// and decides what comes back:
//   - deny: kept out;
//   - escalate: comes back, flagged for the person as a sensitive file
//     (agent instructions, build and install scripts, lockfiles);
//   - allow: comes back.
//
// A binary file added or changed is kept out unless allowBinary: a person
// reading the diff sees only "binary files differ", so it cannot be
// reviewed. A rename is judged on both its old and its new path, and the
// stricter answer counts for both.
func planCommitBack(changes []workspace.Change, decide func(path, status string) (string, error), allowBinary bool) (*commitBackPlan, error) {
	p := &commitBackPlan{}
	rank := map[string]int{decisionAllow: 0, decisionEscalate: 1, decisionDeny: 2}
	for _, c := range changes {
		paths := []string{c.Path}
		if c.OldPath != "" {
			paths = append(paths, c.OldPath)
		}
		verdict := decisionAllow
		for _, path := range paths {
			d, err := decide(path, c.Status)
			if err != nil {
				return nil, err
			}
			if _, known := rank[d]; !known {
				d = decisionDeny // an answer we do not understand keeps the file out
			}
			if rank[d] > rank[verdict] {
				verdict = d
			}
		}
		switch {
		case verdict == decisionDeny:
			p.revert = append(p.revert, paths...)
			p.policy = append(p.policy, c.Path)
			p.keptOut = append(p.keptOut, termSafe(c.Path)+" (policy)")
		case c.Binary && c.Status != "deleted" && !allowBinary:
			p.revert = append(p.revert, paths...)
			p.binary = append(p.binary, c.Path)
			p.keptOut = append(p.keptOut, termSafe(c.Path)+" (binary file: its content cannot be reviewed; -allow-binary brings it back)")
		default:
			p.allowed = append(p.allowed, c.Path)
			if verdict == decisionEscalate {
				p.flagged = append(p.flagged, c.Path)
			}
		}
	}
	return p, nil
}

// commitBackContext is what the approval shows: the files, what was kept
// out and why, sensitive files, the reviewed tree, the diff, and, when the
// diff is cut, exactly what the person did not see and where the rest is.
func commitBackContext(p *commitBackPlan, snap *workspace.Snapshot, rev *workspace.Review, branch, fullDiff string) map[string]string {
	c := map[string]string{
		"files":  strconv.Itoa(len(p.allowed)) + " path(s): " + strings.Join(p.allowed, ", "),
		"branch": branch,
		"tree":   snap.Tree,
		"diff":   rev.Stat + "\n" + rev.Patch,
	}
	if len(p.keptOut) > 0 {
		c["kept_out"] = strings.Join(p.keptOut, "\n")
	}
	if len(p.flagged) > 0 {
		safe := make([]string, len(p.flagged))
		for i, f := range p.flagged {
			safe[i] = termSafe(f) // one path per line, even if its name has a line break
		}
		c["sensitive"] = strings.Join(safe, "\n")
	}
	if rev.Truncated() {
		files := len(rev.Hidden)
		if rev.Cut != "" {
			files++
		}
		lines := []string{fmt.Sprintf("%d of %d bytes of the diff, in %d file(s); the whole diff is in %s",
			rev.TotalBytes-rev.ShownBytes, rev.TotalBytes, files, fullDiff)}
		if rev.Cut != "" {
			lines = append(lines, "cut short: "+termSafe(rev.Cut))
		}
		for _, h := range rev.Hidden {
			lines = append(lines, "not shown: "+termSafe(h))
		}
		c["diff_not_shown"] = strings.Join(lines, "\n")
		c["diff"] += fmt.Sprintf("\n... (cut here: %d more bytes not shown)\n", rev.TotalBytes-rev.ShownBytes)
	}
	return c
}
