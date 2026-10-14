package main

import "ovara.proxy/internal/textsafe"

// Everything the agent controls (URLs, query strings, body previews, file
// names, diffs, command lines) reaches a person's terminal through these
// functions. A raw escape sequence could move the cursor, recolour or erase
// what is on screen and print a harmless-looking request over the real one;
// bidi and invisible characters can make text read differently from what it
// is. Such characters are shown as visible \u{...} escapes instead.

// termSafe makes one line of untrusted text safe to print. Line breaks
// become a visible ⏎. The character classes live in internal/textsafe, which
// the MCP gate shares to flag tool descriptions.
func termSafe(s string) string { return textsafe.Escape(s) }

// termSafeLines keeps line structure (for diffs) and makes each line safe.
func termSafeLines(s string) string { return textsafe.EscapeLines(s) }

// multiLineContext are the context values whose lines are kept apart (a
// diff, the commit-back's one-path-per-line lists and the MCP gate's list of
// tool definitions); each line is still made safe on its own.
var multiLineContext = map[string]bool{"diff": true, "kept_out": true, "sensitive": true, "diff_not_shown": true, "mcp_tools": true}

// sanitizeApproval makes every agent-influenced field of an approval safe to
// print, once, where approvals enter the CLI.
func sanitizeApproval(a pendingApproval) pendingApproval {
	a.ApprovalID = termSafe(a.ApprovalID)
	a.ActionType = termSafe(a.ActionType)
	a.Resource = termSafe(a.Resource)
	a.AgentID = termSafe(a.AgentID)
	a.Status = termSafe(a.Status)
	if a.Context != nil {
		c := make(map[string]string, len(a.Context))
		for k, v := range a.Context {
			if multiLineContext[k] {
				c[termSafe(k)] = termSafeLines(v)
			} else {
				c[termSafe(k)] = termSafe(v)
			}
		}
		a.Context = c
	}
	return a
}
