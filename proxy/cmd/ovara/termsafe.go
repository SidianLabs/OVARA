package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Everything the agent controls (URLs, query strings, body previews, file
// names, diffs, command lines) reaches a person's terminal through these
// functions. A raw escape sequence could move the cursor, recolour or erase
// what is on screen and print a harmless-looking request over the real one;
// bidi and invisible characters can make text read differently from what it
// is. Such characters are shown as visible \u{...} escapes instead.

// termSafe makes one line of untrusted text safe to print. Line breaks
// become a visible ⏎.
func termSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i]) // invalid UTF-8 byte
		case r == '\n':
			b.WriteString(" ⏎ ")
		case r == '\r' && strings.HasPrefix(s[i+n:], "\n"):
			// CRLF shows as one ⏎
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}

// termSafeLines keeps line structure (for diffs) and makes each line safe.
func termSafeLines(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = termSafe(l)
	}
	return strings.Join(lines, "\n")
}

// unsafeRune reports characters that change how a terminal or a reader
// interprets the text around them.
func unsafeRune(r rune) bool {
	if unicode.IsControl(r) { // C0, DEL, C1 (ESC, CSI, OSC, ...)
		return true
	}
	switch {
	case r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2066 && r <= 0x2069,            // bidi isolates
		r == 0x200E, r == 0x200F, r == 0x061C, // directional marks
		r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF, r == 0x180E, // zero-width
		r >= 0x2061 && r <= 0x2064,                               // invisible operators
		r >= 0xE0000 && r <= 0xE007F,                             // tag characters (invisible text)
		r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF, // variation selectors
		r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, // Hangul fillers (blank-looking)
		r == 0x2028, r == 0x2029: // line/paragraph separators
		return true
	}
	return unicode.Is(unicode.Cf, r) // any other format character
}

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
			if k == "diff" {
				c[termSafe(k)] = termSafeLines(v)
			} else {
				c[termSafe(k)] = termSafe(v)
			}
		}
		a.Context = c
	}
	return a
}
