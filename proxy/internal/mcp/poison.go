package mcp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"ovara.proxy/internal/textsafe"
)

// Signs that a tool definition carries instructions for the model rather
// than a description for its user. None of them proves anything; each is
// shown to the person deciding, as a warning.

// LongDescription is the description length past which a tool is flagged:
// a description long enough to hide a second purpose in.
const LongDescription = 1024

// instructionPhrases are wordings that address the model, ask for secrecy
// or reach for other tools and files.
var instructionPhrases = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|other|system)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|messages?)`), "tells the model to ignore its instructions"},
	{regexp.MustCompile(`(?i)\b(do not|don't|never|must not)\b[^.\n]{0,20}\b(tell|inform|mention|reveal|show|notify|alert)\b[^.\n]{0,20}\b(the )?user`), "asks to keep something from the user"},
	{regexp.MustCompile(`(?i)\bthe user\b[^.\n]{0,20}\b(must|should) not\b[^.\n]{0,20}\b(know|see|be told)`), "asks to keep something from the user"},
	{regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>`), "contains a tag addressed to the model (<IMPORTANT>, <system>, ...)"},
	{regexp.MustCompile(`(?i)\bbefore (using|calling|you use|you call|invoking)\b[^.\n]{0,30}\b(tool|function)\b[^.\n]{0,40}\b(read|open|call|use|fetch|send|pass|include)\b`), "tells the model to do something before using the tool"},
	{regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.env\b|mcp\.json|\.cursor/|_desktop_config\.json|/etc/passwd|private key)`), "mentions secret files or keys"},
	{regexp.MustCompile(`(?i)\b(this is (very |extremely )?important|very very important|critical:)`), "insists on importance in a way aimed at the model"},
	{regexp.MustCompile(`(?i)\b(instead of|rather than)\b[^.\n]{0,30}\b(the )?(other|original|real)\b[^.\n]{0,20}\b(tool|server|function)`), "steers the model away from another tool"},
	{regexp.MustCompile(`(?i)\b(send|forward|bcc|cc|copy|upload|post)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,10}[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), "tells the model to send something to an address"},
}

// Flags lists the warnings for one tool definition. others maps tool names
// pinned for other servers to their server (Store.OtherTools).
func Flags(t Tool, others map[string]string) []string {
	var out []string
	name := textsafe.Escape(t.Name)
	text := strings.Join(t.Text, "\n")
	if h := textsafe.Hidden(text); len(h) > 0 {
		kinds := make([]string, 0, len(h))
		total := 0
		for k, n := range h {
			kinds = append(kinds, k)
			total += n
		}
		sort.Strings(kinds)
		out = append(out, fmt.Sprintf("%s: %d hidden character(s) a person does not see but a model reads (%s)", name, total, strings.Join(kinds, ", ")))
		if hidden := decodeTags(text); hidden != "" {
			out = append(out, fmt.Sprintf("%s: the hidden tag characters spell %q", name, textsafe.Escape(cut(hidden, 200))))
			text += "\n" + hidden // the phrase checks read it too
		}
	}
	seen := map[string]bool{}
	for _, p := range instructionPhrases {
		if seen[p.what] {
			continue
		}
		if m := p.re.FindString(text); m != "" {
			seen[p.what] = true
			out = append(out, fmt.Sprintf("%s: %s (%q)", name, p.what, textsafe.Escape(cut(m, 80))))
		}
	}
	if n := len(t.Description); n > LongDescription {
		out = append(out, fmt.Sprintf("%s: description is %d bytes long", name, n))
	}
	if EscapeName(t.Name) != t.Name {
		out = append(out, fmt.Sprintf("%s: tool name has characters outside letters, digits, '_', '-' and '.'", name))
	}
	if srv, ok := others[t.Name]; ok {
		out = append(out, fmt.Sprintf("%s: same name as a tool of %s (shadowing)", name, srv))
	}
	if refs := mentions(text, t.Name, others); len(refs) > 0 {
		out = append(out, fmt.Sprintf("%s: mentions tools of other servers: %s (shadowing)", name, strings.Join(refs, ", ")))
	}
	return out
}

// mentions returns the other servers' tool names that appear in text as
// whole words. Names shorter than four characters are too common to mean
// anything.
func mentions(text, self string, others map[string]string) []string {
	var out []string
	for n, srv := range others {
		if len(n) < 4 || n == self {
			continue
		}
		i := 0
		for {
			j := strings.Index(text[i:], n)
			if j < 0 {
				break
			}
			at := i + j
			if !wordByte(text, at-1) && !wordByte(text, at+len(n)) {
				out = append(out, n+" ("+srv+")")
				break
			}
			i = at + 1
		}
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("and %d more", len(out)-8))
	}
	return out
}

// decodeTags spells out Unicode tag characters (U+E0020 to U+E007E mirror
// printable ASCII): the "ASCII smuggling" form of hidden instructions.
func decodeTags(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	return b.String()
}

func wordByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}
