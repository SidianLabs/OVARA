// Package textsafe classifies characters that change how text reads to a
// person without being visible: terminal control codes, bidi controls,
// zero-width and other format characters, Unicode tag characters,
// variation selectors and blank-looking fillers. The CLI uses it to print
// untrusted text safely; the MCP gate uses it to flag tool descriptions that
// carry text a person cannot see but a model reads.
package textsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kinds of hidden characters, as named to a person.
const (
	KindControl   = "control characters"
	KindBidi      = "bidi controls"
	KindZeroWidth = "zero-width characters"
	KindTag       = "tag characters (invisible text)"
	KindVariation = "variation selectors"
	KindFiller    = "blank-looking fillers"
	KindSeparator = "line/paragraph separators"
	KindFormat    = "other format characters"
)

// Kind names the class of r if it is a character that changes how the text
// around it is read or shown, or returns "".
func Kind(r rune) string {
	if unicode.IsControl(r) { // C0, DEL, C1 (ESC, CSI, OSC, ...)
		return KindControl
	}
	switch {
	case r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2066 && r <= 0x2069,            // bidi isolates
		r == 0x200E, r == 0x200F, r == 0x061C: // directional marks
		return KindBidi
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF, r == 0x180E, // zero-width
		r >= 0x2061 && r <= 0x2064: // invisible operators
		return KindZeroWidth
	case r >= 0xE0000 && r <= 0xE007F:
		return KindTag
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return KindVariation
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return KindFiller
	case r == 0x2028, r == 0x2029:
		return KindSeparator
	}
	if unicode.Is(unicode.Cf, r) {
		return KindFormat
	}
	return ""
}

// Unsafe reports characters that change how a terminal or a reader
// interprets the text around them.
func Unsafe(r rune) bool { return Kind(r) != "" }

// Escape makes one line of untrusted text safe to print: such characters
// become visible \u{...} escapes, invalid UTF-8 bytes \xNN, and line breaks
// a visible ⏎.
func Escape(s string) string {
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
		case Unsafe(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}

// EscapeLines keeps line structure (for diffs) and makes each line safe.
func EscapeLines(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = Escape(l)
	}
	return strings.Join(lines, "\n")
}

// Hidden counts the characters in s that a reader would not see, by kind.
// Ordinary layout (tab, line feed, carriage return) is not counted.
func Hidden(s string) map[string]int {
	var out map[string]int
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if k := Kind(r); k != "" {
			if out == nil {
				out = map[string]int{}
			}
			out[k]++
		}
	}
	return out
}
