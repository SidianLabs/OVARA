package action

import (
	"fmt"
	"strings"
	"unicode"
)

// canonShell parses a shell command line into its canonical command
// list (spec §3.2). Output resource form:
//
//	exe a1 a2 | exe b1 ; exe c   (separators preserved)
//
// Quoting normalized away (quotes are syntax, not semantics);
// env-prefix assignments kept as `VAR=val` argv0 prefixes;
// redirects appended as `>path` / `<path`.
//
// flagParse is set when constructs appear that this parser cannot
// fully model — eval, command substitution with side effects,
// globs, here-docs. Flagged actions stay evaluatable but policy can
// escalate on ParseFlag (and corpus records keep the flag).
func canonShell(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, fmt.Errorf("action: empty command")
	}
	toks, flag, err := tokenize(raw)
	if err != nil {
		return "", flag, err
	}
	out := render(toks)
	if out == "" {
		// e.g. raw was `""` — quoted emptiness is still no command
		return "", flag, fmt.Errorf("action: empty command")
	}
	if !isCanonicalForm(out) {
		// trailing whitespace (incl. an escaped `\ `) can't survive the
		// input trim on re-parse — a word ending in space has no stable
		// canonical form; fail closed
		return "", flag, fmt.Errorf("action: command ends in whitespace")
	}
	return out, flag, nil
}

type tok struct {
	s      string // literal text
	op     bool   // true for separators/redirects (|;&&|| >> > < 2>)
	parsed bool   // false when the token contains unexpanded syntax
	glued  bool   // directly abuts the previous token (no whitespace) —
	// `'"'0` is ONE arg; space-joining would lie about argv
}

func tokenize(s string) ([]tok, bool, error) {
	var toks []tok
	flag := false
	i := 0
	sawSpace := true // leading position counts as separated
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
			sawSpace = true
		case c == ';':
			toks = append(toks, tok{s: ";", op: true})
			i++
			sawSpace = true
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, tok{s: "||", op: true})
			i += 2
			sawSpace = true
		case c == '|':
			toks = append(toks, tok{s: "|", op: true})
			i++
			sawSpace = true
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, tok{s: "&&", op: true})
			i += 2
			sawSpace = true
		case c == '&':
			// bare & = background — model as separator
			toks = append(toks, tok{s: ";", op: true})
			i++
			sawSpace = true
		case c == '>' || c == '<' || (c == '2' && i+1 < len(s) && s[i+1] == '>'):
			// redirect operator + target; `<` forms (here-doc/string)
			// carry bodies the tokenizer can't model — flag them
			if c == '<' {
				flag = true
			}
			op := string(c)
			if c == '2' {
				op = "2>"
				i++
			}
			i++
			if i < len(s) && s[i] == '>' {
				op += ">"
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			start := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != ';' && s[i] != '|' && s[i] != '&' && s[i] != '<' && s[i] != '>' {
				i++
			}
			toks = append(toks, tok{s: op + s[start:i], op: true})
			sawSpace = true
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, flag, fmt.Errorf("action: unterminated quote")
			}
			toks = append(toks, tok{s: s[i+1 : i+1+end],
				glued: !sawSpace && len(toks) > 0})
			sawSpace = false
			i += end + 2
		case c == '"':
			end, inner, f, err := dquote(s, i)
			if err != nil {
				return nil, flag, err
			}
			flag = flag || f
			toks = append(toks, tok{s: inner, parsed: !f,
				glued: !sawSpace && len(toks) > 0})
			sawSpace = false
			i = end
		case c == '`' || strings.HasPrefix(s[i:], "$("):
			// command substitution — semantics depend on contents;
			// keep literally + flag
			flag = true
			start := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != ';' && s[i] != '|' && s[i] != '&' {
				i++
			}
			toks = append(toks, tok{s: s[start:i], parsed: false,
				glued: !sawSpace && len(toks) > 0})
			sawSpace = false
		case c == '$' || c == '*' || c == '?' || c == '[':
			// expansions/globs — keep literally + flag
			flag = true
			fallthrough
		default:
			var b strings.Builder
			for i < len(s) && !strings.ContainsRune(" \t\n;|&<>\"'", rune(s[i])) {
				if s[i] == '$' || s[i] == '*' || s[i] == '?' || s[i] == '[' || s[i] == '`' {
					flag = true
				}
				if s[i] == '\\' && i+1 < len(s) {
					// escape: next char is literal — canonical form
					// uses backslash-escapes for quotes/backslash
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			toks = append(toks, tok{s: b.String(), parsed: !flag,
				glued: !sawSpace && len(toks) > 0})
			sawSpace = false
		}
	}
	return toks, flag, nil
}

// dquote scans a "..." region; expansions inside count as flagged.
func dquote(s string, i int) (int, string, bool, error) {
	var b strings.Builder
	flag := false
	i++ // skip "
	for i < len(s) && s[i] != '"' {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			i++
			continue
		}
		if s[i] == '$' || s[i] == '`' {
			flag = true
		}
		b.WriteByte(s[i])
		i++
	}
	if i >= len(s) {
		return 0, "", flag, fmt.Errorf("action: unterminated dquote")
	}
	return i + 1, b.String(), flag, nil
}

// render emits the canonical form. Word tokens escape `"`, `'`, `\`
// so the output re-parses identically (a literal quote in a word must
// never re-enter the quote syntax). Glued tokens join without a space
// — token adjacency is semantic (argv structure), not formatting.
func render(toks []tok) string {
	var b strings.Builder
	for _, t := range toks {
		if t.glued && len(toks) > 0 && b.Len() > 0 {
			// no separator
		} else if b.Len() > 0 {
			b.WriteByte(' ')
		}
		if t.op {
			b.WriteString(t.s)
			continue
		}
		if t.s == "" {
			// an empty arg is still an arg — keep it explicit
			b.WriteString("\"\"")
			continue
		}
		for i := 0; i < len(t.s); i++ {
			if isShellMeta(t.s[i]) {
				b.WriteByte('\\')
			}
			b.WriteByte(t.s[i])
		}
	}
	return b.String()
}

// isCanonicalForm: a canonical string has no leading/trailing
// unicode whitespace — input is trimmed on every pass, so any such
// output could never round-trip.
func isCanonicalForm(s string) bool {
	return s != "" && strings.TrimSpace(s) == s
}

// isShellMeta reports characters that would re-enter tokenizer syntax
// (quotes, separators, expansions, redirects, globs) or break a word
// apart. Canonical words escape them all — re-parse unescapes, so the
// form is stable AND the literal byte survives round-trips.
func isShellMeta(c byte) bool {
	if unicode.IsSpace(rune(c)) {
		return true
	}
	switch c {
	case '\'', '"', '\\',
		';', '|', '&', '<', '>',
		'$', '*', '?', '[', ']', '`',
		'(', ')', '{', '}', '!', '#', '~', '^':
		return true
	}
	return false
}
