package action

import (
	"fmt"
	"strings"
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
	return render(toks), flag, nil
}

type tok struct {
	s     string // literal text
	op    bool   // true for separators/redirects (|;&&|| >> > < 2>)
	parsed bool  // false when the token contains unexpanded syntax
}

func tokenize(s string) ([]tok, bool, error) {
	var toks []tok
	flag := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == ';':
			toks = append(toks, tok{s: ";", op: true})
			i++
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, tok{s: "||", op: true})
			i += 2
		case c == '|':
			toks = append(toks, tok{s: "|", op: true})
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, tok{s: "&&", op: true})
			i += 2
		case c == '&':
			// bare & = background — model as separator
			toks = append(toks, tok{s: ";", op: true})
			i++
		case c == '>' || c == '<' || (c == '2' && i+1 < len(s) && s[i+1] == '>'):
			// redirect operator + target
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
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != ';' && s[i] != '|' && s[i] != '&' {
				i++
			}
			toks = append(toks, tok{s: op + s[start:i], op: true})
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, flag, fmt.Errorf("action: unterminated quote")
			}
			toks = append(toks, tok{s: s[i+1 : i+1+end]})
			i += end + 2
		case c == '"':
			end, inner, f, err := dquote(s, i)
			if err != nil {
				return nil, flag, err
			}
			flag = flag || f
			toks = append(toks, tok{s: inner, parsed: !f})
			i = end
		case c == '`' || strings.HasPrefix(s[i:], "$("):
			// command substitution — semantics depend on contents;
			// keep literally + flag
			flag = true
			start := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != ';' && s[i] != '|' && s[i] != '&' {
				i++
			}
			toks = append(toks, tok{s: s[start:i], parsed: false})
		case c == '$' || c == '*' || c == '?' || c == '[':
			// expansions/globs — keep literally + flag
			flag = true
			fallthrough
		default:
			start := i
			for i < len(s) && !strings.ContainsRune(" \t\n;|&", rune(s[i])) {
				if s[i] == '$' || s[i] == '*' || s[i] == '?' || s[i] == '[' || s[i] == '`' {
					flag = true
				}
				i++
			}
			toks = append(toks, tok{s: s[start:i], parsed: !flag})
			_ = flag // parsed flag propagated below
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

func render(toks []tok) string {
	var parts []string
	for _, t := range toks {
		parts = append(parts, t.s)
	}
	return strings.Join(parts, " ")
}
