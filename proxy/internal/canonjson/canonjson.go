// Package canonjson reads JSON strictly and writes it back in one canonical
// form.
//
// Why Ovara re-encodes what it checks: a gate that reads a body with one
// parser and then forwards the original bytes leaves the upstream free to
// read those bytes with another parser. Wherever the two disagree (which of
// two duplicate keys wins, whether NaN is a number, what follows the first
// value, how invalid UTF-8 or a lone surrogate is read) the upstream can act
// on something the gate never saw. Every parser differential is a bypass of
// the check. Re-encoding the value the gate decided on, and forwarding that,
// removes the whole class: the upstream receives a body with exactly one
// reading, and it is the one that was checked.
//
// The strict reading accepts only UTF-8, a single top-level value with
// nothing but white space around it, no NaN or Infinity, and no object
// with two members of the same name (with Options.FoldCase, nor two whose
// names differ only in case). Numbers are kept exactly as written.
//
// The canonical form: no insignificant white space; object members sorted
// by name (byte order); strings escaped minimally (", \, control
// characters, U+2028 and U+2029), with no HTML escaping; numbers verbatim;
// array order kept. Decoding the canonical form gives the same value as
// decoding the input, and encoding it again gives the same bytes.
package canonjson

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrNotJSON: the bytes are not one JSON value (a syntax error, NaN or
	// Infinity, a second value, or nothing at all).
	ErrNotJSON = errors.New("not a single valid JSON value")
	// ErrInvalidUTF8: the bytes are not valid UTF-8.
	ErrInvalidUTF8 = errors.New("JSON is not valid UTF-8")
	// ErrDuplicateKey: an object has two members with the same name (or,
	// with FoldCase, names that differ only in case).
	ErrDuplicateKey = errors.New("JSON object with duplicate member names")
)

// Ambiguous reports an error for bytes that are JSON to a lenient reader
// but that readers do not agree on (duplicate keys, invalid UTF-8).
func Ambiguous(err error) bool {
	return errors.Is(err, ErrDuplicateKey) || errors.Is(err, ErrInvalidUTF8)
}

// Options adjust the strict reading.
type Options struct {
	// FoldCase makes member names that differ only in case duplicates
	// (Unicode simple folding, as case-insensitive readers match them).
	FoldCase bool
	// AllowBOM ignores a leading UTF-8 byte order mark. It is not part of
	// the canonical form.
	AllowBOM bool
}

var bom = []byte("\xef\xbb\xbf")

// Decode reads data strictly. Objects come back as map[string]any, arrays
// as []any, numbers as json.Number (as written), and strings, booleans and
// null as string, bool and nil.
func Decode(data []byte, o Options) (any, error) {
	if o.AllowBOM && len(data) >= len(bom) && string(data[:len(bom)]) == string(bom) {
		data = data[len(bom):]
	}
	// json.Valid is the syntax check (one value, no NaN, nesting bounded);
	// the walk below can then assume well-formed input. It lets invalid
	// UTF-8 through inside strings, which the next check does not.
	if !json.Valid(data) {
		return nil, ErrNotJSON
	}
	if !utf8.Valid(data) {
		return nil, ErrInvalidUTF8
	}
	p := parser{b: data, fold: o.FoldCase}
	p.ws()
	return p.value()
}

// Encode writes v (as Decode returns it) in canonical form.
func Encode(v any) ([]byte, error) {
	var e encoder
	if err := e.value(v); err != nil {
		return nil, err
	}
	return e.b, nil
}

// Canonical reads data strictly and returns its canonical form.
func Canonical(data []byte, o Options) ([]byte, error) {
	v, err := Decode(data, o)
	if err != nil {
		return nil, err
	}
	// The canonical form is rarely longer than the input.
	e := encoder{b: make([]byte, 0, len(data)+len(data)/16)}
	if err := e.value(v); err != nil {
		return nil, err
	}
	return e.b, nil
}

type parser struct {
	b    []byte
	i    int
	fold bool
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() (any, error) {
	switch c := p.b[p.i]; c {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		return p.str(), nil
	case 't':
		p.i += 4
		return true, nil
	case 'f':
		p.i += 5
		return false, nil
	case 'n':
		p.i += 4
		return nil, nil
	default:
		start := p.i
		for p.i < len(p.b) {
			switch p.b[p.i] {
			case '-', '+', '.', 'e', 'E', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				p.i++
				continue
			}
			break
		}
		return json.Number(p.b[start:p.i]), nil
	}
}

func (p *parser) object() (any, error) {
	p.i++ // {
	m := map[string]any{}
	var folded map[string]bool
	if p.fold {
		folded = map[string]bool{}
	}
	p.ws()
	if p.b[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		k := p.str()
		if _, dup := m[k]; dup {
			return nil, ErrDuplicateKey
		}
		if p.fold {
			f := Fold(k)
			if folded[f] {
				return nil, ErrDuplicateKey
			}
			folded[f] = true
		}
		p.ws()
		p.i++ // :
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		m[k] = v
		p.ws()
		if p.b[p.i] == '}' {
			p.i++
			return m, nil
		}
		p.i++ // ,
	}
}

func (p *parser) array() (any, error) {
	p.i++ // [
	a := []any{}
	p.ws()
	if p.b[p.i] == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		if p.b[p.i] == ']' {
			p.i++
			return a, nil
		}
		p.i++ // ,
	}
}

// str reads a string token the way encoding/json does: a \u escape of a
// lone surrogate reads as U+FFFD.
func (p *parser) str() string {
	p.i++ // opening quote
	start := p.i
	for p.b[p.i] != '"' && p.b[p.i] != '\\' {
		p.i++
	}
	if p.b[p.i] == '"' {
		s := string(p.b[start:p.i])
		p.i++
		return s
	}
	out := append([]byte(nil), p.b[start:p.i]...)
	for {
		c := p.b[p.i]
		switch c {
		case '"':
			p.i++
			return string(out)
		case '\\':
			p.i++
			switch e := p.b[p.i]; e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r := getu4(p.b[p.i+1:])
				p.i += 4
				if utf16.IsSurrogate(r) {
					r2 := rune(-1)
					if p.i+6 < len(p.b) && p.b[p.i+1] == '\\' && p.b[p.i+2] == 'u' {
						r2 = getu4(p.b[p.i+3:])
					}
					if d := utf16.DecodeRune(r, r2); d != unicode.ReplacementChar {
						p.i += 6
						r = d
					} else {
						r = unicode.ReplacementChar
					}
				}
				out = utf8.AppendRune(out, r)
			}
			p.i++
		default:
			out = append(out, c)
			p.i++
		}
	}
}

// getu4 decodes four hex digits (already validated as such).
func getu4(b []byte) rune {
	if len(b) < 4 {
		return -1
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			c = c - 'A' + 10
		default:
			return -1
		}
		r = r<<4 | rune(c)
	}
	return r
}

type encoder struct{ b []byte }

var errUnsupported = errors.New("canonjson: value of a type Decode does not return")

func (e *encoder) value(v any) error {
	switch t := v.(type) {
	case nil:
		e.b = append(e.b, "null"...)
	case bool:
		if t {
			e.b = append(e.b, "true"...)
		} else {
			e.b = append(e.b, "false"...)
		}
	case json.Number:
		// A number, and only a number: valid JSON starting like one.
		if t == "" || !(t[0] == '-' || ('0' <= t[0] && t[0] <= '9')) || !json.Valid([]byte(t)) {
			return errUnsupported
		}
		e.b = append(e.b, t...)
	case string:
		e.str(t)
	case []any:
		e.b = append(e.b, '[')
		for i, x := range t {
			if i > 0 {
				e.b = append(e.b, ',')
			}
			if err := e.value(x); err != nil {
				return err
			}
		}
		e.b = append(e.b, ']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		e.b = append(e.b, '{')
		for i, k := range keys {
			if i > 0 {
				e.b = append(e.b, ',')
			}
			e.str(k)
			e.b = append(e.b, ':')
			if err := e.value(t[k]); err != nil {
				return err
			}
		}
		e.b = append(e.b, '}')
	default:
		return errUnsupported
	}
	return nil
}

const hexDigits = "0123456789abcdef"

// str writes s quoted. s is valid UTF-8 (Decode only returns such
// strings); an invalid byte is written as U+FFFD all the same.
func (e *encoder) str(s string) {
	e.b = append(e.b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			e.b = append(e.b, s[start:i]...)
			switch c {
			case '"', '\\':
				e.b = append(e.b, '\\', c)
			case '\n':
				e.b = append(e.b, '\\', 'n')
			case '\r':
				e.b = append(e.b, '\\', 'r')
			case '\t':
				e.b = append(e.b, '\\', 't')
			case '\b':
				e.b = append(e.b, '\\', 'b')
			case '\f':
				e.b = append(e.b, '\\', 'f')
			default:
				e.b = append(e.b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			e.b = append(e.b, s[start:i]...)
			e.b = append(e.b, `\ufffd`...)
			i += size
			start = i
			continue
		}
		// U+2028 and U+2029 end a line in JavaScript source; escaping them
		// keeps the output one line for any reader.
		if r == '\u2028' || r == '\u2029' {
			e.b = append(e.b, s[start:i]...)
			e.b = append(e.b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	e.b = append(e.b, s[start:]...)
	e.b = append(e.b, '"')
}

// Fold maps s to one spelling per case-insensitive equivalence class
// (Unicode simple folding, which is what case-insensitive JSON readers use:
// "K" and the Kelvin sign fold together).
func Fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}
