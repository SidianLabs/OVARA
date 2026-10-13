package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Readers on the other side of the gate are not all as strict as this
// package. Python's json.loads, which the official Python SDK uses, takes
// NaN, Infinity and -Infinity, and given bytes it detects UTF-16 and UTF-32
// by their byte order marks or the pattern of NUL bytes (RFC 4627). A body
// this package cannot read but such a reader can would otherwise pass as
// "not JSON-RPC" and reach the server with no decision. The sniffer below
// reads bytes the way the most lenient of those readers would, only far
// enough to say whether they could be JSON-RPC.

// ErrUnparseable: the bytes are not valid JSON as this package reads it
// (UTF-8, no NaN or Infinity, one value) but a lenient reader could take
// them for a JSON-RPC message. Callers refuse such a body.
var ErrUnparseable = errors.New("the message looks like JSON-RPC but cannot be read strictly")

// LooksLikeJSONRPC reports whether a lenient JSON reader could take data
// for JSON-RPC: once BOMs and the NUL bytes of UTF-16/32 are set aside and
// \u escapes of ASCII characters are read, it starts with '{' or '[' and
// either names a "jsonrpc" or "method" member (in any case) or holds a NaN
// or Infinity literal.
func LooksLikeJSONRPC(data []byte) bool {
	var s Sniffer
	_, _ = s.Write(data)
	return s.Found()
}

// Sniffer is LooksLikeJSONRPC over a stream written in pieces of any size.
type Sniffer struct {
	decided bool // the first significant character has been seen
	jsonish bool // ... and it opens an object or an array
	found   bool
	tail    []byte // the end of the previous piece, read again with the next
}

// sniffOverlap is how much of one piece is read again with the next, so a
// token split between pieces is still seen. It covers the longest token
// written in UTF-32 with every character escaped.
const sniffOverlap = 512

// Write never fails.
func (s *Sniffer) Write(p []byte) (int, error) {
	if s.found || (s.decided && !s.jsonish) {
		return len(p), nil
	}
	window := append(append([]byte(nil), s.tail...), p...)
	norm := normalizeLenient(window)
	if !s.decided {
		rest := bytes.TrimLeft(norm, " \t\r\n\xef\xbb\xbf\xfe\xff")
		if len(rest) > 0 {
			s.decided = true
			s.jsonish = rest[0] == '{' || rest[0] == '['
		}
	}
	if s.jsonish && (bytes.Contains(norm, []byte(`"jsonrpc"`)) || bytes.Contains(norm, []byte(`"method"`)) || hasNonFinite(norm)) {
		s.found = true
	}
	if len(window) > sniffOverlap {
		window = window[len(window)-sniffOverlap:]
	}
	s.tail = window
	return len(p), nil
}

// Found reports what LooksLikeJSONRPC would for everything written.
func (s *Sniffer) Found() bool { return s.found }

// normalizeLenient drops NUL bytes (what is left of UTF-16/32 text once
// they are gone is its ASCII), turns \u escapes of ASCII characters into
// the characters and folds ASCII to lower case.
func normalizeLenient(b []byte) []byte {
	stripped := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0 {
			stripped = append(stripped, c)
		}
	}
	out := make([]byte, 0, len(stripped))
	for i := 0; i < len(stripped); i++ {
		c := stripped[i]
		if c == '\\' && i+5 < len(stripped) && (stripped[i+1] == 'u' || stripped[i+1] == 'U') {
			if v, ok := hex4(stripped[i+2 : i+6]); ok && v < 0x80 {
				c = byte(v)
				i += 5
			}
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return out
}

func hex4(b []byte) (int, bool) {
	v := 0
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9':
			v = v<<4 | int(c-'0')
		case 'a' <= c && c <= 'f':
			v = v<<4 | int(c-'a'+10)
		case 'A' <= c && c <= 'F':
			v = v<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// hasNonFinite reports a NaN or Infinity literal where a value starts
// (after ':', '[' or ','), followed by a character that ends it. b is
// already folded to lower case.
func hasNonFinite(b []byte) bool {
	for i, c := range b {
		if c != ':' && c != '[' && c != ',' {
			continue
		}
		j := i + 1
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
			j++
		}
		if j < len(b) && (b[j] == '-' || b[j] == '+') {
			j++
		}
		for _, lit := range []string{"nan", "infinity"} {
			k := j + len(lit)
			if k < len(b) && string(b[j:k]) == lit && !isIdentByte(b[k]) {
				return true
			}
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c >= 0x80
}

// ArgumentsSHA256 is the SHA-256 (hex) of the canonical form of a tool
// call's arguments: members sorted by name, no insignificant white space,
// numbers as written. Two calls whose arguments differ in any value hash
// differently; the same arguments written in another order hash the same.
// Arguments that cannot be decoded are hashed as they are.
func ArgumentsSHA256(args json.RawMessage) string {
	if len(bytes.TrimSpace(args)) == 0 {
		args = json.RawMessage("null")
	}
	canon := []byte(args)
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) == nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if enc.Encode(v) == nil {
			canon = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		}
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// SHA256Hex is the SHA-256 (hex) of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
