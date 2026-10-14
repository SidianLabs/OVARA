package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzSnifferSplitInvariance: the Sniffer gives the answer
// LooksLikeJSONRPC gives for the whole body, however the body is cut into
// pieces. A body that reaches the proxy in pieces must not be sniffed
// differently from the same bytes in one read.
func FuzzSnifferSplitInvariance(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}`,
		`{'method':'x'`, `{a:1,method :2}`, `[{id=1;method=>"x"}]`, "{\\u006dethod:1}",
		"\x00{\x00m\x00e\x00t\x00h\x00o\x00d\x00:\x001\x00", "\xef\xbb\xbf  {\"JSONRPC\":1,",
		`{xmethod:` + strings.Repeat("a", 600), `{"a":1,method` + strings.Repeat(" ", 700) + `:2}`,
		`hello "method"`, ``,
	} {
		f.Add([]byte(s), uint16(7), uint8(3))
	}
	f.Fuzz(func(t *testing.T, data []byte, cut uint16, chunk uint8) {
		want := LooksLikeJSONRPC(data)
		if got := sniffSplit(data, int(cut)%(len(data)+1)); got != want {
			t.Fatalf("%q cut at %d: %v, whole: %v", data, int(cut)%(len(data)+1), got, want)
		}
		if n := int(chunk)%64 + 1; sniffChunks(data, n) != want {
			t.Fatalf("%q in pieces of %d: not %v", data, n, want)
		}
	})
}

// FuzzToolCallNameIsAlwaysGated: a method name that a dispatcher using the
// standard library's own rules (case folded by strings.EqualFold, white space
// and control characters trimmed, a C string ending at a NUL) would run as
// tools/call is read as a tool call, and one that is not exactly tools/call
// is marked ambiguous so it is refused. The oracle here does not share code
// with the parser.
func FuzzToolCallNameIsAlwaysGated(f *testing.F) {
	for _, s := range []string{"tools/call", "Tools/Call", "tools/call ", "tools/call\x00x", "toolſ/call", "tools/callx", "Ping", "", " tools/call "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, method string) {
		if !utf8.ValidString(method) {
			return // invalid UTF-8 is refused on its own (ambiguous) and cannot be written in JSON as is
		}
		q, err := json.Marshal(method)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":` + string(q) + `,"params":{"name":"x"}}`))
		if err != nil {
			return // not a message (an empty method)
		}
		name := method
		if i := strings.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
		runs := strings.EqualFold(name, "tools/call")
		m := b.Messages[0]
		switch {
		case method == "tools/call":
			if !m.IsToolCall() || m.MisspeltToolCall() || b.Ambiguous {
				t.Fatalf("tools/call itself: %+v ambiguous %v", m, b.Ambiguous)
			}
		case runs:
			if !m.IsToolCall() || !m.MisspeltToolCall() || !b.Ambiguous || !b.IsMCP() {
				t.Fatalf("%q would run as tools/call but reads IsToolCall %v Misspelt %v Ambiguous %v IsMCP %v", method, m.IsToolCall(), m.MisspeltToolCall(), b.Ambiguous, b.IsMCP())
			}
		default:
			if m.MisspeltToolCall() {
				t.Fatalf("%q is not a tools/call by any reading but is marked misspelt", method)
			}
		}
	})
}
