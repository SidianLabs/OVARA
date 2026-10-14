package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// sniffSplit feeds data to a Sniffer in two pieces cut at i.
func sniffSplit(data []byte, i int) bool {
	var s Sniffer
	_, _ = s.Write(data[:i])
	_, _ = s.Write(data[i:])
	return s.Found()
}

// sniffChunks feeds data to a Sniffer n bytes at a time.
func sniffChunks(data []byte, n int) bool {
	var s Sniffer
	for len(data) > 0 {
		k := min(n, len(data))
		_, _ = s.Write(data[:k])
		data = data[k:]
	}
	return s.Found()
}

// The Sniffer is LooksLikeJSONRPC over a stream: whatever the size of the
// pieces a body arrives in, the answer is the one for the body in one piece.
// A body that reached the proxy in pieces must not be sniffed differently
// from the same bytes in one read.
func TestSnifferAnswersTheSameForEverySplit(t *testing.T) {
	pad := strings.Repeat(" ", 700) // more than the overlap kept between pieces
	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}`,
		`{"a":1,"method"` + pad + `:"tools/call",}`,
		`{"a":1,"jsonrpc"` + pad + `:"2.0",}`,
		`{"a":"` + pad + `","method":"x",}`,
		"{\"\\u006d\\u0065thod\":\"x\",}",
		"\xef\xbb\xbf  {\"JSONRPC\":1,",
		utf16leASCII(`{"method":"tools/call","x":NaN}`),
		// member names a lenient reader takes: single-quoted, bare, with
		// = or ; separators, and white space (also NULs) between name and
		// separator long enough to span several pieces
		`{'method'` + pad + `:1}`,
		`{a:1,method` + pad + `:2}`,
		`{a:1,method` + pad + `=2}`,
		`{"a":1;` + pad + `jsonrpc` + pad + `=>"2.0"}`,
		`{"a":"` + pad + `",method:1}`,
		"{\"a\":1,m\\u0065thod\t\r\n:1}",
		utf16leASCII(`{a:1,method : 2}`),
		// not JSON-RPC, and must stay so however it is split; the last one
		// has the name exactly at the start of the text kept between pieces
		`{xmethod:` + strings.Repeat("a", 600),
		`{methods` + pad + `:1}`,
		`{x_method` + pad + `:1}`,
		`{"a":"financial"`,
		`hello "method"`,
		`{"a":"b"}`,
	}
	for _, b := range bodies {
		data := []byte(b)
		want := LooksLikeJSONRPC(data)
		for i := 0; i <= len(data); i++ {
			if got := sniffSplit(data, i); got != want {
				t.Fatalf("%.50q split at %d: %v, whole body: %v", b, i, got, want)
			}
		}
		for _, n := range []int{1, 2, 3, 7, 64, 513} {
			if got := sniffChunks(data, n); got != want {
				t.Fatalf("%.50q in pieces of %d: %v, whole body: %v", b, n, got, want)
			}
		}
	}
}

func utf16leASCII(s string) string {
	b := make([]byte, 0, 2*len(s)+2)
	b = append(b, 0xff, 0xfe)
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return string(b)
}

// White space between a member name and its separator is as long as the body
// likes; padding must not hide the name.
func TestLooksLikeJSONRPCThroughLongWhiteSpace(t *testing.T) {
	for _, pad := range []string{strings.Repeat(" ", 700), strings.Repeat("\r\n\t ", 400), strings.Repeat(" \x00", 900)} {
		for _, b := range []string{
			`{a:1,method` + pad + `:2}`,
			`{a:1,jsonrpc` + pad + `=2}`,
			`{'method'` + pad + `:2}`,
		} {
			if !LooksLikeJSONRPC([]byte(b)) {
				t.Errorf("%d bytes of padding hid the name: %.40q", len(pad), b)
			}
		}
	}
}

func toolCallBody(t *testing.T, method string) []byte {
	t.Helper()
	m, err := json.Marshal(method)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"method":` + string(m) + `,"params":{"name":"delete_everything","arguments":{}}}`)
}

// A dispatcher that ignores case, trims the name, or stops it at a NUL would
// run "Tools/Call" as tools/call. Ovara decides every tools/call, so a name
// that reads as one to such a dispatcher is refused outright: never passed on
// as other traffic, and never put to a person as a call it is not spelt as.
func TestMisspeltToolCallIsRefusedNotPassedOn(t *testing.T) {
	for _, method := range []string{
		"Tools/Call", "TOOLS/CALL", "tools/CALL",
		"tools/call ", " tools/call", "\ttools/call\r\n", " tools/call", // white space of any kind
		"tools/call\x00", "tools/call\x00junk", // a C string ends at the NUL
		"toolſ/call", // U+017F folds to s, as strings.EqualFold reads it
	} {
		g, a := newTestGate(t)
		b, err := Parse(toolCallBody(t, method))
		if err != nil {
			t.Errorf("%q: %v", method, err)
			continue
		}
		if !b.IsMCP() || !b.Ambiguous || !b.Messages[0].IsToolCall() || !b.Messages[0].MisspeltToolCall() {
			t.Errorf("%q: IsMCP %v, Ambiguous %v, IsToolCall %v", method, b.IsMCP(), b.Ambiguous, b.Messages[0].IsToolCall())
		}
		checks := g.ClientBody(context.Background(), "srv", b)
		if len(checks) != 1 || checks[0].Verdict.Allowed() || checks[0].Verdict.Reasons[0] != "mcp_message_ambiguous" {
			t.Errorf("%q: not refused: %+v", method, checks)
		}
		if len(a.asked) != 0 {
			t.Errorf("%q: put to a person (%d questions)", method, len(a.asked))
		}
	}
}

// Names that are not tools/call by any such reading are left alone, so other
// JSON-RPC services (a "Ping" method, "tools/calls") are not caught.
func TestOtherMethodNamesAreNotMistakenForToolCalls(t *testing.T) {
	for _, method := range []string{"tools/calls", "tools/callx", "xtools/call", "tools/ call", "tools\x00/call", "tool/call", "Ping", "Initialize", ""} {
		b, err := Parse(toolCallBody(t, method))
		if err != nil {
			continue // an empty name is not a message at all
		}
		if b.Messages[0].IsToolCall() || b.Ambiguous || (!IsMethod(method) && b.IsMCP()) {
			t.Errorf("%q: IsToolCall %v, Ambiguous %v, IsMCP %v", method, b.Messages[0].IsToolCall(), b.Ambiguous, b.IsMCP())
		}
	}
	b, err := Parse(toolCallBody(t, "tools/call"))
	if err != nil || b.Ambiguous || !b.Messages[0].IsToolCall() || b.Messages[0].MisspeltToolCall() {
		t.Fatalf("tools/call itself: %v %+v", err, b)
	}
}
