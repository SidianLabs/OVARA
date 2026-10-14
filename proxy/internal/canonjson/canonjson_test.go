package canonjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// strictRef decodes data with encoding/json (numbers as json.Number), the
// reference reading the canonical form must preserve.
func strictRef(t testing.TB, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("reference decode of %q: %v", data, err)
	}
	return v
}

func TestCanonicalForm(t *testing.T) {
	cases := []struct{ in, want string }{
		{` { "b" : 1 , "a" : [ true , false , null ] } `, `{"a":[true,false,null],"b":1}`},
		{`{"n":1.50e+3,"m":-0,"big":123456789012345678901234567890}`, `{"big":123456789012345678901234567890,"m":-0,"n":1.50e+3}`},
		{`"\u0041\/\"<>&"`, `"A/\"<>&"`},
		{`"line\nbreak\ttab\u0001\b\f"`, `"line\nbreak\ttab\u0001\b\f"`},
		{"\"\\u2028\\u2029\"", "\"\\u2028\\u2029\""},
		{"\"\u2028\u2029\"", "\"\\u2028\\u2029\""},
		{"\"\\ud83d\\ude00\"", "\"\U0001F600\""},
		{"\"\\ud800x\"", "\"\uFFFDx\""},
		{"\"\\udc00\\ud83d\\ude00\"", "\"\uFFFD\U0001F600\""},
		{`[]`, `[]`},
		{`{}`, `{}`},
		{`{"z":{"y":{},"x":[]}}`, `{"z":{"x":[],"y":{}}}`},
	}
	for _, c := range cases {
		got, err := Canonical([]byte(c.in), Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if string(got) != c.want {
			t.Errorf("Canonical(%s) = %s, want %s", c.in, got, c.want)
		}
		if !reflect.DeepEqual(strictRef(t, got), strictRef(t, []byte(c.in))) {
			t.Errorf("%s: value changed", c.in)
		}
	}
}

func TestCanonicalRefuses(t *testing.T) {
	cases := []struct {
		in   string
		opt  Options
		want error
	}{
		{`{"a":1,"a":2}`, Options{}, ErrDuplicateKey},
		{`{"a":1,"a":2}`, Options{}, ErrDuplicateKey},
		{`[{"x":{"k":1,"k":1}}]`, Options{}, ErrDuplicateKey},
		{`{"a":1,"A":2}`, Options{FoldCase: true}, ErrDuplicateKey},
		{`{"k":1,"\u212a":2}`, Options{FoldCase: true}, ErrDuplicateKey}, // Kelvin sign
		{"{\"a\":\"\xff\"}", Options{}, ErrInvalidUTF8},
		{`{"a":NaN}`, Options{}, ErrNotJSON},
		{`{"a":Infinity}`, Options{}, ErrNotJSON},
		{`{"a":1} {"b":2}`, Options{}, ErrNotJSON},
		{`{"a":1}x`, Options{}, ErrNotJSON},
		{``, Options{}, ErrNotJSON},
		{"\xef\xbb\xbf{}", Options{}, ErrNotJSON},
		{"\xff\xfe{\x00}\x00", Options{}, ErrNotJSON}, // UTF-16LE
	}
	for _, c := range cases {
		_, err := Canonical([]byte(c.in), c.opt)
		if !errors.Is(err, c.want) {
			t.Errorf("Canonical(%q) err = %v, want %v", c.in, err, c.want)
		}
	}
	if _, err := Canonical([]byte(`{"a":1,"A":2}`), Options{}); err != nil {
		t.Errorf("case variants without FoldCase: %v", err)
	}
	if got, err := Canonical([]byte("\xef\xbb\xbf {\"a\":1}"), Options{AllowBOM: true}); err != nil || string(got) != `{"a":1}` {
		t.Errorf("BOM allowed: %s, %v", got, err)
	}
}

// checkProperties asserts what canonicalisation promises for one input
// that the strict reading accepts.
func checkProperties(t testing.TB, data []byte, o Options) {
	v, err := Decode(data, o)
	if err != nil {
		return
	}
	c, err := Encode(v)
	if err != nil {
		t.Fatalf("Encode after Decode of %q: %v", data, err)
	}
	// The strict reading agrees with encoding/json on input it accepts.
	in := data
	if o.AllowBOM {
		in = bytes.TrimPrefix(in, bom)
	}
	if ref := strictRef(t, in); !reflect.DeepEqual(ref, v) {
		t.Fatalf("Decode(%q) = %#v, encoding/json reads %#v", data, v, ref)
	}
	// decode(canonical(x)) == decode(x), under the strict reading and the
	// reference one.
	v2, err := Decode(c, o)
	if err != nil {
		t.Fatalf("canonical form %q of %q does not read back: %v", c, data, err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Fatalf("value changed: %q -> %q", data, c)
	}
	if ref := strictRef(t, c); !reflect.DeepEqual(ref, v) {
		t.Fatalf("encoding/json reads %q as %#v, want %#v", c, ref, v)
	}
	// canonical(canonical(x)) == canonical(x)
	c2, err := Canonical(c, o)
	if err != nil || !bytes.Equal(c, c2) {
		t.Fatalf("not idempotent: %q -> %q -> %q (%v)", data, c, c2, err)
	}
	// One line, whatever the input: stdio framing depends on it.
	if bytes.ContainsAny(c, "\r\n") {
		t.Fatalf("canonical form has a line break: %q", c)
	}
}

var seeds = []string{
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":[1,2.5e10,-0.0,"s"]}}}`,
	`[{"b":null,"a":true},{"c":false}]`,
	"\"\\ud83d\\ude00 \\ud800 \\u00e9 \\u2028 \\/ \\\\ \\\" \\b\\f\\n\\r\\t \\u001f\"",
	`{"K":1,"k":2}`,
	`{"a":1,"a":1}`,
	`{"x":NaN}`,
	"\xef\xbb\xbf{\"a\":[]}",
	`12345678901234567890.123e-45`,
	`{"model":"m","messages":[{"role":"user","content":"<b>hi</b> & bye"}]}`,
}

func FuzzCanonical(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, fold bool) {
		checkProperties(t, data, Options{FoldCase: fold, AllowBOM: fold})
	})
}

func TestCanonicalProperties(t *testing.T) {
	for _, s := range seeds {
		checkProperties(t, []byte(s), Options{})
		checkProperties(t, []byte(s), Options{FoldCase: true, AllowBOM: true})
	}
}

// modelRequest builds a model request body of about n bytes, shaped like a
// long conversation.
func modelRequest(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"model":"claude-x","max_tokens":4096,"stream":true,"system":"You are a coding agent.\nBe careful.","tools":[{"name":"bash","description":"run a command","input_schema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}],"messages":[`)
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"role":"user","content":[{"type":"text","text":"turn %d: please look at the file and tell me what \"it\" does.\nline two\tindented \u00e9 <tag> & more text to fill the buffer up"}]},`, i)
		fmt.Fprintf(&b, `{"role":"assistant","content":[{"type":"tool_use","id":"toolu_%d","name":"bash","input":{"command":"cat src/file_%d.go | head -n 40"}}]}`, i, i)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func BenchmarkCanonicalModelRequest1MiB(b *testing.B) {
	body := modelRequest(1 << 20)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Canonical(body, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCanonical1MiBIsFast is the performance sanity bound: a 1 MiB model
// request is canonicalised well inside 50 ms (best of a few runs, so a
// busy machine does not fail it).
func TestCanonical1MiBIsFast(t *testing.T) {
	body := modelRequest(1 << 20)
	best := time.Hour
	for range 5 {
		start := time.Now()
		if _, err := Canonical(body, Options{}); err != nil {
			t.Fatal(err)
		}
		best = min(best, time.Since(start))
	}
	limit := 50 * time.Millisecond
	if testing.CoverMode() != "" || raceEnabled {
		limit *= 10 // instrumented builds are several times slower
	}
	if best > limit {
		t.Fatalf("canonicalising 1 MiB took %v, want under %v", best, limit)
	}
	t.Logf("1 MiB canonicalised in %v", best)
}
