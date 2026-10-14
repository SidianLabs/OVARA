package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Two tool calls with different arguments never produce the same approval
// context: the arguments are bound by their hash, so the gateway's dedupe
// (agent, action, env, resource, context) cannot hand the second call the
// first call's approval, and the approver can tell them apart.
func TestToolCallPreviewBindsArguments(t *testing.T) {
	st, _ := OpenStore("")
	tools, _, err := ToolList(json.RawMessage(`{"tools":[{"name":"send_email","description":"Send.","inputSchema":{"type":"object"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Approve("h/mcp", tools, "a1"); err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	g := NewGate(st, AskFunc(func(ctx context.Context, a, r string, p map[string]string) (string, string) {
		got = append(got, p)
		return OutcomeAllow, ""
	}), nil)
	pad := strings.Repeat("x", 450)
	g.ToolCall(context.Background(), "h/mcp", "send_email", json.RawMessage(`{"body":"`+pad+`","to":"boss@corp.examp"}`))
	g.ToolCall(context.Background(), "h/mcp", "send_email", json.RawMessage(`{"body":"`+pad+`","to":"evil@atk.exampl"}`))
	if reflect.DeepEqual(got[0], got[1]) {
		t.Fatalf("two different tool calls give identical approval contexts: %v", got[0])
	}
	if got[0]["arguments_sha256"] == "" || got[0]["arguments_sha256"] == got[1]["arguments_sha256"] {
		t.Errorf("arguments_sha256 missing or equal: %q %q", got[0]["arguments_sha256"], got[1]["arguments_sha256"])
	}

	// The hash is of the canonical form: the same arguments written
	// differently hash the same.
	a, b := ArgumentsSHA256(json.RawMessage(`{"b":1, "a":"x"}`)), ArgumentsSHA256(json.RawMessage(`{"a":"x","b":1}`))
	if a != b || len(a) != 64 {
		t.Errorf("canonical hash differs: %s %s", a, b)
	}
	if ArgumentsSHA256(json.RawMessage(`{"a":1}`)) == ArgumentsSHA256(json.RawMessage(`{"a":1.0}`)) {
		t.Error("different number spellings hash the same")
	}
}

// The request body's hash comes along with every tool call of the body.
func TestClientBodyCarriesBodyHash(t *testing.T) {
	st, _ := OpenStore("")
	tools, _, _ := ToolList(json.RawMessage(`{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`))
	_ = st.Approve("h/mcp", tools, "a1")
	var got map[string]string
	g := NewGate(st, AskFunc(func(ctx context.Context, a, r string, p map[string]string) (string, string) {
		got = p
		return OutcomeAllow, ""
	}), nil)
	b, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	b.SHA256 = "abc123"
	g.ClientBody(context.Background(), "h/mcp", b)
	if got["body_sha256"] != "abc123" || got["arguments_sha256"] == "" {
		t.Errorf("preview %v", got)
	}
}

func TestLooksLikeJSONRPC(t *testing.T) {
	yes := []string{
		`{"jsonrpc":"2.0","method":"x","params":{"a":NaN}}`,
		`{"x":Infinity}`,
		`[{"y": -Infinity}]`,
		`{"method":"tools/call",}`,
		"\x00{\x00\"\x00m\x00e\x00t\x00h\x00o\x00d\x00\"\x00:",
		"\xef\xbb\xbf{\"JSONRPC\":1,",
		"  \n{\"method\":\"a\"}{}",
		// Readers that take single-quoted or unquoted member names
		// (Gson, JSON5, lenient Kotlin) and = or ; as separators.
		`{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'x'}}`,
		`{'method':'x'`,
		`{jsonrpc:"2.0",id:1,method:"tools/call"}`,
		`{ method : "tools/call" }`,
		"{\n  method\t:\n\"tools/call\"}",
		`[{id=1;method=>"tools/call"}]`,
		`{"a":1,/*c*/method:2}`,
		"{\\u006dethod:1}",
		"\x00{\x00m\x00e\x00t\x00h\x00o\x00d\x00:\x001\x00",
	}
	no := []string{``, `hello "method"`, `{"a":"financial"`, `{"nanny":1,`, `--boundary "jsonrpc"`, `{"a":"b"}`,
		// near-misses of the names above
		`{methods:1,`, `{x_method:1,`, `{$method:1,`, `{"a":"methodology"`, `{prejsonrpc:1,`, `{method`, `[1,2,3`, `method:1`}
	for _, s := range yes {
		if !LooksLikeJSONRPC([]byte(s)) {
			t.Errorf("%q: not seen as JSON-RPC", s)
		}
	}
	for _, s := range no {
		if LooksLikeJSONRPC([]byte(s)) {
			t.Errorf("%q: seen as JSON-RPC", s)
		}
	}
	// Parse says so when it refuses such a body.
	if _, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":NaN}}`)); err != ErrUnparseable {
		t.Errorf("Parse: %v, want ErrUnparseable", err)
	}
}

// A tool list a lenient client would read but Go cannot is refused.
func TestServerBodyRefusesUnparseableJSONRPC(t *testing.T) {
	st, _ := OpenStore("")
	g := NewGate(st, AskFunc(func(ctx context.Context, a, r string, p map[string]string) (string, string) {
		return OutcomeAllow, ""
	}), nil)
	res := g.ServerBody(context.Background(), "h/mcp", []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{"x":NaN}}]}}`))
	if res.Verdict.Allowed() || !res.IsMCP {
		t.Fatalf("verdict %+v", res)
	}
	if res := g.ServerBody(context.Background(), "h/mcp", []byte(`plain text`)); !res.Verdict.Allowed() {
		t.Fatalf("plain text refused: %+v", res)
	}
}
