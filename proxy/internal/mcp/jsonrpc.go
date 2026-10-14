// Package mcp reads Model Context Protocol traffic (JSON-RPC 2.0) so that
// tool definitions can be pinned and tool calls decided one by one. It is
// shared by the proxy (MCP over HTTP: Streamable HTTP and the older HTTP+SSE
// transport) and `ovara mcp wrap` (MCP over stdio).
//
// Everything here reads untrusted bytes. Messages are read strictly: a body
// whose meaning could differ between this parser and the server's or the
// client's (duplicate keys, keys that differ only in case, invalid UTF-8) is
// reported as ambiguous so that callers can refuse it instead of deciding on
// one reading while the other side acts on another.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"ovara.proxy/internal/canonjson"
)

// MaxMessageBytes bounds one JSON-RPC message (or batch, or SSE event) that
// is read whole to be checked.
const MaxMessageBytes = 4 << 20

// methods are the MCP method names (2024-11-05 through 2025-11-25). Any
// "notifications/..." method counts too.
var methods = map[string]bool{
	"initialize": true, "ping": true,
	"tools/list": true, "tools/call": true,
	"resources/list": true, "resources/templates/list": true, "resources/read": true,
	"resources/subscribe": true, "resources/unsubscribe": true,
	"prompts/list": true, "prompts/get": true,
	"completion/complete": true, "logging/setLevel": true,
	"sampling/createMessage": true, "elicitation/create": true, "roots/list": true,
	"tasks/get": true, "tasks/list": true, "tasks/result": true, "tasks/cancel": true,
}

// IsMethod reports whether m is an MCP method name.
func IsMethod(m string) bool { return methods[m] || strings.HasPrefix(m, "notifications/") }

// toolCallMethod is the method whose spelling is a security decision: every
// tools/call is decided one by one.
const toolCallMethod = "tools/call"

var foldedToolCall = canonjson.Fold(toolCallMethod)

// misspeltToolCall reports a method name that is not "tools/call" as written
// but that a dispatcher which normalises names would run as one: it differs
// only in case (Unicode simple folding, as strings.EqualFold reads it), in
// white space or control characters around it, or in what follows a NUL (a C
// string ends there). Official SDKs match the name exactly; a hand-written
// router may not, and what such a router runs must not pass as other traffic.
func misspeltToolCall(method string) bool {
	if method == toolCallMethod {
		return false
	}
	if i := strings.IndexByte(method, 0); i >= 0 {
		method = method[:i]
	}
	method = strings.TrimFunc(method, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
	return canonjson.Fold(method) == foldedToolCall
}

var (
	// ErrNotJSONRPC: the bytes are not a JSON object or array of objects.
	ErrNotJSONRPC = errors.New("not a JSON-RPC message")
	// ErrAmbiguous: the message could be read two ways (duplicate or
	// case-variant keys, invalid UTF-8).
	ErrAmbiguous = errors.New("ambiguous JSON-RPC message")
)

// Message is one JSON-RPC message.
type Message struct {
	ID     json.RawMessage // nil for a notification
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  json.RawMessage
	// JSONRPC is the "jsonrpc" member as written ("2.0" for a valid one).
	JSONRPC string
}

// IsRequest reports a request (method and id).
func (m Message) IsRequest() bool { return m.Method != "" && m.ID != nil }

// IsResponse reports a response (result or error, no method).
func (m Message) IsResponse() bool { return m.Method == "" && (m.Result != nil || m.Error != nil) }

// IsToolCall reports a tools/call, or a message a lenient dispatcher would
// run as one (see MisspeltToolCall). Every such message is decided.
func (m Message) IsToolCall() bool { return m.Method == toolCallMethod || misspeltToolCall(m.Method) }

// MisspeltToolCall reports a method name that is not tools/call as written
// but would be run as one by a dispatcher that ignores case, trims the name,
// or ends it at a NUL. Parse marks such a message ambiguous.
func (m Message) MisspeltToolCall() bool { return misspeltToolCall(m.Method) }

// IsMCP reports whether the message is MCP traffic: an MCP method (or a
// misspelling of tools/call), or a JSON-RPC 2.0 response.
func (m Message) IsMCP() bool {
	return IsMethod(m.Method) || misspeltToolCall(m.Method) || (m.JSONRPC == "2.0" && m.IsResponse())
}

// Body is a parsed JSON-RPC body: one message or a batch.
type Body struct {
	Messages []Message
	Batch    bool
	// Ambiguous is set when the strict reading failed (see ErrAmbiguous)
	// but a lenient one still found messages: callers that would act on
	// them must refuse instead.
	Ambiguous bool
	// SHA256 is the hash (hex) of the bytes Parse was given. A caller that
	// holds the body in another form (the HTTP body before it was
	// decompressed) may set it to that form's hash. It goes with every
	// tool-call question, so an approval stands for these exact bytes.
	SHA256 string
}

// IsMCP reports whether any message in the body is MCP traffic.
func (b *Body) IsMCP() bool {
	for _, m := range b.Messages {
		if m.IsMCP() {
			return true
		}
	}
	return false
}

// Parse reads a JSON-RPC body. A leading byte order mark and surrounding
// white space are ignored. It returns ErrNotJSONRPC for anything that is not
// a JSON object or a non-empty array of objects, and ErrUnparseable instead
// when the bytes are not valid JSON but a lenient reader could take them
// for JSON-RPC (see LooksLikeJSONRPC). A body that parses only leniently
// comes back with Ambiguous set.
func Parse(data []byte) (*Body, error) {
	b, err := parse(data)
	if err != nil {
		if errors.Is(err, ErrNotJSONRPC) && !json.Valid(trimBody(data)) && LooksLikeJSONRPC(data) {
			return nil, ErrUnparseable
		}
		return nil, err
	}
	b.SHA256 = SHA256Hex(data)
	return b, nil
}

func trimBody(data []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf")))
}

func parse(data []byte) (*Body, error) {
	data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf"))
	data = bytes.TrimSpace(data)
	if len(data) == 0 || (data[0] != '{' && data[0] != '[') {
		return nil, ErrNotJSONRPC
	}
	ambiguous := !utf8.Valid(data) || CheckKeys(data) != nil
	b := &Body{Ambiguous: ambiguous}
	if data[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil || len(items) == 0 {
			return nil, ErrNotJSONRPC
		}
		b.Batch = true
		for _, it := range items {
			m, amb, err := parseMessage(it)
			if err != nil {
				// An invalid member does not make the rest of the batch
				// invisible: the server still runs the valid ones.
				b.Ambiguous = true
				continue
			}
			b.Ambiguous = b.Ambiguous || amb
			b.Messages = append(b.Messages, m)
		}
		if len(b.Messages) == 0 {
			return nil, ErrNotJSONRPC
		}
		return b, nil
	}
	m, amb, err := parseMessage(data)
	if err != nil {
		return nil, err
	}
	b.Ambiguous = b.Ambiguous || amb
	b.Messages = []Message{m}
	return b, nil
}

func parseMessage(raw json.RawMessage) (Message, bool, error) {
	o, err := ParseObject(raw)
	if err != nil {
		return Message{}, false, ErrNotJSONRPC
	}
	var m Message
	if v, ok := o.Get("jsonrpc"); ok {
		_ = json.Unmarshal(v, &m.JSONRPC)
	}
	if v, ok := o.Get("method"); ok {
		if json.Unmarshal(v, &m.Method) != nil || m.Method == "" {
			// a method that is not a string: nothing a server dispatches on
			return Message{}, false, ErrNotJSONRPC
		}
		if misspeltToolCall(m.Method) {
			o.Ambiguous = true // read as tools/call by some, as another method by others
		}
	}
	if v, ok := o.Get("id"); ok && string(v) != "null" {
		m.ID = v
	} else if ok && m.Method == "" {
		m.ID = v // a response may carry id null
	}
	m.Params, _ = o.Get("params")
	m.Result, _ = o.Get("result")
	m.Error, _ = o.Get("error")
	return m, o.Ambiguous, nil
}

// Object is a JSON object whose members are looked up the way the most
// lenient reader would: a member whose name differs from the asked name
// only in case is found too, and marks the object Ambiguous (a reader that
// matches names case-insensitively would act on it, a strict one would
// not).
type Object struct {
	members   map[string]json.RawMessage
	folded    map[string]string // fold(name) -> name as written
	Ambiguous bool
}

// ParseObject decodes raw as a JSON object.
func ParseObject(raw json.RawMessage) (*Object, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, ErrNotJSONRPC
	}
	o := &Object{members: m, folded: make(map[string]string, len(m))}
	for k := range m {
		f := fold(k)
		if _, dup := o.folded[f]; dup {
			o.Ambiguous = true
		}
		o.folded[f] = k
	}
	return o, nil
}

// Get returns the member named name. A member spelt with different case is
// returned too, with the object marked Ambiguous.
func (o *Object) Get(name string) (json.RawMessage, bool) {
	if v, ok := o.members[name]; ok {
		if k := o.folded[fold(name)]; k != name {
			o.Ambiguous = true // both "name" and "NAME"
		}
		return v, true
	}
	if k, ok := o.folded[fold(name)]; ok {
		o.Ambiguous = true
		return o.members[k], true
	}
	return nil, false
}

// Len is the number of members.
func (o *Object) Len() int { return len(o.members) }

// fold maps s to one spelling per case-insensitive equivalence class
// (canonjson.Fold: Unicode simple folding, which is what case-insensitive
// JSON readers use).
func fold(s string) string { return canonjson.Fold(s) }

// errDuplicateKey reports an object with two members whose names are equal
// ignoring case.
var errDuplicateKey = errors.New("duplicate key")

// CheckKeys walks data and fails on any object, at any depth, with two
// member names that are equal or differ only in case. Readers disagree on
// which of two such members wins; a check that read one while the other
// side acts on the other would decide about the wrong value.
func CheckKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		obj       bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].expectKey = true
				}
			}
			continue
		}
		if top == nil || !top.obj {
			continue
		}
		if top.expectKey {
			k, _ := tok.(string)
			f := fold(k)
			if top.keys[f] {
				return errDuplicateKey
			}
			top.keys[f] = true
			top.expectKey = false
		} else {
			top.expectKey = true
		}
	}
}

// ErrorCode is the JSON-RPC error code Ovara answers with when policy or a
// person refuses a message.
const ErrorCode = -32001

// ErrorMessage is the message of that error.
const ErrorMessage = "denied by Ovara policy"

// ParseErrorCode is the JSON-RPC "Parse error" code, given to a message
// refused because it cannot be read strictly.
const ParseErrorCode = -32700

// ParseErrorResponse is the error (id null, code ParseErrorCode) sent in
// place of a message that cannot be read strictly.
func ParseErrorResponse(server string) []byte {
	v := RefusedUnparseable()
	e := map[string]any{"code": ParseErrorCode, "message": "Parse error: " + ErrorMessage + ": " + v.Detail, "data": v.ErrorData(server)}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": e})
	return out
}

// ErrorResponse builds a JSON-RPC error response for id (null when id is
// nil) saying why Ovara refused. data is attached as the error's data.
func ErrorResponse(id json.RawMessage, detail string, data map[string]any) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	msg := ErrorMessage
	if detail != "" {
		msg += ": " + detail
	}
	e := map[string]any{"code": ErrorCode, "message": msg}
	if len(data) > 0 {
		e["data"] = data
	}
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	return out
}
