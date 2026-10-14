package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Tool is one tool definition as a server listed it.
type Tool struct {
	Name        string
	Title       string
	Description string
	// Canonical is the canonical JSON of the hashed members (see Hash).
	Canonical []byte
	// Hash is the hex SHA-256 of Canonical.
	Hash string
	// Text is every string in the definition (names, descriptions, schema
	// text), for the poisoning checks.
	Text []string
}

// hashedMembers are the members of a tool definition that are pinned: what
// a client shows to the model or a person, and the arguments it will send.
var hashedMembers = []string{"name", "title", "description", "inputSchema", "outputSchema", "annotations"}

var (
	// ErrBadToolList: a result has a "tools" member that is not a list of
	// tool objects with string names.
	ErrBadToolList = errors.New("malformed tool list")
)

// ToolList reads a JSON-RPC result. It reports whether the result is a tool
// list (it has a "tools" member) and, if so, the tools. A "tools" member that
// is not a well-formed list is an error, as is a result that can be read two
// ways: either could be shown to a model unchecked.
func ToolList(result json.RawMessage) ([]Tool, bool, error) {
	o, err := ParseObject(result)
	if err != nil {
		return nil, false, nil // not an object: not a tool list
	}
	raw, ok := o.Get("tools")
	if !ok {
		return nil, false, nil
	}
	if o.Ambiguous {
		return nil, true, ErrAmbiguous
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, true, ErrBadToolList
	}
	tools := make([]Tool, 0, len(items))
	seen := map[string]bool{}
	for _, it := range items {
		t, err := parseTool(it)
		if err != nil {
			return nil, true, err
		}
		if seen[t.Name] {
			return nil, true, fmt.Errorf("%w: tool %q listed twice", ErrBadToolList, t.Name)
		}
		seen[t.Name] = true
		tools = append(tools, t)
	}
	return tools, true, nil
}

func parseTool(raw json.RawMessage) (Tool, error) {
	o, err := ParseObject(raw)
	if err != nil {
		return Tool{}, ErrBadToolList
	}
	var t Tool
	canon := map[string]any{}
	for _, k := range hashedMembers {
		v, ok := o.Get(k)
		if !ok {
			continue
		}
		val, err := decodeValue(v)
		if err != nil {
			return Tool{}, ErrBadToolList
		}
		canon[k] = val
	}
	if o.Ambiguous {
		return Tool{}, ErrAmbiguous
	}
	name, ok := canon["name"].(string)
	if !ok || name == "" {
		return Tool{}, fmt.Errorf("%w: a tool without a name", ErrBadToolList)
	}
	t.Name = name
	for _, f := range []struct {
		key string
		dst *string
	}{{"description", &t.Description}, {"title", &t.Title}} {
		if v, present := canon[f.key]; present {
			s, ok := v.(string)
			if !ok {
				return Tool{}, fmt.Errorf("%w: tool %q has a %s that is not text", ErrBadToolList, name, f.key)
			}
			*f.dst = s
		}
	}
	t.Canonical, err = canonicalJSON(canon)
	if err != nil {
		return Tool{}, ErrBadToolList
	}
	sum := sha256.Sum256(t.Canonical)
	t.Hash = hex.EncodeToString(sum[:])
	collectText(canon, &t.Text)
	return t, nil
}

func decodeValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// canonicalJSON encodes v with object members in sorted order, numbers as
// written, and no HTML escaping: the same definition always gives the same
// bytes, whatever order or spacing the server used.
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// collectText appends every string in v, member names included, in a
// stable order.
func collectText(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, e := range x {
			collectText(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			*out = append(*out, k)
			collectText(x[k], out)
		}
	}
}

// ToolCall reads the params of a tools/call request: the tool's name and
// its raw arguments.
func ToolCall(params json.RawMessage) (name string, args json.RawMessage, err error) {
	o, err := ParseObject(params)
	if err != nil {
		return "", nil, fmt.Errorf("tools/call without params: %w", ErrNotJSONRPC)
	}
	v, ok := o.Get("name")
	if !ok || json.Unmarshal(v, &name) != nil || name == "" {
		return "", nil, fmt.Errorf("tools/call without a tool name: %w", ErrNotJSONRPC)
	}
	args, _ = o.Get("arguments")
	if o.Ambiguous {
		return "", nil, ErrAmbiguous
	}
	return name, args, nil
}

// EscapeName makes a tool name safe to put in a policy resource: anything
// but letters, digits, '_', '-' and '.' is percent-encoded, so a name cannot
// contain a separator, a wildcard or white space.
func EscapeName(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
