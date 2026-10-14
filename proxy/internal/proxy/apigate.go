package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"ovara.proxy/internal/mcp"
)

// Body-aware API gates. Some APIs put the verb in the body, not in the
// URL: a GraphQL endpoint takes queries and mutations at one POST, the
// AWS JSON and Query APIs name the action in a header or a form field, and
// JSON-RPC names a method. A URL rule cannot tell a read from a write
// there. Once the URL decision is an allow by rule, these gates read the
// held body and ask about the operation as an action of its own:
//
//	graphql.operation  graphql:<host><path>/<query|mutation|subscription>:<name>
//	aws.action         aws:<service>:<Action>
//	jsonrpc.call       jsonrpc:<host><path>/<method>
//
// A read passes (a GraphQL query, an AWS Describe/List/Get, a JSON-RPC
// method whose name says it reads); everything else is a question unless a
// rule decides it. The operation is written into the receipt's reasons
// (operation:<resource>) either way. A request a person approved as a URL
// is not asked again: they saw the body. MCP bodies are the MCP gate's.

const (
	actionGraphQL = "graphql.operation"
	actionAWS     = "aws.action"
	actionJSONRPC = "jsonrpc.call"
	// operationNote is the receipt reason naming the operation a gate read.
	operationNote = "operation:"
	// maxOperationPreview bounds the operation text shown to a person.
	maxOperationPreview = 600
	kindRead            = "read"
	kindWrite           = "write"
	opQuery             = "query"
	formContentType     = "application/x-www-form-urlencoded"
	graphqlContentType  = "application/graphql"
	errActionDenied     = "action denied"
)

// SetAPIGate turns the body-aware gates on or off. Off is the zero value
// (what a Server starts with); the binaries turn it on unless api_gate is
// false in proxy.json.
func (s *Server) SetAPIGate(on bool) { s.apiGate = on }

// apiOperation is what a gate read in a body.
type apiOperation struct {
	action   string // the action type asked about
	resource string
	read     bool // passes without a question
	preview  map[string]string
	why      string
	// refuse names why the request may not go out at all (an encoded body
	// the gate cannot read, a JSON-RPC batch), with the status to answer.
	refuse string
	status int
}

// apiOperationOf reads the operation in an allowed request's body, nil
// when there is none the gates know.
func (s *Server) apiOperationOf(r *http.Request, hb *heldBody, br *bodyRead) *apiOperation {
	if !s.apiGate || hb == nil || hb.size == 0 || r.Method != http.MethodPost || s.isModelHost(r.URL.Hostname()) {
		return nil
	}
	if br != nil && br.mcp != nil {
		return nil // the MCP gate's
	}
	host := hostForResource(r)
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	awsHost := isAWSHost(host)
	target := r.Header.Get("X-Amz-Target")
	graphqlCT := ct == graphqlContentType || ct == graphqlContentType+"+json" || ct == "application/graphql-response+json"
	jsonCT := jsonContentType(r.Header) || graphqlCT
	formCT := ct == formContentType
	data, ok := s.readableBody(r, hb)
	if !ok {
		// An encoding the gate cannot read. Where an operation could be
		// inside (an AWS call, a GraphQL or JSON body), the request is
		// refused: what a server would decode and act on must be checked.
		if target != "" || awsHost || jsonCT || graphqlCT {
			return &apiOperation{refuse: "encoded_body_not_checked", status: http.StatusUnsupportedMediaType}
		}
		return nil
	}
	if target != "" || (awsHost && formCT) {
		return awsOperation(host, target, ct, data)
	}
	if graphqlCT && ct == graphqlContentType {
		return graphqlOperation(host, r.URL.Path, string(data), "", nil)
	}
	if !jsonCT && !(len(data) > 0 && data[0] == '{') && !(len(data) > 0 && data[0] == '[') {
		return nil
	}
	if op := jsonrpcOperation(host, r.URL.Path, data); op != nil {
		return op
	}
	var gq struct {
		Query         string          `json:"query"`
		OperationName string          `json:"operationName"`
		Variables     json.RawMessage `json:"variables"`
	}
	if json.Unmarshal(data, &gq) == nil && gq.Query != "" {
		return graphqlOperation(host, r.URL.Path, gq.Query, gq.OperationName, gq.Variables)
	}
	return nil
}

// readableBody returns the held body as the server would read it: plain,
// or gzip decoded. false for an encoding the gate does not decode.
func (s *Server) readableBody(r *http.Request, hb *heldBody) ([]byte, bool) {
	data, err := io.ReadAll(hb.reader())
	if err != nil {
		return nil, false
	}
	encs := contentEncodings(r.Header.Values("Content-Encoding"))
	switch {
	case len(encs) == 0:
		return data, true
	case len(encs) == 1 && (encs[0] == encGzip || encs[0] == "x-gzip"):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		out, err := io.ReadAll(io.LimitReader(zr, hb.size*64+1<<20))
		if err != nil {
			return nil, false
		}
		return out, true
	}
	return nil, false
}

// hostForResource is the host as a gate's resource names it: normalised,
// with the port when it is not the scheme's default.
func hostForResource(r *http.Request) string {
	host := normalizeHost(r.URL.Hostname())
	if p := r.URL.Port(); p != "" && p != "443" && p != "80" {
		host += ":" + p
	}
	return host
}

// --- AWS ------------------------------------------------------------------

func isAWSHost(host string) bool {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return strings.HasSuffix(h, ".amazonaws.com") || strings.HasSuffix(h, ".amazonaws.com.cn")
}

// awsReadPrefixes are the action names that read. Everything else (Create,
// Delete, Put, Update, Run, Terminate, Invoke, Assume, Decrypt, Send, ...)
// is asked about.
var awsReadPrefixes = []string{
	"Describe", "List", "Get", "Head", "Lookup", "Search", "Query", "Scan", "BatchGet",
	"Select", "Check", "Validate", "Estimate", "View", "Verify", "Preview", "Simulate",
	"Discover", "Resolve", "Is", "Count",
}

// awsSensitiveReads read a secret, a credential or a password: asked about
// although their name says Get.
var awsSensitiveReads = map[string]bool{
	"GetSecretValue": true, "BatchGetSecretValue": true, "GetParameter": true, "GetParameters": true,
	"GetParametersByPath": true, "GetFederationToken": true, "GetSessionToken": true,
	"GetAuthorizationToken": true, "GetPasswordData": true, "GetCredentialsForIdentity": true,
	"GetOpenIdToken": true, "GetClusterCredentials": true,
}

func awsIsRead(action string) bool {
	if awsSensitiveReads[action] {
		return false
	}
	for _, p := range awsReadPrefixes {
		if strings.HasPrefix(action, p) && (len(action) == len(p) || action[len(p)] >= 'A' && action[len(p)] <= 'Z') {
			return true
		}
	}
	return false
}

// awsOperation reads the action of an AWS JSON API call (X-Amz-Target:
// Service_Version.Action) or Query API call (a form body with Action=).
func awsOperation(host, target, ct string, data []byte) *apiOperation {
	service := strings.ToLower(host)
	if i := strings.IndexByte(service, '.'); i >= 0 {
		service = service[:i]
	}
	action := ""
	if target != "" {
		action = target
		if i := strings.LastIndexByte(target, '.'); i >= 0 {
			action = target[i+1:]
			if !isAWSHost(host) {
				service = strings.ToLower(target[:i])
				if j := strings.IndexByte(service, '_'); j >= 0 {
					service = service[:j]
				}
			}
		}
	} else if ct == formContentType {
		if len(data) > 64<<10 {
			return nil
		}
		vals, err := url.ParseQuery(string(data))
		if err != nil {
			return nil
		}
		action = vals.Get("Action")
	}
	if action == "" || !isName(action) {
		return nil
	}
	read := awsIsRead(action)
	kind := kindWrite
	if read {
		kind = kindRead
	}
	op := &apiOperation{
		action:   actionAWS,
		resource: "aws:" + service + ":" + action,
		read:     read,
		why:      "names an AWS action in its body or header",
		preview: map[string]string{
			"aws_action":     service + " " + action,
			"operation_kind": kind,
		},
	}
	return op
}

// --- JSON-RPC -------------------------------------------------------------

// rpcReadPrefixes are what a method name starts with, after its namespace
// (eth_, net_, web3_, Service.), when it reads.
var rpcReadPrefixes = []string{
	"get", "list", "read", "describe", "query", "fetch", "search", "find", "count", "exists", "has",
	"is", "status", "ping", "health", "version", "info", "call", "estimate", "blocknumber", "chainid",
	"gasprice", "feehistory", "syncing", "accounts", "subscribe", "clientversion", "peercount",
	"listening", "logs", "show", "lookup", "check", "validate", "simulate", "preview",
}

func rpcIsRead(method string) bool {
	m := strings.ToLower(method)
	if i := strings.IndexAny(m, "_./:"); i > 0 && i < len(m)-1 {
		m = m[i+1:]
	}
	for _, p := range rpcReadPrefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// jsonrpcOperation reads the method of a JSON-RPC call: an object with a
// "jsonrpc" member, or with "method" and "id" or "params". A batch (an
// array) is refused: one request, one call to decide.
func jsonrpcOperation(host, path string, data []byte) *apiOperation {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(trimmed, &arr) != nil || len(arr) == 0 {
			return nil
		}
		for _, el := range arr {
			var m struct {
				JSONRPC string `json:"jsonrpc"`
				Method  string `json:"method"`
			}
			if json.Unmarshal(el, &m) == nil && m.Method != "" && m.JSONRPC != "" {
				return &apiOperation{refuse: "jsonrpc_batch", status: http.StatusBadRequest}
			}
		}
		return nil
	}
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(trimmed, &m) != nil || m.Method == "" {
		return nil
	}
	if m.JSONRPC == "" && m.ID == nil && m.Params == nil {
		return nil
	}
	if mcp.IsMethod(m.Method) {
		return nil // the MCP gate's, when it is on; never a generic question
	}
	read := rpcIsRead(m.Method)
	kind := kindWrite
	if read {
		kind = kindRead
	}
	op := &apiOperation{
		action:   actionJSONRPC,
		resource: "jsonrpc:" + host + path + "/" + mcp.EscapeName(m.Method),
		read:     read,
		why:      "names a JSON-RPC method",
		preview: map[string]string{
			"jsonrpc_method": truncate(m.Method, 120),
			"operation_kind": kind,
		},
	}
	if len(m.Params) > 0 {
		op.preview["params"] = truncate(redactPreview(string(m.Params)), maxOperationPreview)
	}
	return op
}

// --- GraphQL --------------------------------------------------------------

type graphqlOp struct {
	kind  string // query | mutation | subscription
	name  string // the operation's name, "" when anonymous
	field string // the first top-level field
}

// graphqlOperation reads which operation a GraphQL request runs: the one
// operationName selects, else the document's first (an anonymous
// selection set is a query). nil when the document holds no operation.
func graphqlOperation(host, path, document, operationName string, variables json.RawMessage) *apiOperation {
	ops := graphqlOperations(document)
	if len(ops) == 0 {
		return nil
	}
	chosen := ops[0]
	if operationName != "" {
		for _, o := range ops {
			if o.name == operationName {
				chosen = o
				break
			}
		}
	}
	name := chosen.name
	if name == "" {
		name = chosen.field
	}
	if name == "" {
		name = "anonymous"
	}
	kind := kindWrite
	if chosen.kind == opQuery {
		kind = kindRead
	}
	op := &apiOperation{
		action:   actionGraphQL,
		resource: "graphql:" + host + path + "/" + chosen.kind + ":" + mcp.EscapeName(name),
		read:     chosen.kind == opQuery,
		why:      "is a GraphQL " + chosen.kind,
		preview: map[string]string{
			"graphql_operation": chosen.kind + " " + name,
			"operation":         truncate(redactPreview(strings.Join(strings.Fields(document), " ")), maxOperationPreview),
			"operation_kind":    kind,
		},
	}
	if len(variables) > 0 && string(variables) != "null" {
		op.preview["variables"] = truncate(redactPreview(string(variables)), maxOperationPreview)
	}
	return op
}

// graphqlOperations lists the operations a document defines, in order.
// A small reader of the GraphQL grammar: comments, strings (block strings
// too), names and punctuators; nesting is tracked so that an operation is
// recognised only at the top level.
func graphqlOperations(doc string) []graphqlOp {
	toks := graphqlTokens(doc)
	var ops []graphqlOp
	depth := 0
	fragment := false // a fragment definition's selection set is coming
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t == "{" || t == "(" || t == "[":
			if depth == 0 && t == "{" {
				if fragment {
					fragment = false
				} else {
					ops = append(ops, graphqlOp{kind: opQuery, field: firstField(toks, i)})
				}
			}
			depth++
		case t == "}" || t == ")" || t == "]":
			if depth > 0 {
				depth--
			}
		case depth == 0 && (t == opQuery || t == "mutation" || t == "subscription"):
			op := graphqlOp{kind: t}
			j := i + 1
			if j < len(toks) && isName(toks[j]) && toks[j] != opQuery && toks[j] != "mutation" && toks[j] != "subscription" && toks[j] != "fragment" {
				op.name = toks[j]
				j++
			}
			// skip variable definitions and directives up to the selection set
			d := 0
		scan:
			for ; j < len(toks); j++ {
				switch {
				case toks[j] == "(" || toks[j] == "[":
					d++
				case toks[j] == ")" || toks[j] == "]":
					d--
				case toks[j] == "{" && d == 0:
					break scan
				}
			}
			if j < len(toks) {
				op.field = firstField(toks, j)
			}
			ops = append(ops, op)
			i = j // the "{" is counted by the next iteration's depth++ ... handled below
			depth++
		case depth == 0 && t == "fragment":
			// fragment Name on Type { ... }: not an operation; its selection
			// set is skipped above.
			fragment = true
		}
	}
	return ops
}

// firstField is the first field name inside the selection set opening at
// toks[open] (an alias "a: field" names the field).
func firstField(toks []string, open int) string {
	for j := open + 1; j < len(toks); j++ {
		t := toks[j]
		if t == "..." || t == "}" {
			return ""
		}
		if isName(t) {
			if j+2 < len(toks) && toks[j+1] == ":" && isName(toks[j+2]) {
				return toks[j+2]
			}
			return t
		}
	}
	return ""
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// graphqlTokens splits a document into names, punctuators and strings
// (returned as a single "\"\"" token so a brace inside one is not seen);
// comments and commas are dropped.
func graphqlTokens(doc string) []string {
	var toks []string
	for i := 0; i < len(doc); {
		c := doc[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == 0xEF && i+2 < len(doc) && doc[i+1] == 0xBB && doc[i+2] == 0xBF:
			i++
		case c == '#':
			for i < len(doc) && doc[i] != '\n' {
				i++
			}
		case c == '"':
			if strings.HasPrefix(doc[i:], `"""`) {
				end := strings.Index(doc[i+3:], `"""`)
				for end >= 0 && end > 0 && doc[i+3+end-1] == '\\' { // an escaped triple quote
					next := strings.Index(doc[i+3+end+3:], `"""`)
					if next < 0 {
						end = -1
						break
					}
					end = end + 3 + next
				}
				if end < 0 {
					i = len(doc)
				} else {
					i += 3 + end + 3
				}
			} else {
				i++
				for i < len(doc) && doc[i] != '"' && doc[i] != '\n' {
					if doc[i] == '\\' {
						i++
					}
					i++
				}
				i++
			}
			toks = append(toks, `""`)
		case c == '.' && strings.HasPrefix(doc[i:], "..."):
			toks = append(toks, "...")
			i += 3
		case strings.IndexByte("{}()[]:@$!=|&", c) >= 0:
			toks = append(toks, string(c))
			i++
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i + 1
			for j < len(doc) && (doc[j] == '_' || doc[j] >= 'a' && doc[j] <= 'z' || doc[j] >= 'A' && doc[j] <= 'Z' || doc[j] >= '0' && doc[j] <= '9') {
				j++
			}
			toks = append(toks, doc[i:j])
			i = j
		case c == '-' || c >= '0' && c <= '9':
			j := i + 1
			for j < len(doc) && (doc[j] >= '0' && doc[j] <= '9' || doc[j] == '.' || doc[j] == 'e' || doc[j] == 'E' || doc[j] == '+' || doc[j] == '-') {
				j++
			}
			toks = append(toks, "0")
			i = j
		default:
			i++
		}
	}
	return toks
}

// apiRefusalText is the error a gate's refusal answers with.
func apiRefusalText(reason string) string {
	switch reason {
	case "encoded_body_not_checked":
		return "the request body is encoded in a form Ovara does not read, and could carry an operation to decide; send it plain or gzip"
	case "jsonrpc_batch":
		return "a JSON-RPC batch is not decided as one: send one call per request"
	}
	return errActionDenied
}
