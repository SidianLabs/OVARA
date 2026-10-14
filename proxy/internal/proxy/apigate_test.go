package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The body-aware gates: once a URL rule allows a POST, the operation in its
// body is named in the receipt, a read passes and a write is a question.

func apiGateServer(t *testing.T) (*Server, *actionGateway, string, *recorder) {
	t.Helper()
	srv, ag, chainFile := newActionServer(t, "allow")
	srv.SetAPIGate(true)
	up := newRecorder(t)
	return srv, ag, chainFile, up
}

func postJSON(srv *Server, url, body string) int {
	return send(srv, http.MethodPost, url, "application/json", strings.NewReader(body), nil).Code
}

func TestAPIGate_GraphQLQueryPassesAndIsNamed(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	host := mustHostPort(t, up.URL)
	code := postJSON(srv, up.URL+"/graphql", `{"query":"query Viewer { viewer { login } }"}`)
	if code != 200 || up.hits.Load() != 1 {
		t.Fatalf("a query must pass: %d, hits %d", code, up.hits.Load())
	}
	if n := len(ag.of(actionGraphQL)); n != 0 {
		t.Fatalf("a query was asked about %d time(s)", n)
	}
	r := lastReceiptOf(t, chainFile)
	if !containsString(r.Reasons, "operation:graphql:"+host+"/graphql/query:Viewer") {
		t.Fatalf("receipt does not name the operation: %v", r.Reasons)
	}
}

func TestAPIGate_GraphQLMutationIsAQuestion(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionGraphQL, "deny")
	secret := "ghp_" + strings.Repeat("a", 36) // credential-shaped, built here so no token sits in the source
	body := `{"query":"mutation CreateIssue($input: CreateIssueInput!) { createIssue(input: $input) { issue { id } } }","variables":{"input":{"title":"x","token":"` + secret + `"}}}`
	code := postJSON(srv, up.URL+"/graphql", body)
	if code != 403 || up.hits.Load() != 0 {
		t.Fatalf("a denied mutation must not go out: %d, hits %d", code, up.hits.Load())
	}
	checks := ag.of(actionGraphQL)
	if len(checks) != 1 || checks[0].Resource != "graphql:"+host+"/graphql/mutation:CreateIssue" {
		t.Fatalf("asked %+v", checks)
	}
	ctx := checks[0].Context
	if ctx["graphql_operation"] != "mutation CreateIssue" || ctx["operation_kind"] != kindWrite || !strings.Contains(ctx["operation"], "createIssue(input: $input)") {
		t.Fatalf("context: %v", ctx)
	}
	if strings.Contains(ctx["variables"], secret) || ctx["body_sha256"] == "" {
		t.Fatalf("variables not redacted or hash missing: %v", ctx)
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != gwDeny || !containsString(r.Reasons, "operation:graphql:"+host+"/graphql/mutation:CreateIssue") {
		t.Fatalf("receipt: %+v", r)
	}

	ag.setDecision(actionGraphQL, "allow")
	if code := postJSON(srv, up.URL+"/graphql", body); code != 200 || up.hits.Load() != 1 {
		t.Fatalf("an allowed mutation must go out: %d, hits %d", code, up.hits.Load())
	}
}

func TestAPIGate_GraphQLOperationNameSelectsAmongSeveral(t *testing.T) {
	srv, ag, _, up := apiGateServer(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionGraphQL, "deny")
	doc := `query A { a } mutation B { b } # trailing comment with a { brace
	fragment F on T { f }`
	body, _ := json.Marshal(map[string]any{"query": doc, "operationName": "B"})
	if code := postJSON(srv, up.URL+"/api", string(body)); code != 403 {
		t.Fatalf("the selected mutation must be asked about: %d", code)
	}
	if c := ag.of(actionGraphQL); len(c) != 1 || c[0].Resource != "graphql:"+host+"/api/mutation:B" {
		t.Fatalf("asked %+v", c)
	}
	// With A selected, nothing is asked.
	body, _ = json.Marshal(map[string]any{"query": doc, "operationName": "A"})
	if code := postJSON(srv, up.URL+"/api", string(body)); code != 200 || len(ag.of(actionGraphQL)) != 1 {
		t.Fatalf("the selected query must pass: %d", code)
	}
}

func TestAPIGate_GraphQLShorthandAndRawDocument(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionGraphQL, "deny")
	// An anonymous selection set is a query named by its first field; a
	// string holding a brace does not confuse the reader.
	if code := postJSON(srv, up.URL+"/graphql", `{"query":"{ me: viewer(arg: \"}{\") { login } }"}`); code != 200 {
		t.Fatalf("shorthand query: %d", code)
	}
	if !containsString(lastReceiptOf(t, chainFile).Reasons, "operation:graphql:"+host+"/graphql/query:viewer") {
		t.Fatalf("receipt: %v", lastReceiptOf(t, chainFile).Reasons)
	}
	// application/graphql carries the document itself.
	code := send(srv, http.MethodPost, up.URL+"/graphql", "application/graphql", strings.NewReader(`mutation { deleteRepo(id: 1) }`), nil).Code
	if code != 403 || len(ag.of(actionGraphQL)) != 1 || ag.of(actionGraphQL)[0].Resource != "graphql:"+host+"/graphql/mutation:deleteRepo" {
		t.Fatalf("raw document mutation: %d %+v", code, ag.of(actionGraphQL))
	}
	// A JSON body whose "query" is an object (a search API) is not GraphQL.
	if code := postJSON(srv, up.URL+"/search", `{"query":{"match":{"x":1}}}`); code != 200 || len(ag.of(actionGraphQL)) != 1 {
		t.Fatalf("not GraphQL: %d", code)
	}
}

func TestAPIGate_AWSTargetHeader(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	ag.setDecision(actionAWS, "deny")
	hdr := map[string]string{"X-Amz-Target": "DynamoDB_20120810.DeleteTable"}
	code := send(srv, http.MethodPost, up.URL+"/", "application/x-amz-json-1.0", strings.NewReader(`{"TableName":"users"}`), hdr).Code
	if code != 403 || up.hits.Load() != 0 {
		t.Fatalf("a denied AWS write must not go out: %d, hits %d", code, up.hits.Load())
	}
	if c := ag.of(actionAWS); len(c) != 1 || c[0].Resource != "aws:dynamodb:DeleteTable" || c[0].Context["aws_action"] != "dynamodb DeleteTable" {
		t.Fatalf("asked %+v", c)
	}
	hdr["X-Amz-Target"] = "DynamoDB_20120810.DescribeTable"
	code = send(srv, http.MethodPost, up.URL+"/", "application/x-amz-json-1.0", strings.NewReader(`{"TableName":"users"}`), hdr).Code
	if code != 200 || len(ag.of(actionAWS)) != 1 {
		t.Fatalf("a read must pass unasked: %d", code)
	}
	if !containsString(lastReceiptOf(t, chainFile).Reasons, "operation:aws:dynamodb:DescribeTable") {
		t.Fatalf("receipt: %v", lastReceiptOf(t, chainFile).Reasons)
	}
	// A read of a secret is not a read.
	hdr["X-Amz-Target"] = "secretsmanager.GetSecretValue"
	if code := send(srv, http.MethodPost, up.URL+"/", "application/x-amz-json-1.1", strings.NewReader(`{"SecretId":"prod/db"}`), hdr).Code; code != 403 {
		t.Fatalf("GetSecretValue must be asked about: %d", code)
	}
}

func TestAPIGate_AWSQueryAPI(t *testing.T) {
	// The Query API names the action in a form body, on an AWS host.
	form := url.Values{"Action": {"TerminateInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {"i-1"}}
	op := awsOperation("ec2.us-east-1.amazonaws.com", "", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if op == nil || op.resource != "aws:ec2:TerminateInstances" || op.read {
		t.Fatalf("TerminateInstances: %+v", op)
	}
	form.Set("Action", "DescribeInstances")
	if op := awsOperation("ec2.us-east-1.amazonaws.com", "", "application/x-www-form-urlencoded", []byte(form.Encode())); op == nil || !op.read {
		t.Fatalf("DescribeInstances: %+v", op)
	}
	if op := awsOperation("sts.amazonaws.com", "", "application/x-www-form-urlencoded", []byte("Action=GetSessionToken&Version=2011-06-15")); op == nil || op.read {
		t.Fatalf("GetSessionToken mints a credential: %+v", op)
	}
	for action, read := range map[string]bool{"ListBuckets": true, "GetItem": true, "Getaway": false, "PutItem": false, "AssumeRole": false, "Decrypt": false, "IsVpcPeered": true} {
		if awsIsRead(action) != read {
			t.Errorf("awsIsRead(%s) = %v", action, !read)
		}
	}
	if !isAWSHost("ec2.us-east-1.amazonaws.com") || !isAWSHost("sts.cn-north-1.amazonaws.com.cn") || isAWSHost("amazonaws.com.evil.example") {
		t.Error("isAWSHost")
	}
}

func TestAPIGate_JSONRPC(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionJSONRPC, "deny")
	write := `{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{"to":"0xabc","value":"0x1"}]}`
	if code := postJSON(srv, up.URL+"/rpc", write); code != 403 || up.hits.Load() != 0 {
		t.Fatalf("a denied method must not go out: %d, hits %d", code, up.hits.Load())
	}
	c := ag.of(actionJSONRPC)
	if len(c) != 1 || c[0].Resource != "jsonrpc:"+host+"/rpc/eth_sendTransaction" || c[0].Context["jsonrpc_method"] != "eth_sendTransaction" || !strings.Contains(c[0].Context["params"], "0xabc") {
		t.Fatalf("asked %+v", c)
	}
	read := `{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["0xabc","latest"]}`
	if code := postJSON(srv, up.URL+"/rpc", read); code != 200 || len(ag.of(actionJSONRPC)) != 1 {
		t.Fatalf("a read method must pass unasked: %d", code)
	}
	if !containsString(lastReceiptOf(t, chainFile).Reasons, "operation:jsonrpc:"+host+"/rpc/eth_getBalance") {
		t.Fatalf("receipt: %v", lastReceiptOf(t, chainFile).Reasons)
	}
	// A batch is refused whole, before anything goes out.
	batch := `[{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[]},{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction","params":[]}]`
	if code := postJSON(srv, up.URL+"/rpc", batch); code != 400 || up.hits.Load() != 1 {
		t.Fatalf("batch: %d, hits %d", code, up.hits.Load())
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "jsonrpc_batch") {
		t.Fatalf("batch receipt: %+v", r)
	}
	// An MCP method is never a generic question: the MCP gate decides it
	// (here it refuses an unpinned tool).
	if code := postJSON(srv, up.URL+"/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x"}}`); len(ag.of(actionJSONRPC)) != 1 {
		t.Fatalf("MCP method asked about by the generic gate (%d)", code)
	}
	// Plain JSON that is not a call is not asked about.
	if code := postJSON(srv, up.URL+"/items", `{"method":"card","amount":5}`); code != 200 || len(ag.of(actionJSONRPC)) != 1 {
		t.Fatalf("plain JSON: %d", code)
	}
	for m, read := range map[string]bool{"eth_call": true, "net_version": true, "Filesystem.Read": true, "getUser": true, "eth_sendRawTransaction": false, "deploy": false, "admin_addPeer": false, "personal_sign": false} {
		if rpcIsRead(m) != read {
			t.Errorf("rpcIsRead(%s) = %v", m, !read)
		}
	}
}

func TestAPIGate_EncodedBodies(t *testing.T) {
	srv, ag, chainFile, up := apiGateServer(t)
	ag.setDecision(actionGraphQL, "deny")
	// gzip is decoded: the mutation inside is seen.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"query":"mutation { drop }"}`))
	_ = zw.Close()
	code := send(srv, http.MethodPost, up.URL+"/graphql", "application/json", bytes.NewReader(buf.Bytes()), map[string]string{"Content-Encoding": "gzip"}).Code
	if code != 403 || len(ag.of(actionGraphQL)) != 1 {
		t.Fatalf("gzip mutation: %d, asked %d", code, len(ag.of(actionGraphQL)))
	}
	// An encoding no gate reads, on a JSON body: refused, not sent (the MCP
	// gate refuses it first when it is on, this gate when it is not).
	code = send(srv, http.MethodPost, up.URL+"/graphql", "application/json", strings.NewReader("xxxx"), map[string]string{"Content-Encoding": "br"}).Code
	if code < 400 || code >= 500 || up.hits.Load() != 0 {
		t.Fatalf("unreadable encoding: %d, hits %d", code, up.hits.Load())
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny {
		t.Fatalf("receipt: %+v", r)
	}
	if err := srv.SetMCPGate(false, ""); err != nil {
		t.Fatal(err)
	}
	code = send(srv, http.MethodPost, up.URL+"/graphql", "application/json", strings.NewReader("xxxx"), map[string]string{"Content-Encoding": "br"}).Code
	if code != 415 || up.hits.Load() != 0 {
		t.Fatalf("unreadable encoding with the MCP gate off: %d, hits %d", code, up.hits.Load())
	}
	if r := lastReceiptOf(t, chainFile); !containsString(r.Reasons, "encoded_body_not_checked") {
		t.Fatalf("receipt: %+v", r)
	}
	// The same encoding on a body no gate would read goes out as before.
	code = send(srv, http.MethodPost, up.URL+"/upload", "application/octet-stream", strings.NewReader("xxxx"), map[string]string{"Content-Encoding": "br"}).Code
	if code != 200 {
		t.Fatalf("octet-stream with br: %d", code)
	}
}

func TestAPIGate_OffAsksNothing(t *testing.T) {
	srv, ag, _, up := apiGateServer(t)
	srv.SetAPIGate(false)
	ag.setDecision(actionGraphQL, "deny")
	if code := postJSON(srv, up.URL+"/graphql", `{"query":"mutation { drop }"}`); code != 200 || len(ag.of(actionGraphQL)) != 0 {
		t.Fatalf("gate off: %d", code)
	}
}

func TestAPIGate_GraphQLReader(t *testing.T) {
	cases := map[string][]graphqlOp{
		`{ viewer { login } }`: {{kind: "query", field: "viewer"}},
		`query Q($id: ID = "}") @live { node(id: $id) { ...F } } fragment F on N { id }`: {{kind: "query", name: "Q", field: "node"}},
		`mutation { a: addStar(input: {id: "{"}) { b } }`:                                {{kind: "mutation", field: "addStar"}},
		"subscription S {\n  # a comment { with braces\n  events { id }\n}":              {{kind: "subscription", name: "S", field: "events"}},
		`"""a block string { with a brace """ query { x }`:                               {{kind: "query", field: "x"}},
		`fragment only on T { x }`:                                                       nil,
		`not graphql at all`:                                                             nil,
	}
	for doc, want := range cases {
		got := graphqlOperations(doc)
		if len(got) != len(want) {
			t.Errorf("%q: got %+v, want %+v", doc, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q: got %+v, want %+v", doc, got[i], want[i])
			}
		}
	}
}
