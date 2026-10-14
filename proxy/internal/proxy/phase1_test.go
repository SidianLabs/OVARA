package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

// gwCheck is one /v1/runtime/check the proxy made.
type gwCheck struct {
	ActionType string
	Resource   string
	Context    map[string]string
}

// actionGateway answers http.request checks with urlDecision and every other
// action type from decisions (default "allow"); the approvals it opens
// report status.
type actionGateway struct {
	urlDecision atomic.Value // string
	matchedRule atomic.Value // string: the rule named in http.request decisions
	status      atomic.Value // string
	creates     atomic.Int32
	mu          sync.Mutex
	decisions   map[string]string
	checks      []gwCheck
}

func (g *actionGateway) setDecision(action, d string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.decisions[action] = d
}

func (g *actionGateway) all() []gwCheck {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]gwCheck(nil), g.checks...)
}

func (g *actionGateway) of(action string) []gwCheck {
	var out []gwCheck
	for _, c := range g.all() {
		if c.ActionType == action {
			out = append(out, c)
		}
	}
	return out
}

func newActionServer(t *testing.T, urlDecision string) (*Server, *actionGateway, string) {
	t.Helper()
	ag := &actionGateway{decisions: map[string]string{}}
	ag.urlDecision.Store(urlDecision)
	ag.status.Store("pending")
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/runtime/check":
			var body struct {
				ActionType string `json:"action_type"`
				Resource   string `json:"resource"`
				Metadata   struct {
					ProxyContext map[string]string `json:"proxy_context"`
				} `json:"metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ag.mu.Lock()
			ag.checks = append(ag.checks, gwCheck{body.ActionType, body.Resource, body.Metadata.ProxyContext})
			dec, ok := ag.decisions[body.ActionType]
			ag.mu.Unlock()
			if body.ActionType == "http.request" {
				dec = ag.urlDecision.Load().(string)
			} else if !ok {
				dec = "allow"
			}
			resp := map[string]any{"decision": dec, "decision_id": "d1"}
			if mr, _ := ag.matchedRule.Load().(string); mr != "" && body.ActionType == "http.request" {
				resp["matched_rule"] = mr
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.URL.Path == "/v1/approval/create":
			n := ag.creates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": fmt.Sprintf("apr_%d", n)})
		case strings.HasPrefix(r.URL.Path, "/v1/approval/apr_") && strings.HasSuffix(r.URL.Path, "/claim"):
			// single use is the real gateway's job; here every claim succeeds
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "claimed": true})
		case strings.HasPrefix(r.URL.Path, "/v1/approval/apr_"):
			_ = json.NewEncoder(w).Encode(map[string]string{"status": ag.status.Load().(string)})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gw.Close)
	dir := t.TempDir()
	c, err := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	chainFile := filepath.Join(dir, "receipts.jsonl")
	chain, err := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	if chain != nil {
		t.Cleanup(func() { _ = chain.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	srv := New(c, gateway.New(gw.URL, "", "test"), nil, chain, false)
	srv.SetPublicEgressOnly(false)
	srv.SetConnectPort443Only(false)
	srv.SetEscalateWindow(2*time.Second, 10*time.Millisecond)
	return srv, ag, chainFile
}

// recorder is an upstream that keeps what it was sent.
type recorder struct {
	*httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	body []byte
}

func newRecorder(t *testing.T) *recorder {
	rc := &recorder{}
	rc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.body = b
		rc.mu.Unlock()
		rc.hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(rc.Close)
	return rc
}

func (rc *recorder) got() []byte {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.body
}

func send(srv *Server, method, url, ctype string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	r, _ := http.NewRequest(method, url, body)
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)
	return rec
}

func lastReceiptOf(t *testing.T, chainFile string) receipts.Receipt {
	t.Helper()
	data, err := readLastLine(chainFile)
	if err != nil {
		t.Fatal(err)
	}
	var r receipts.Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A-01: the person is asked only once the whole body is in, the approval
// context names its hash, and exactly those bytes go upstream. Before, the
// question went out after a 400-byte peek and the rest of the body was read
// from the agent after the answer.
func TestApprovalCoversTheExactBodySent(t *testing.T) {
	srv, ag, _ := newActionServer(t, "escalate")
	up := newRecorder(t)
	ps := httptest.NewServer(srv)
	defer ps.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ps.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	first, rest := strings.Repeat("A", 400), strings.Repeat("Z", 400)
	fmt.Fprintf(conn, "POST %s/upload HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: 800\r\n\r\n%s",
		up.URL, strings.TrimPrefix(up.URL, "http://"), first)
	time.Sleep(200 * time.Millisecond)
	if n := len(ag.all()); n != 0 {
		t.Fatalf("the gateway was asked (%d checks) before the body was complete", n)
	}
	_, _ = io.WriteString(conn, rest)
	go func() {
		for len(ag.all()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		ag.status.Store("approved")
	}()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || string(up.got()) != first+rest {
		t.Fatalf("status %d, upstream got %q", resp.StatusCode, up.got())
	}
	sum := sha256.Sum256([]byte(first + rest))
	if got := ag.all()[0].Context["body_sha256"]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("approval context body_sha256 = %q, want the hash of the bytes sent", got)
	}
}

// A-01: a body too large to hold for review is refused and receipted, never
// forwarded unseen, whether its length is declared or streamed.
func TestBodyTooLargeToReviewIsRefused(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		srv, ag, chainFile := newActionServer(t, "allow")
		up := newRecorder(t)
		r, _ := http.NewRequest("POST", up.URL+"/x", bytes.NewReader(make([]byte, defaultMaxHeldBody+1)))
		if streamed {
			r.ContentLength = -1
			r.Body = io.NopCloser(io.MultiReader(strings.NewReader("a"), bytes.NewReader(make([]byte, defaultMaxHeldBody))))
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "body_too_large_to_review") {
			t.Fatalf("streamed=%v: want 413 body_too_large_to_review, got %d %s", streamed, rec.Code, rec.Body)
		}
		if up.hits.Load() != 0 || len(ag.all()) != 0 {
			t.Fatalf("streamed=%v: upstream hits=%d gateway checks=%d", streamed, up.hits.Load(), len(ag.all()))
		}
		if rc := lastReceiptOf(t, chainFile); rc.Decision != gwDeny || rc.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("receipt %+v", rc)
		}
	}
	// A body at the limit still goes through, whole.
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	if rec := send(srv, "POST", up.URL+"/x", "application/octet-stream", bytes.NewReader(make([]byte, defaultMaxHeldBody)), nil); rec.Code != 200 || len(up.got()) != defaultMaxHeldBody {
		t.Fatalf("body at the limit: %d, upstream got %d bytes", rec.Code, len(up.got()))
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = io.WriteString(zw, s)
	zw.Close()
	return b.Bytes()
}

// A-05: a body the person cannot see is said to be unseen, and why; a gzip
// text body is decompressed for the preview.
func TestUnseenBodiesAreNamed(t *testing.T) {
	cases := []struct {
		name, ctype, enc string
		body             []byte
		note, preview    string
	}{
		{"binary", "application/octet-stream", "", []byte{1, 2, 3, 4, 5}, "contents not shown: 5 bytes of application/octet-stream", ""},
		{"no type", "", "", []byte(`{"a":1}`), "contents not shown: 7 bytes of undeclared type", ""},
		{"multipart", "multipart/form-data; boundary=b", "", []byte("--b\r\n\r\nx\r\n--b--"), "bytes of multipart/form-data", ""},
		{"brotli", "application/json", "br", []byte("xxxx"), "encoded br", ""},
		{"gzip json", "application/json", "gzip", gz(`{"msg":"hello from gzip"}`), "gzip", `"msg":"hello from gzip"`},
		{"long text", "text/plain", "", []byte(strings.Repeat("hello world ", 500)), "showing first 400 of 6000 bytes", "hello world"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, ag, _ := newActionServer(t, "deny")
			hdr := map[string]string{}
			if c.enc != "" {
				hdr["Content-Encoding"] = c.enc
			}
			send(srv, "POST", "http://x.example/up", c.ctype, bytes.NewReader(c.body), hdr)
			ctx := ag.all()[0].Context
			if !strings.Contains(ctx["body_note"], c.note) {
				t.Errorf("body_note = %q, want it to contain %q (context %v)", ctx["body_note"], c.note, ctx)
			}
			if c.preview == "" && ctx["body_preview"] != "" {
				t.Errorf("unexpected preview %q", ctx["body_preview"])
			}
			if !strings.Contains(ctx["body_preview"], c.preview) {
				t.Errorf("body_preview = %q, want %q", ctx["body_preview"], c.preview)
			}
		})
	}
}

// A-16: the person sees the request's own headers, credentials masked, and
// the whole context stays within the gateway's 12 keys.
func TestApproverSeesRequestHeaders(t *testing.T) {
	srv, ag, _ := newActionServer(t, "deny")
	send(srv, "POST", "http://x.example/up?q=1&token=ghp_abcdefghijklmnopqrstuvwxyz0123456789", "application/json",
		bytes.NewReader(gz(`{"password":"hunter2hunter2"}`)), map[string]string{
			"Content-Encoding":       "gzip",
			"X-Exfil":                "some data",
			"Authorization":          "Bearer abcdefghijklmnopqrstuvwxyz",
			"User-Agent":             "curl/8",
			"X-HTTP-Method-Override": "DELETE",
		})
	ctx := ag.all()[0].Context
	h := ctx["headers"]
	if !strings.Contains(h, "X-Exfil: some data") || !strings.Contains(h, "Authorization: [⚠ credential") {
		t.Fatalf("headers = %q", h)
	}
	if strings.Contains(h, "abcdefghij") || strings.Contains(h, "curl") || strings.Contains(h, "Override") {
		t.Fatalf("headers show a credential, a standard header or a not-forwarded one: %q", h)
	}
	if len(ctx) > 12 {
		t.Fatalf("context has %d keys; the gateway keeps 12: %v", len(ctx), ctx)
	}
}

// EGRESS-02: a read's path and headers share one budget with its query.
func TestReadBudgetCoversPathAndHeaders(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	cases := map[string]func() *httptest.ResponseRecorder{
		"long path": func() *httptest.ResponseRecorder {
			return send(srv, "GET", up.URL+"/"+strings.Repeat("p", 1900)+"?q="+strings.Repeat("q", 300), "", nil, nil)
		},
		"big custom header": func() *httptest.ResponseRecorder {
			return send(srv, "GET", up.URL+"/x", "", nil, map[string]string{"X-Exfil": strings.Repeat("A", 3000)})
		},
		"stuffed user agent": func() *httptest.ResponseRecorder {
			return send(srv, "GET", up.URL+"/x", "", nil, map[string]string{"User-Agent": strings.Repeat("A", 3000)})
		},
	}
	for name, run := range cases {
		if rec := run(); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "read_request_too_large") {
			t.Errorf("%s: want 403 read_request_too_large, got %d %s", name, rec.Code, rec.Body)
		}
	}
	if up.hits.Load() != 0 {
		t.Fatalf("upstream reached %d times", up.hits.Load())
	}
	if rec := send(srv, "GET", up.URL+"/x?q=short", "", nil, map[string]string{"User-Agent": "git/2.43", "Git-Protocol": "version=2"}); rec.Code != 200 {
		t.Fatalf("an ordinary read must pass, got %d", rec.Code)
	}
}

// EGRESS-02: inside the TLS tunnel, headers are bounded like on the outer
// listener (64 KiB), not by the 1 MiB default.
func TestTunnelHeadersAreBounded(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer up.Close()
	f := newFixture(t, "allow", nil)
	resp, _ := tunnel(t, f.srv, f.ca, up, map[string]string{"X-Big": strings.Repeat("A", 100<<10)}) //nolint:bodyclose // the helper reads and closes the body
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("want 431, got %d", resp.StatusCode)
	}
}

func uploadPackV0() string {
	return pkt("want "+shaA+" multi_ack_detailed side-band-64k thin-pack ofs-delta agent=git/2.43.0\n") +
		pkt("want "+shaB+"\n") + "0000" + pkt("have "+shaZ+"\n") + pkt("done\n")
}

func uploadPackV2() string {
	return pkt("command=fetch\n") + pkt("agent=git/2.43.0\n") + pkt("object-format=sha1\n") + "0001" +
		pkt("thin-pack\n") + pkt("ofs-delta\n") + pkt("want "+shaA+"\n") + pkt("done\n") + "0000"
}

// EGRESS-03: an allowed POST to git-upload-pack goes through only when it is
// a real fetch negotiation.
func TestUploadPackPostMustBeAGitFetch(t *testing.T) {
	const ct = "application/x-git-upload-pack-request"
	srv, _, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	ok := map[string]func() *httptest.ResponseRecorder{
		"v0": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, strings.NewReader(uploadPackV0()), nil)
		},
		"v2 fetch": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", "Application/X-Git-Upload-Pack-Request", strings.NewReader(uploadPackV2()), nil)
		},
		"v2 ls-refs": func() *httptest.ResponseRecorder {
			body := pkt("command=ls-refs\n") + "0001" + pkt("peel\n") + pkt("symrefs\n") + pkt("ref-prefix refs/heads/\n") + "0000"
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, strings.NewReader(body), nil)
		},
		"gzip": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, bytes.NewReader(gz(uploadPackV0())), map[string]string{"Content-Encoding": "gzip"})
		},
	}
	for name, run := range ok {
		if rec := run(); rec.Code != 200 {
			t.Errorf("%s: a genuine fetch was refused: %d %s", name, rec.Code, rec.Body)
		}
	}
	hits := up.hits.Load()
	bad := map[string]func() *httptest.ResponseRecorder{
		"data body": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, strings.NewReader("AWS_SECRET=abc"), nil)
		},
		"data in a pkt-line": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, strings.NewReader(pkt("want "+shaA+"\n")+pkt("stolen data here\n")), nil)
		},
		"wrong type": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", "application/json", strings.NewReader(uploadPackV0()), nil)
		},
		"not the final segment": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/api/files/git-upload-pack/x", ct, strings.NewReader(uploadPackV0()), nil)
		},
		"encoded slash": func() *httptest.ResponseRecorder {
			return send(srv, "POST", up.URL+"/api/files/exfil%2Fgit-upload-pack", ct, strings.NewReader(uploadPackV0()), nil)
		},
	}
	for name, run := range bad {
		if rec := run(); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not_git_upload_pack") {
			t.Errorf("%s: want 403 not_git_upload_pack, got %d %s", name, rec.Code, rec.Body)
		}
	}
	// Over the size bound: refused before policy is asked.
	big := pkt("want "+shaA+"\n") + strings.Repeat(pkt("have "+shaA+"\n"), defaultMaxUploadPack/49+10)
	if rec := send(srv, "POST", up.URL+"/o/r.git/git-upload-pack", ct, strings.NewReader(big), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized negotiation: want 413, got %d", rec.Code)
	}
	if up.hits.Load() != hits {
		t.Fatalf("a fake upload-pack reached the upstream")
	}
}

// EGRESS-04: a push is recognised whatever its Content-Type spelling or a
// trailing slash, and one whose refs cannot be read carries the
// "git-receive-pack" marker (which policy can match) instead of nothing.
// Policy that allows such a push is not trusted: the refs were never seen.
func TestPushDetectionAndUnparsedPushes(t *testing.T) {
	push := pkt(shaA+" "+shaB+" refs/heads/main\x00report-status\n") + "0000PACK"
	cases := []struct {
		name, path, ctype, body, want string
	}{
		{"canonical", "/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", push, " refs/heads/main"},
		{"type case", "/o/r.git/git-receive-pack", "Application/X-Git-Receive-Pack-Request", push, " refs/heads/main"},
		{"trailing slash", "/o/r.git/git-receive-pack/", "application/x-git-receive-pack-request", push, " refs/heads/main"},
		{"other type", "/o/r.git/git-receive-pack", "application/json", push, " refs/heads/main"},
		{"garbage body", "/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", "not a push", " git-receive-pack"},
		{"no flush", "/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", pkt(shaA + " " + shaB + " refs/heads/main\n"), " git-receive-pack"},
		{"odd ref name", "/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", pkt(shaA+" "+shaB+" refs/heads/a$b\n") + "0000", " git-receive-pack"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, ag, _ := newActionServer(t, "allow")
			up := newRecorder(t)
			rec := send(srv, "POST", up.URL+c.path, c.ctype, strings.NewReader(c.body), nil)
			res := ag.all()[0].Resource
			if !strings.HasSuffix(res, c.path+c.want) {
				t.Fatalf("resource %q, want suffix %q", res, c.path+c.want)
			}
			unparsed := c.want == pushUnparsed
			if unparsed && (rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "git_push_unparsed") || up.hits.Load() != 0) {
				t.Fatalf("allowed unparsed push: %d %s hits=%d", rec.Code, rec.Body, up.hits.Load())
			}
			if !unparsed && rec.Code != 200 {
				t.Fatalf("allowed parsed push: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// EGRESS-04: a push larger than the old 1 MiB peek is held whole, and the
// pushed bytes are exactly what upstream receives.
func TestLargePushIsHeldWhole(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	body := pkt(shaA+" "+shaB+" refs/heads/feature\x00report-status\n") + "0000PACK" + strings.Repeat("x", 9<<20)
	rec := send(srv, "POST", up.URL+"/o/r.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(body), nil)
	if rec.Code != 200 || string(up.got()) != body {
		t.Fatalf("status %d, upstream got %d of %d bytes", rec.Code, len(up.got()), len(body))
	}
	sum := sha256.Sum256([]byte(body))
	if c := ag.all()[0]; !strings.HasSuffix(c.Resource, " refs/heads/feature") || c.Context["body_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("check %q %v", c.Resource, c.Context["body_sha256"])
	}
}

// EGRESS-05: allowed traffic to one host is metered. Past the default
// allowance a person is asked; until then nobody is.
func TestEgressBudgetAsksPastTheDefaultAllowance(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	ag.setDecision("egress.budget", "deny")
	for i := 0; i < defaultBudgetRequests; i++ {
		if rec := send(srv, "GET", up.URL+"/x", "", nil, nil); rec.Code != 200 {
			t.Fatalf("request %d within the budget: %d", i, rec.Code)
		}
	}
	if n := len(ag.of("egress.budget")); n != 0 {
		t.Fatalf("asked %d times within the budget", n)
	}
	rec := send(srv, "GET", up.URL+"/x", "", nil, nil)
	q := ag.of("egress.budget")
	if rec.Code != http.StatusForbidden || len(q) != 1 || q[0].Resource != "budget:127.0.0.1" {
		t.Fatalf("over budget: %d, questions %+v", rec.Code, q)
	}
}

// EGRESS-05: an approval raises the host's allowance for the rest of the
// run, and parallel requests over the budget share one question.
func TestEgressBudgetApprovalDoublesAllowance(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	ag.setDecision("egress.budget", "escalate")
	srv.SetEgressBudget(true, 3, 0)
	for i := 0; i < 3; i++ {
		send(srv, "GET", up.URL+"/x", "", nil, nil)
	}
	var wg sync.WaitGroup
	codes := make([]int, 3)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = send(srv, "GET", up.URL+"/x", "", nil, nil).Code
		}(i)
	}
	time.Sleep(100 * time.Millisecond)
	if up.hits.Load() != 3 {
		t.Fatalf("over-budget requests ran before the answer: hits=%d", up.hits.Load())
	}
	ag.status.Store("approved")
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("codes %v", codes)
		}
	}
	if ag.creates.Load() != 1 {
		t.Fatalf("parallel requests opened %d approvals", ag.creates.Load())
	}
	// 6 used of a doubled allowance of 6: the next one asks again.
	ag.status.Store("denied")
	if rec := send(srv, "GET", up.URL+"/x", "", nil, nil); rec.Code != http.StatusForbidden || ag.creates.Load() != 2 {
		t.Fatalf("past the doubled allowance: %d creates=%d", rec.Code, ag.creates.Load())
	}
}

// EGRESS-05: bytes count too.
func TestEgressBudgetCountsBytes(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	ag.setDecision("egress.budget", "deny")
	srv.SetEgressBudget(true, 1000, 1000)
	if rec := send(srv, "POST", up.URL+"/x", "text/plain", strings.NewReader(strings.Repeat("a", 600)), nil); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := send(srv, "POST", up.URL+"/x", "text/plain", strings.NewReader(strings.Repeat("a", 600)), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("second should exceed 1000 bytes: %d", rec.Code)
	}
}

// EGRESS-06: the resource is bounded for policy and receipts, and a request
// whose resource would be cut is refused rather than decided on a prefix.
func TestLongResourceIsRefusedAndReceiptBounded(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := newRecorder(t)
	rec := send(srv, "POST", up.URL+"/"+strings.Repeat("a", 5000)+"/secret-target", "text/plain", strings.NewReader("x"), nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "resource_too_long") || up.hits.Load() != 0 {
		t.Fatalf("want 403 resource_too_long, got %d %s", rec.Code, rec.Body)
	}
	if len(ag.all()) != 0 {
		t.Fatal("a cut resource was put to policy")
	}
	if rc := lastReceiptOf(t, chainFile); len(rc.URL) > maxResourceBytes+32 || !strings.Contains(rc.URL, "bytes)") || rc.Decision != gwDeny {
		t.Fatalf("receipt URL %d bytes, decision %s", len(rc.URL), rc.Decision)
	}
}

// The config file's limits reach the proxy.
func TestApplyConfigSetsLimits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(p, []byte(`{"gateway_url":"http://x","listen_addr":"127.0.0.1:9443",
		"max_held_body_bytes":10,"max_push_bytes":20,"max_upload_pack_bytes":30,"max_read_request_bytes":40,
		"egress_budget":{"requests_per_minute":5,"bytes_per_minute":50},"model_gate_ask":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, _ := newActionServer(t, "allow")
	srv.ApplyConfig(cfg)
	want := limits{maxHeldBody: 10, maxPush: 20, maxUploadPack: 30, maxReadRequest: 40}
	if srv.limits != want || srv.budget.reqLimit != 5 || srv.budget.byteLim != 50 || !srv.modelGateNoAsk {
		t.Fatalf("limits %+v budget %d/%d noAsk=%v", srv.limits, srv.budget.reqLimit, srv.budget.byteLim, srv.modelGateNoAsk)
	}
	up := newRecorder(t)
	if rec := send(srv, "POST", up.URL+"/x", "text/plain", strings.NewReader(strings.Repeat("a", 11)), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("configured body limit not applied: %d", rec.Code)
	}
	cfg.EgressBudget = &config.EgressBudget{Off: true}
	srv.ApplyConfig(cfg)
	if srv.budget != nil {
		t.Fatal("egress_budget.off did not turn the budget off")
	}
}

// A-12: an answer given inside the last poll interval is not lost.
func TestApprovalInTheLastPollIntervalCounts(t *testing.T) {
	srv, ag, _ := newActionServer(t, "escalate")
	up := newRecorder(t)
	srv.SetEscalateWindow(100*time.Millisecond, time.Second) // no poll before the deadline
	ag.status.Store("approved")
	if rec := send(srv, "POST", up.URL+"/deploy", "", nil, nil); rec.Code != 200 || up.hits.Load() != 1 {
		t.Fatalf("approved before the deadline: %d hits=%d", rec.Code, up.hits.Load())
	}
}

// A clean install hits a registry thousands of times a minute; it must not
// pause at the default allowance, while any other host still does.
func TestPackageRegistriesGetALargerAllowance(t *testing.T) {
	b := newEgressBudget(10, 1<<20)
	for i := 0; i < 50; i++ {
		if !b.take("registry.npmjs.org", 10) {
			t.Fatalf("registry request %d paused under a 10x allowance", i)
		}
	}
	for i := 0; i < 10; i++ {
		b.take("example.org", 10)
	}
	if b.take("example.org", 10) {
		t.Fatal("an ordinary host kept going past its allowance")
	}
}
