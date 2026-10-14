package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

// scriptedGateway answers /v1/runtime/check with `decision` and drives the
// approval endpoints from `status` (what /v1/approval/{id} reports).
type scriptedGateway struct {
	decision atomic.Value // string
	status   atomic.Value // string
	checks   atomic.Int32
	creates  atomic.Int32
	down     atomic.Bool
	// claim: what POST /v1/approval/apr_1/claim answers
	claims       atomic.Int32 // successful claims
	used         atomic.Bool  // the approval was claimed already
	claimMissing atomic.Bool  // an older gateway: the route does not exist
	rule         atomic.Value // matched_rule in the decision, when set
}

func newScripted(t *testing.T, decision string) (*Server, *scriptedGateway, string) {
	t.Helper()
	sg := &scriptedGateway{}
	sg.decision.Store(decision)
	sg.status.Store("pending")
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sg.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch {
		case r.URL.Path == "/v1/whoami":
			w.WriteHeader(404)
		case r.URL.Path == "/v1/runtime/check":
			sg.checks.Add(1)
			d := map[string]any{"decision": sg.decision.Load().(string), "decision_id": "d1"}
			if rule, _ := sg.rule.Load().(string); rule != "" {
				d["matched_rule"] = rule
			}
			_ = json.NewEncoder(w).Encode(d)
		case r.URL.Path == "/v1/approval/apr_1/claim":
			if sg.claimMissing.Load() {
				w.WriteHeader(404)
				return
			}
			st := sg.status.Load().(string)
			if st != "approved" {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": st, "claimed": false})
				return
			}
			if !sg.used.CompareAndSwap(false, true) {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "approval already used"})
				return
			}
			sg.claims.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "claimed": true})
		case r.URL.Path == "/v1/approval/create":
			sg.creates.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"approval_id": "apr_1"})
		case r.URL.Path == "/v1/approval/apr_1":
			json.NewEncoder(w).Encode(map[string]string{"status": sg.status.Load().(string)})
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
	return srv, sg, chainFile
}

func upstreamCounting(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "upstream")
	}))
	t.Cleanup(u.Close)
	return u, &hits
}

func do(srv *Server, method, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(method, url, nil)
	srv.ServeHTTP(rec, req)
	return rec
}

func TestEscalatedRequestRunsOnlyAfterApproval(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	up, hits := upstreamCounting(t)

	go func() {
		time.Sleep(150 * time.Millisecond)
		if hits.Load() != 0 {
			t.Errorf("upstream reached BEFORE approval")
		}
		sg.status.Store("approved")
	}()
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("approved request should run once: code=%d hits=%d", rec.Code, hits.Load())
	}
	if sg.creates.Load() != 1 {
		t.Fatalf("exactly one approval should be opened, got %d", sg.creates.Load())
	}
}

func TestDeniedApprovalNeverReachesUpstream(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	up, hits := upstreamCounting(t)
	sg.status.Store("denied")
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("denied: code=%d hits=%d", rec.Code, hits.Load())
	}
}

func TestUnansweredApprovalTimesOutWithoutRunning(t *testing.T) {
	srv, _, _ := newScripted(t, "escalate")
	srv.SetEscalateWindow(120*time.Millisecond, 10*time.Millisecond)
	up, hits := upstreamCounting(t)
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != http.StatusGatewayTimeout || hits.Load() != 0 {
		t.Fatalf("timeout: code=%d hits=%d", rec.Code, hits.Load())
	}
}

func TestDenyDecisionBlocksWithoutAskingAnyone(t *testing.T) {
	srv, sg, _ := newScripted(t, "deny")
	up, hits := upstreamCounting(t)
	rec := do(srv, "POST", up.URL+"/leak")
	if rec.Code != http.StatusForbidden || hits.Load() != 0 || sg.creates.Load() != 0 {
		t.Fatalf("deny: code=%d hits=%d approvals=%d", rec.Code, hits.Load(), sg.creates.Load())
	}
}

// A policy "allow" on a host in the sensitive list is still a human decision.
func TestSensitiveHostIsBlockedEvenWhenPolicyAllows(t *testing.T) {
	srv, sg, _ := newScripted(t, "allow")
	up, hits := upstreamCounting(t)
	srv.SetSensitiveHosts([]string{"127.0.0.1"})
	srv.SetEscalateWindow(120*time.Millisecond, 10*time.Millisecond)
	rec := do(srv, "GET", up.URL+"/internal")
	if hits.Load() != 0 || rec.Code == 200 {
		t.Fatalf("sensitive host reached without approval: code=%d hits=%d", rec.Code, hits.Load())
	}
	// A DENY with an explanation, not an approval request: the gateway only
	// opens approvals for decisions it recorded as escalate (409 otherwise),
	// so a proxy-forced pause could never have been answered.
	if rec.Code != http.StatusForbidden || sg.creates.Load() != 0 {
		t.Fatalf("want 403 and no approval opened, got code=%d approvals=%d", rec.Code, sg.creates.Load())
	}
	if !strings.Contains(rec.Body.String(), "sensitive_host") {
		t.Fatalf("the refusal must say why: %s", rec.Body.String())
	}
}

// Gateway unreachable: fail closed by default.
func TestGatewayDownFailsClosed(t *testing.T) {
	srv, sg, _ := newScripted(t, "allow")
	sg.down.Store(true)
	up, hits := upstreamCounting(t)
	rec := do(srv, "GET", up.URL+"/x")
	if rec.Code != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("fail-closed: code=%d hits=%d", rec.Code, hits.Load())
	}
}

// Fail-open lets traffic through but must never also hand it credentials.
func TestFailOpenNeverInjectsCredentials(t *testing.T) {
	srv, sg, _ := newScripted(t, "allow")
	srv.failOpen = true
	sg.down.Store(true)
	var sawAuth string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	srv.bindings = []creds.Binding{{Host: mustHostPort(t, up.URL), Headers: map[string]string{"Authorization": "Bearer REAL-SECRET-VALUE"}}}
	srv.transport.TLSClientConfig.InsecureSkipVerify = true

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", up.URL+"/x", nil)
	srv.ServeHTTP(rec, req)
	if sawAuth == "Bearer REAL-SECRET-VALUE" {
		t.Fatal("fail-open handed the real credential to an unchecked request")
	}
}

// A gateway that answers with an unknown decision string must not execute.
func TestMalformedDecisionIsNotAnAllow(t *testing.T) {
	for _, d := range []string{"", "ALLOW", "allowed", "maybe", "allow "} {
		t.Run(fmt.Sprintf("%q", d), func(t *testing.T) {
			srv, _, _ := newScripted(t, d)
			up, hits := upstreamCounting(t)
			rec := do(srv, "GET", up.URL+"/x")
			if hits.Load() != 0 || rec.Code == 200 {
				t.Fatalf("decision %q reached the upstream (code=%d)", d, rec.Code)
			}
		})
	}
}

// Every outcome leaves a receipt that matches what happened.
func TestEveryOutcomeIsReceipted(t *testing.T) {
	srv, sg, chainFile := newScripted(t, "deny")
	up, _ := upstreamCounting(t)
	do(srv, "POST", up.URL+"/a")
	sg.decision.Store("allow")
	do(srv, "GET", up.URL+"/b")
	// The denied request has one receipt; the forwarded one has an attempt
	// receipt (written before it was sent) and its outcome.
	if n := countLines(t, chainFile); n != 3 {
		t.Fatalf("2 requests, %d receipts, want 3", n)
	}
}

// The agent must never hold a response whose receipt is not yet on disk. The
// upstream sends its headers and then stalls mid-body; by the time the client
// has the headers, the receipt has to exist.
func TestReceiptIsWrittenBeforeTheResponseReachesTheAgent(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "first-chunk\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "second-chunk\n")
	}))
	defer up.Close()
	defer close(release)

	srv, _, chainFile := newScripted(t, "allow")
	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	resp, err := client.Get(up.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Headers are in hand, the body is still open. Both receipts (the
	// attempt and its outcome) must be there.
	if n := countLines(t, chainFile); n != 2 {
		t.Fatalf("response headers reached the agent with %d receipts on disk, want 2", n)
	}
}

// An approved request is claimed before it runs, so the approval is used
// once: the gateway sees exactly one claim for the one upstream call.
func TestApprovedRequestIsClaimedBeforeItRuns(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	up, hits := upstreamCounting(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		sg.status.Store("approved")
	}()
	if rec := do(srv, "POST", up.URL+"/deploy"); rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("approved request: code=%d hits=%d", rec.Code, hits.Load())
	}
	if sg.claims.Load() != 1 || !sg.used.Load() {
		t.Fatalf("claims=%d used=%v, want one claim", sg.claims.Load(), sg.used.Load())
	}
}

// An approval already used by an identical request is not ridden again:
// the request is refused, nothing reaches upstream, and the answer says so.
func TestAnApprovalAlreadyUsedIsNotReplayed(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	up, hits := upstreamCounting(t)
	sg.status.Store("approved")
	sg.used.Store(true)
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != http.StatusForbidden || hits.Load() != 0 || !strings.Contains(rec.Body.String(), "already used") {
		t.Fatalf("used approval: code=%d hits=%d body=%s", rec.Code, hits.Load(), rec.Body)
	}
}

// With the retry answer configured, an unanswered hold ends in 503 with
// Retry-After and the approval id, not 504; the approval stays open, so the
// same request sent again after the person approved runs, once.
func TestRetryAnswerCarriesRetryAfterAndTheApprovalStaysOpen(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	srv.SetEscalateWindow(120*time.Millisecond, 10*time.Millisecond)
	srv.SetEscalateAnswer(true)
	sg.rule.Store("deploys need a person")
	up, hits := upstreamCounting(t)
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != http.StatusServiceUnavailable || hits.Load() != 0 {
		t.Fatalf("held and unanswered: code=%d hits=%d", rec.Code, hits.Load())
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After %q", ra)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "held for approval" || body["approval_id"] != "apr_1" || body["decision_id"] != "d1" || body["rule"] != "deploys need a person" {
		t.Fatalf("answer %v", body)
	}
	// The person approves after the agent was told to come back.
	sg.status.Store("approved")
	if rec := do(srv, "POST", up.URL+"/deploy"); rec.Code != 200 || hits.Load() != 1 || sg.claims.Load() != 1 {
		t.Fatalf("retry after approval: code=%d hits=%d claims=%d", rec.Code, hits.Load(), sg.claims.Load())
	}
}

// Without the retry answer (the default) the hold still ends in 504.
func TestTimeoutAnswerIsTheDefault(t *testing.T) {
	srv, _, _ := newScripted(t, "escalate")
	srv.SetEscalateWindow(120*time.Millisecond, 10*time.Millisecond)
	up, hits := upstreamCounting(t)
	rec := do(srv, "POST", up.URL+"/deploy")
	if rec.Code != http.StatusGatewayTimeout || hits.Load() != 0 || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("default: code=%d hits=%d retry-after=%q", rec.Code, hits.Load(), rec.Header().Get("Retry-After"))
	}
}

// A gateway without the claim route (an older one) does not stop an
// approved request: it runs, and the proxy says once that approvals are
// not single-use there.
func TestAnOlderGatewayWithoutClaimStillRuns(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	sg.claimMissing.Store(true)
	sg.status.Store("approved")
	up, hits := upstreamCounting(t)
	if rec := do(srv, "POST", up.URL+"/deploy"); rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("older gateway: code=%d hits=%d", rec.Code, hits.Load())
	}
}

// Every refusal names the rule that decided, so the agent (and the person
// reading its output) can see what to change.
func TestRefusalsNameTheRule(t *testing.T) {
	srv, sg, _ := newScripted(t, "deny")
	sg.rule.Store("no paste sites")
	up, _ := upstreamCounting(t)
	rec := do(srv, "POST", up.URL+"/leak")
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || body["rule"] != "no paste sites" {
		t.Fatalf("deny: code=%d body=%v", rec.Code, body)
	}
	srv2, sg2, _ := newScripted(t, "escalate")
	sg2.rule.Store("deploys need a person")
	sg2.status.Store("denied")
	rec = do(srv2, "POST", up.URL+"/deploy")
	body = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || body["rule"] != "deploys need a person" {
		t.Fatalf("denied approval: code=%d body=%v", rec.Code, body)
	}
}
