package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
			json.NewEncoder(w).Encode(map[string]any{"decision": sg.decision.Load().(string), "decision_id": "d1"})
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
func TestSensitiveHostForcesApprovalEvenWhenPolicyAllows(t *testing.T) {
	srv, sg, _ := newScripted(t, "allow")
	up, hits := upstreamCounting(t)
	srv.SetSensitiveHosts([]string{"127.0.0.1"})
	srv.SetEscalateWindow(120*time.Millisecond, 10*time.Millisecond)
	rec := do(srv, "GET", up.URL+"/internal")
	if hits.Load() != 0 || rec.Code == 200 {
		t.Fatalf("sensitive host reached without approval: code=%d hits=%d", rec.Code, hits.Load())
	}
	if sg.creates.Load() != 1 {
		t.Fatalf("an approval should have been opened, got %d", sg.creates.Load())
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
	srv.bindings = []creds.Binding{{Host: mustHost(t, up.URL), Headers: map[string]string{"Authorization": "Bearer REAL-SECRET-VALUE"}}}
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
	if n := countLines(t, chainFile); n != 2 {
		t.Fatalf("2 requests, %d receipts", n)
	}
}
