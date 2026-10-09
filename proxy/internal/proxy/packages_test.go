package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

// pkgGateway allows every URL and answers package.install with pkgDecision;
// each approval it opens reports approvalStatus.
type pkgGateway struct {
	pkgDecision    atomic.Value // string
	approvalStatus atomic.Value // string
	pkgChecks      atomic.Int32
	creates        atomic.Int32
	mu             sync.Mutex
	resources      []string
}

func newPkgServer(t *testing.T, gate bool, pinned ...string) (*Server, *pkgGateway, *atomic.Int32) {
	t.Helper()
	pg := &pkgGateway{}
	pg.pkgDecision.Store("escalate")
	pg.approvalStatus.Store("pending")
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/runtime/check":
			var body struct {
				ActionType string `json:"action_type"`
				Resource   string `json:"resource"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			dec := "allow"
			if body.ActionType == actionPackageInstall {
				pg.pkgChecks.Add(1)
				pg.mu.Lock()
				pg.resources = append(pg.resources, body.Resource)
				pg.mu.Unlock()
				dec = pg.pkgDecision.Load().(string)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"decision": dec, "decision_id": "d1"})
		case r.URL.Path == "/v1/approval/create":
			n := pg.creates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": fmt.Sprintf("apr_%d", n)})
		case strings.HasPrefix(r.URL.Path, "/v1/approval/apr_"):
			_ = json.NewEncoder(w).Encode(map[string]string{"status": pg.approvalStatus.Load().(string)})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gw.Close)
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "tarball")
	}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	c, err := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := receipts.LoadOrCreate(filepath.Join(dir, "receipts.jsonl"), filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(c, gateway.New(gw.URL, "", "test"), nil, chain, false)
	srv.SetPublicEgressOnly(false)
	srv.SetConnectPort443Only(false)
	srv.SetEscalateWindow(2*time.Second, 10*time.Millisecond)
	// every upstream host is the local test server
	addr := up.Listener.Addr().String()
	srv.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if gate {
		srv.SetPackageGate(pinned)
	}
	return srv, pg, &hits
}

const leftPad = "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"

func TestPackageGate_PinnedPackagePassesWithoutAQuestion(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true, "npm:left-pad@1.3.0")
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != 200 {
		t.Fatalf("pinned package: %d %s", rec.Code, rec.Body)
	}
	if pg.pkgChecks.Load() != 0 || hits.Load() != 1 {
		t.Fatalf("checks=%d hits=%d", pg.pkgChecks.Load(), hits.Load())
	}
}

func TestPackageGate_NewPackagePausesOnceThenIsAllowed(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true)
	go func() {
		time.Sleep(100 * time.Millisecond)
		if hits.Load() != 0 {
			t.Errorf("downloaded before approval")
		}
		pg.approvalStatus.Store("approved")
	}()
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != 200 {
		t.Fatalf("approved package: %d %s", rec.Code, rec.Body)
	}
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != 200 {
		t.Fatalf("second download: %d", rec.Code)
	}
	if pg.creates.Load() != 1 || pg.pkgChecks.Load() != 1 || hits.Load() != 2 {
		t.Fatalf("want one question for two downloads: creates=%d checks=%d hits=%d", pg.creates.Load(), pg.pkgChecks.Load(), hits.Load())
	}
	if pg.resources[0] != "npm:left-pad@1.3.0" {
		t.Fatalf("the person was asked about %q", pg.resources[0])
	}
}

func TestPackageGate_RefusedPackageNeverDownloads(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true)
	pg.approvalStatus.Store("denied")
	rec := do(srv, http.MethodGet, leftPad)
	if rec.Code != http.StatusForbidden || hits.Load() != 0 || !strings.Contains(rec.Body.String(), "npm:left-pad@1.3.0") {
		t.Fatalf("refused: %d hits=%d %s", rec.Code, hits.Load(), rec.Body)
	}
	// a refusal is not remembered as an allowance: asking again asks again
	do(srv, http.MethodGet, leftPad)
	if pg.creates.Load() != 2 || hits.Load() != 0 {
		t.Fatalf("creates=%d hits=%d", pg.creates.Load(), hits.Load())
	}
}

func TestPackageGate_PolicyDenyAndAllow(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true)
	pg.pkgDecision.Store("deny")
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != http.StatusForbidden || pg.creates.Load() != 0 {
		t.Fatalf("policy deny: %d creates=%d", rec.Code, pg.creates.Load())
	}
	pg.pkgDecision.Store("allow")
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("policy allow: %d", rec.Code)
	}
}

func TestPackageGate_ParallelDownloadsAskOnce(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true)
	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = do(srv, http.MethodGet, leftPad).Code
		}(i)
	}
	time.Sleep(150 * time.Millisecond)
	pg.approvalStatus.Store("approved")
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("codes %v", codes)
		}
	}
	if pg.creates.Load() != 1 || hits.Load() != 5 {
		t.Fatalf("creates=%d hits=%d", pg.creates.Load(), hits.Load())
	}
}

func TestPackageGate_MetadataAndAuditAreNotAsked(t *testing.T) {
	srv, pg, _ := newPkgServer(t, true)
	for _, u := range []string{
		"http://registry.npmjs.org/left-pad",
		"http://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
		"http://pypi.org/simple/six/",
	} {
		method := http.MethodGet
		if strings.Contains(u, "advisories") {
			method = http.MethodPost
		}
		if rec := do(srv, method, u); rec.Code != 200 {
			t.Fatalf("%s: %d", u, rec.Code)
		}
	}
	if pg.pkgChecks.Load() != 0 {
		t.Fatalf("metadata asked about: %v", pg.resources)
	}
}

func TestPackageGate_OffByDefault(t *testing.T) {
	srv, pg, hits := newPkgServer(t, false)
	if rec := do(srv, http.MethodGet, leftPad); rec.Code != 200 || pg.pkgChecks.Load() != 0 || hits.Load() != 1 {
		t.Fatalf("gate off: %d checks=%d", rec.Code, pg.pkgChecks.Load())
	}
}

func TestUnattended_EscalationsAreRefusedAtOnce(t *testing.T) {
	// a new package: refused without opening an approval
	srv, pg, hits := newPkgServer(t, true)
	srv.SetUnattended(true)
	start := time.Now()
	rec := do(srv, http.MethodGet, leftPad)
	if rec.Code != http.StatusForbidden || hits.Load() != 0 || pg.creates.Load() != 0 {
		t.Fatalf("unattended new package: %d hits=%d creates=%d", rec.Code, hits.Load(), pg.creates.Load())
	}
	if time.Since(start) > time.Second {
		t.Fatalf("unattended refusal waited %v", time.Since(start))
	}
	// a pinned one still goes through
	srv2, _, hits2 := newPkgServer(t, true, "npm:left-pad@1.3.0")
	srv2.SetUnattended(true)
	if rec := do(srv2, http.MethodGet, leftPad); rec.Code != 200 || hits2.Load() != 1 {
		t.Fatalf("unattended pinned package: %d", rec.Code)
	}
}

func TestUnattended_EscalatedRequestRefusedWithoutApproval(t *testing.T) {
	srv, sg, _ := newScripted(t, "escalate")
	srv.SetUnattended(true)
	up, hits := upstreamCounting(t)
	start := time.Now()
	rec := do(srv, http.MethodPost, up.URL+"/deploy")
	if rec.Code != http.StatusForbidden || hits.Load() != 0 || sg.creates.Load() != 0 {
		t.Fatalf("unattended escalate: %d hits=%d creates=%d", rec.Code, hits.Load(), sg.creates.Load())
	}
	if !strings.Contains(rec.Body.String(), "unattended") || time.Since(start) > time.Second {
		t.Fatalf("body %s, took %v", rec.Body, time.Since(start))
	}
}
