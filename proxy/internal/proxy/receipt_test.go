package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

// receiptGateway answers like the real gateway does for receipts: a matched
// rule, a policy hash, and an approval resolved by a named person.
func receiptGateway(t *testing.T, decision string) *httptest.Server {
	t.Helper()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runtime/check":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision": decision, "decision_id": "d1",
				"reason_codes": []string{"policy_escalate"},
				"matched_rule": "writes need approval",
				"receipt_stub": map[string]any{"policy_hash": "sha256:abc"},
			})
		case "/v1/approval/create":
			_ = json.NewEncoder(w).Encode(map[string]string{"approval_id": "apr_1"})
		case "/v1/approval/apr_1":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "resolved_by": "operator:alice"})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gw.Close)
	return gw
}

func receiptServer(t *testing.T, decision, chainFile string) *Server {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := receipts.LoadOrCreate(chainFile, filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	if chain != nil {
		t.Cleanup(func() { _ = chain.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	srv := New(c, gateway.New(receiptGateway(t, decision).URL, "", "test"), nil, chain, false)
	srv.SetPublicEgressOnly(false)
	srv.SetConnectPort443Only(false)
	srv.SetEscalateWindow(2*time.Second, 10*time.Millisecond)
	return srv
}

// G-06: a request whose receipt cannot be written is not sent.
func TestNoUpstreamBytesWithoutReceipt(t *testing.T) {
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "var", "receipts.jsonl")
	srv := receiptServer(t, "allow", chainFile)
	// The receipt directory's place is taken by a file: no receipt can be
	// created there.
	_ = os.WriteFile(filepath.Join(dir, "var"), []byte("not a directory"), 0o600)
	up, hits := upstreamCounting(t)
	rec := do(srv, "GET", up.URL+"/x")
	if hits.Load() != 0 {
		t.Fatal("request reached the upstream without a receipt")
	}
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "receipt could not be written; not forwarding") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// Fail-open keeps forwarding when the receipt cannot be written.
func TestNoReceiptFailOpenStillForwards(t *testing.T) {
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "var", "receipts.jsonl")
	srv := receiptServer(t, "allow", chainFile)
	srv.failOpen = true
	_ = os.WriteFile(filepath.Join(dir, "var"), []byte("x"), 0o600)
	up, hits := upstreamCounting(t)
	do(srv, "GET", up.URL+"/x")
	if hits.Load() != 1 {
		t.Fatal("fail_open should forward")
	}
}

// Receipt v2: an approved request leaves an attempt receipt, synced before
// it was sent, and an outcome receipt naming it, both carrying who asked,
// which rule and policy decided, who approved, and what was sent.
func TestReceiptV2Fields(t *testing.T) {
	dir := t.TempDir()
	chainFile := filepath.Join(dir, "receipts.jsonl")
	srv := receiptServer(t, "escalate", chainFile)
	srv.SetClientAuth("proxy-token")
	up, hits := upstreamCounting(t)
	body := []byte(`{"title":"hello"}`)
	req, _ := http.NewRequest("POST", up.URL+"/issues", bytes.NewReader(body))
	req.Header.Set("Proxy-Authorization", "Bearer proxy-token")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("approved request: %d hits=%d", rec.Code, hits.Load())
	}
	data, _ := os.ReadFile(chainFile)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want attempt + outcome, got %d lines", len(lines))
	}
	var a, o receipts.Receipt
	_ = json.Unmarshal(lines[0], &a)
	_ = json.Unmarshal(lines[1], &o)
	sum := sha256.Sum256(body)
	tok := sha256.Sum256([]byte("proxy-token"))
	want := receipts.Receipt{V: 2, Decision: "allow", ApprovalID: "apr_1", Agent: "pt_" + hex.EncodeToString(tok[:])[:16],
		Rule: "writes need approval", PolicyHash: "sha256:abc", Approver: "operator:alice",
		ReqBytes: int64(len(body)), BodySHA256: hex.EncodeToString(sum[:])}
	for _, r := range []receipts.Receipt{a, o} {
		if r.V != want.V || r.Decision != want.Decision || r.ApprovalID != want.ApprovalID || r.Agent != want.Agent ||
			r.Rule != want.Rule || r.PolicyHash != want.PolicyHash || r.Approver != want.Approver ||
			r.ReqBytes != want.ReqBytes || r.BodySHA256 != want.BodySHA256 || len(r.Reasons) == 0 || r.KeyID == "" {
			t.Fatalf("receipt fields:\n got %+v\nwant %+v", r, want)
		}
	}
	if a.Phase != "attempt" || a.Outcome != "sent" || a.Status != 0 {
		t.Fatalf("attempt: %+v", a)
	}
	if o.Phase != "outcome" || o.AttemptID != a.ReceiptID || o.Status != 200 || o.RespBytes != int64(len("upstream")) {
		t.Fatalf("outcome: %+v", o)
	}
}
