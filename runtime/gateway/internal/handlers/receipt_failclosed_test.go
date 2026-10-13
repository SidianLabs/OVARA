package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipts"
)

// failingReceipts is a receipt store whose disk is full.
type failingReceipts struct{ receipts.Store }

func (failingReceipts) Put(*models.Receipt) error { return errors.New("no space left on device") }

// recordingReceipts keeps what was persisted.
type recordingReceipts struct {
	receipts.Store
	got []*models.Receipt
}

func (r *recordingReceipts) Put(rc *models.Receipt) error { r.got = append(r.got, rc); return nil }

func checkWith(t *testing.T, rs receipts.Store) *models.DecisionResponse {
	t.Helper()
	store := policy.NewStore("v1-test")
	store.ClearRules()
	store.AddRule(policy.Rule{ActionType: "http.request", Environment: "*", Resource: "GET *", Allow: true})
	h := New(evaluator.New(store), nil, config.Default(), rs)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	body, _ := json.Marshal(models.ActionRequest{
		Nonce: uuid.NewString(), IssuedAt: time.Now(), ActionType: "http.request",
		Resource: "GET https://pypi.org/simple/", Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
	})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/runtime/check", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("check: %d %s", w.Code, w.Body.String())
	}
	var resp models.DecisionResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return &resp
}

// G-06: an allow whose receipt cannot be written is answered as a deny.
func TestAllowWithoutReceiptIsDenied(t *testing.T) {
	if got := checkWith(t, receipts.NewInMemoryStore()); got.Decision != models.DecisionAllow {
		t.Fatalf("baseline: %s", got.Decision)
	}
	got := checkWith(t, failingReceipts{})
	if got.Decision != models.DecisionDeny {
		t.Fatalf("allow returned although its receipt was not written: %s", got.Decision)
	}
	found := false
	for _, r := range got.ReasonCodes {
		found = found || r == models.ReasonReceiptUnavailable
	}
	if !found {
		t.Fatalf("reason missing: %v", got.ReasonCodes)
	}
}

// G-15: the local placeholder signature is never persisted as if it were
// a signature.
func TestPlaceholderSignatureNeverPersisted(t *testing.T) {
	rs := &recordingReceipts{Store: receipts.NewInMemoryStore()}
	checkWith(t, rs)
	if len(rs.got) != 1 {
		t.Fatalf("want one receipt, got %d", len(rs.got))
	}
	if strings.HasPrefix(rs.got[0].Signature, "sig_v1_local:") || strings.HasPrefix(rs.got[0].Signature, "sig_v1:") {
		t.Fatalf("persisted signature %q", rs.got[0].Signature)
	}
	// The stores themselves refuse it too.
	for _, st := range []receipts.Store{receipts.NewInMemoryStore()} {
		if err := st.Put(&models.Receipt{ReceiptID: "r1", Signature: "sig_v1_local:r1"}); err == nil {
			t.Fatal("store accepted a placeholder signature")
		}
	}
}
