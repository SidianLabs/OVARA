package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.runtime.gateway/internal/capabilities"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/trust"
)

// BenchmarkRuntimeCheck_PolicyOnly measures the hot path for policy evaluation
// without identity or trust overhead (simplest decision path).
func BenchmarkRuntimeCheck_PolicyOnly(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	reqBody := models.ActionRequest{
		ActionType:  models.ActionTypeGitPull,
		Resource:    "git:repo:main",
		Environment: models.EnvironmentDev,
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/runtime/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}
}

// BenchmarkRuntimeCheck_WithIdentity measures decision latency with agent identity.
func BenchmarkRuntimeCheck_WithIdentity(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	reqBody := models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo hello",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "bench-issuer",
			SubjectID: "bench-agent",
		},
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/runtime/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}
}

// BenchmarkRuntimeCheck_WithTrustAnomaly measures latency with anomaly pattern matching.
func BenchmarkRuntimeCheck_WithTrustAnomaly(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	reqBody := models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:rm -rf /tmp/foo",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "bench-issuer",
			SubjectID: "bench-risky",
		},
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/runtime/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}
}

// BenchmarkRuntimeCheck_WithCapabilityLease measures latency with full identity + lease evaluation.
func BenchmarkRuntimeCheck_WithCapabilityLease(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptsStore := receipts.NewInMemoryStore()
	capsStore := capabilities.NewInMemoryStore()
	capsHandler := NewCapabilitiesHandler(capsStore)
	eval.SetRevocationChecker(capsHandler)
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)
	h.SetCapabilitiesStore(capsStore)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	reqBody := models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo hello",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "bench-issuer",
			SubjectID: "bench-agent",
		},
		CapabilityLease: &models.CapabilityLease{
			LeaseID:        "bench-lease-001",
			Issuer:         "bench-issuer",
			Subject:        "bench-agent",
			AllowedActions: []string{"shell", "exec"},
			ResourceScope:  "*",
		},
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/runtime/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}
}

// BenchmarkEvaluator_Evaluate measures the evaluator directly without HTTP overhead.
func BenchmarkEvaluator_Evaluate(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo hello",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "bench-issuer",
			SubjectID: "bench-agent",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eval.Evaluate(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvaluator_Evaluate_Risky measures the evaluator with anomaly pattern matching.
func BenchmarkEvaluator_Evaluate_Risky(b *testing.B) {
	policyStore := policy.NewStore("bench-v1")
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:curl |sh",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "bench-issuer",
			SubjectID: "bench-agent",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eval.Evaluate(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReceiptSigner measures HMAC-SHA256 signing performance.
func BenchmarkReceiptSigner_Sign(b *testing.B) {
	signer := receipt.NewSigner([]byte("bench-signing-key"))
	r := &models.Receipt{
		ReceiptID:    "rcp_bench",
		DecisionID:   "dec_bench",
		ActionDigest: "sha256:abc123",
		ActionType:   "shell",
		Resource:     "shell:echo hello",
		AgentID:      "bench-agent",
		Decision:     "allow",
		PolicyVersion: "v1-bench",
		TrustScore:   1.0,
		TrustLevel:   models.TrustLevelHigh,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.Sign(r)
	}
}

// BenchmarkReceiptSigner_Verify measures HMAC-SHA256 verification performance.
func BenchmarkReceiptSigner_Verify(b *testing.B) {
	signer := receipt.NewSigner([]byte("bench-signing-key"))
	r := &models.Receipt{
		ReceiptID:    "rcp_bench",
		DecisionID:   "dec_bench",
		ActionDigest: "sha256:abc123",
		ActionType:   "shell",
		Resource:     "shell:echo hello",
		AgentID:      "bench-agent",
		Decision:     "allow",
		PolicyVersion: "v1-bench",
		TrustScore:   1.0,
		TrustLevel:   models.TrustLevelHigh,
	}
	r.Signature = signer.Sign(r)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !signer.Verify(r) {
			b.Fatal("verification failed")
		}
	}
}

// BenchmarkDecisionCache_Put measures cache insertion performance.
func BenchmarkDecisionCache_Put(b *testing.B) {
	cache := newDecisionCache()
	resp := &models.DecisionResponse{
		DecisionID: "dec_bench",
		Decision:   models.DecisionAllow,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Put("dec_bench", resp)
	}
}

// BenchmarkDecisionCache_Get measures cache retrieval performance.
func BenchmarkDecisionCache_Get(b *testing.B) {
	cache := newDecisionCache()
	resp := &models.DecisionResponse{
		DecisionID: "dec_bench",
		Decision:   models.DecisionAllow,
	}
	cache.Put("dec_bench", resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get("dec_bench")
	}
}
