package load

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

func testHandler() http.Handler {
	mux := http.NewServeMux()
	store := policy.NewStore("v1-test")
	store.AddRule(policy.Rule{ActionType: "shell", Environment: "local", Allow: true})
	store.AddRule(policy.Rule{ActionType: "shell", Environment: "dev", Escalate: true})
	store.AddRule(policy.Rule{ActionType: "git.pull", Environment: "*", Allow: true})
	store.AddRule(policy.Rule{ActionType: "git.push", Environment: "*", Escalate: true})
	store.AddRule(policy.Rule{ActionType: "exec", Environment: "*", Escalate: true})

	eval := evaluator.New(store)

	mux.HandleFunc("/v1/runtime/check", func(w http.ResponseWriter, r *http.Request) {
		var req models.ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp, err := eval.Evaluate(&req)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	return mux
}

func TestLoadDecisionThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	server := httptest.NewServer(testHandler())
	defer server.Close()

	config := LoadConfig{
		Target:      server.URL,
		Duration:    5 * time.Second,
		Concurrency: 50,
	}

	metrics := RunLoadTest(config)
	report := GenerateReport(metrics)

	if report.TotalRequests < 100 {
		t.Errorf("total requests = %d, want >= 100", report.TotalRequests)
	}
	if report.ErrorRate > 5 {
		t.Errorf("error rate = %.2f%%, want < 5%%", report.ErrorRate)
	}
	t.Logf("Throughput: %.0f decisions/sec", report.DecisionsPerSec)
	t.Logf("Latency p50=%v p95=%v p99=%v", report.Latency.P50, report.Latency.P95, report.Latency.P99)
	t.Logf("Errors: %d/%d (%.2f%%)", report.FailedRequests, report.TotalRequests, report.ErrorRate)
}

func TestLoadDecisionLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	server := httptest.NewServer(testHandler())
	defer server.Close()

	// Threshold is more permissive than the measured Apple M4 baseline (7-30ms)
	// to avoid flakes on busy CI runners. 250ms still catches real regressions
	// where decision latency is pathologically slow.
	const ciThreshold = 250 * time.Millisecond
	const devThreshold = 100 * time.Millisecond

	threshold := devThreshold
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		threshold = ciThreshold
	}

	config := LoadConfig{
		Target:      server.URL,
		Duration:    3 * time.Second,
		Concurrency: 20,
	}

	metrics := RunLoadTest(config)
	latency := CalculatePercentiles(metrics.Latencies)

	if latency.P99 > threshold {
		t.Errorf("p99 latency = %v, want < %v (CI=%v dev=%v)",
			latency.P99, threshold, ciThreshold, devThreshold)
	}
	t.Logf("Latency: min=%v avg=%v p50=%v p95=%v p99=%v max=%v (threshold=%v)",
		latency.Min, latency.Avg, latency.P50, latency.P95, latency.P99, latency.Max, threshold)
}

func TestGenerateRequest(t *testing.T) {
	for i := 0; i < 100; i++ {
		req := generateRequest()
		if req["action_type"] == nil || req["resource"] == nil || req["environment"] == nil {
			t.Errorf("missing required fields in request: %v", req)
		}
	}
}

func TestCalculatePercentiles(t *testing.T) {
	latencies := make([]time.Duration, 100)
	for i := range latencies {
		latencies[i] = time.Duration(i) * time.Millisecond
	}

	p := CalculatePercentiles(latencies)
	if p.P50 != 50*time.Millisecond {
		t.Errorf("p50 = %v, want 50ms", p.P50)
	}
	if p.P95 != 95*time.Millisecond {
		t.Errorf("p95 = %v, want 95ms", p.P95)
	}
	if p.P99 != 99*time.Millisecond {
		t.Errorf("p99 = %v, want 99ms", p.P99)
	}
}

func TestGenerateReport(t *testing.T) {
	metrics := &Metrics{
		TotalRequests:   1000,
		SuccessRequests: 990,
		FailedRequests:  10,
		Latencies:       make([]time.Duration, 1000),
		StartTime:       time.Now(),
		EndTime:         time.Now().Add(10 * time.Second),
	}
	for i := range metrics.Latencies {
		metrics.Latencies[i] = time.Duration(i) * time.Microsecond
	}

	report := GenerateReport(metrics)
	if report.DecisionsPerSec != 100 {
		t.Errorf("decisions/sec = %.2f, want 100", report.DecisionsPerSec)
	}
	if report.ErrorRate != 1 {
		t.Errorf("error rate = %.2f%%, want 1%%", report.ErrorRate)
	}
}
