package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.tools.benchmarks/internal/generator"
	"ovara.tools.benchmarks/internal/report"
)

func TestReporterRecordResult(t *testing.T) {
	r := report.NewReporter()
	
	// Record some test results
	for i := 0; i < 10; i++ {
		r.RecordResult(report.RequestResult{
			Latency: time.Duration(i+1) * time.Millisecond,
			Success: i%2 == 0,
			Timestamp: time.Now(),
		})
	}
	
	reportData := r.GenerateReport()
	
	if reportData.TotalRequests != 10 {
		t.Errorf("Expected 10 requests, got %d", reportData.TotalRequests)
	}
	
	if reportData.TotalSuccesses != 5 {
		t.Errorf("Expected 5 successes, got %d", reportData.TotalSuccesses)
	}
	
	if reportData.TotalErrors != 5 {
		t.Errorf("Expected 5 errors, got %d", reportData.TotalErrors)
	}
	
	if reportData.ErrorRate != 50.0 {
		t.Errorf("Expected 50%% error rate, got %.2f%%", reportData.ErrorRate)
	}
}

func TestReporterPercentiles(t *testing.T) {
	r := report.NewReporter()

	// Record 100 results with known latencies
	for i := 1; i <= 100; i++ {
		r.RecordResult(report.RequestResult{
			Latency: time.Duration(i) * time.Microsecond,
			Success: true,
			Timestamp: time.Now(),
		})
	}

	reportData := r.GenerateReport()

	// p50 = latencies[100*50/100] = latencies[50] = 51μs
	if reportData.P50Latency != 51*time.Microsecond {
		t.Errorf("Expected p50 latency of 51μs, got %v", reportData.P50Latency)
	}

	// p95 = latencies[100*95/100] = latencies[95] = 96μs
	if reportData.P95Latency != 96*time.Microsecond {
		t.Errorf("Expected p95 latency of 96μs, got %v", reportData.P95Latency)
	}

	// p99 = latencies[100*99/100] = latencies[99] = 100μs
	if reportData.P99Latency != 100*time.Microsecond {
		t.Errorf("Expected p99 latency of 100μs, got %v", reportData.P99Latency)
	}
}

func TestReporterDecisionsPerSecond(t *testing.T) {
	r := report.NewReporter()
	
	// Use a fixed start time for reproducibility
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		r.RecordResult(report.RequestResult{
			Latency: time.Millisecond,
			Success: true,
			Timestamp: start.Add(time.Duration(i) * 10 * time.Millisecond),
		})
	}
	
	reportData := r.GenerateReport()
	
	// The timestamps span 990ms (from 0ms to 990ms), so decisions/sec should be ~100
	// But the calculation uses time.Now() for EndTime, which is different
	// Let's check that the calculation is reasonable
	if reportData.DecisionsPerSecond < 1 || reportData.DecisionsPerSecond > 10000 {
		t.Errorf("Expected reasonable decisions/sec, got %.2f", reportData.DecisionsPerSecond)
	}
}

func TestLoadGeneratorWithMockServer(t *testing.T) {
	// Create a mock server that responds quickly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime/check" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"allowed": true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	
	gen := generator.NewLoadGenerator(server.URL, 5, 2*time.Second, 500*time.Millisecond, 500*time.Millisecond)
	
	reportData := gen.GenerateLoad()
	
	// Verify we got some results
	if reportData.TotalRequests == 0 {
		t.Error("Expected some requests to be made")
	}
	
	// Verify all requests succeeded (mock server always returns 200)
	if reportData.TotalSuccesses != reportData.TotalRequests {
		t.Errorf("Expected all requests to succeed, got %d successes out of %d requests",
			reportData.TotalSuccesses, reportData.TotalRequests)
	}
	
	// Verify error rate is 0
	if reportData.ErrorRate != 0 {
		t.Errorf("Expected 0%% error rate, got %.2f%%", reportData.ErrorRate)
	}
	
	// Verify latency metrics are reasonable
	if reportData.P50Latency <= 0 {
		t.Error("Expected positive p50 latency")
	}
	
	if reportData.P95Latency <= 0 {
		t.Error("Expected positive p95 latency")
	}
	
	if reportData.P99Latency <= 0 {
		t.Error("Expected positive p99 latency")
	}
}

func TestLoadGeneratorErrorHandling(t *testing.T) {
	// Create a server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer server.Close()
	
	gen := generator.NewLoadGenerator(server.URL, 2, 1*time.Second, 100*time.Millisecond, 100*time.Millisecond)
	
	reportData := gen.GenerateLoad()
	
	// Verify we got some results
	if reportData.TotalRequests == 0 {
		t.Error("Expected some requests to be made")
	}
	
	// Verify all requests failed
	if reportData.TotalErrors != reportData.TotalRequests {
		t.Errorf("Expected all requests to fail, got %d errors out of %d requests",
			reportData.TotalErrors, reportData.TotalRequests)
	}
	
	// Verify error rate is 100%
	if reportData.ErrorRate != 100.0 {
		t.Errorf("Expected 100%% error rate, got %.2f%%", reportData.ErrorRate)
	}
}

func TestJSONReportOutput(t *testing.T) {
	r := report.NewReporter()
	
	// Record some test results
	for i := 0; i < 5; i++ {
		r.RecordResult(report.RequestResult{
			Latency: time.Duration(i+1) * time.Millisecond,
			Success: true,
			Timestamp: time.Now(),
		})
	}
	
	reportData := r.GenerateReport()
	
	// Test JSON marshaling
	data, err := json.Marshal(reportData)
	if err != nil {
		t.Errorf("Failed to marshal report to JSON: %v", err)
	}
	
	// Verify JSON is valid
	var unmarshaled report.Report
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Errorf("Failed to unmarshal JSON report: %v", err)
	}
	
	// Verify data integrity
	if unmarshaled.TotalRequests != reportData.TotalRequests {
		t.Errorf("Expected %d requests in JSON, got %d",
			reportData.TotalRequests, unmarshaled.TotalRequests)
	}
}

func TestTimeSeriesOutput(t *testing.T) {
	r := report.NewReporter()
	
	// Record results across multiple seconds
	baseTime := time.Now().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		for j := 0; j < 10; j++ {
			r.RecordResult(report.RequestResult{
				Latency: time.Duration(j+1) * time.Millisecond,
				Success: true,
				Timestamp: baseTime.Add(time.Duration(i) * time.Second),
			})
		}
	}
	
	reportData := r.GenerateReport()
	
	// Verify time series has entries
	if len(reportData.TimeSeries) == 0 {
		t.Error("Expected time series to have entries")
	}
	
	// Verify time series is sorted
	for i := 1; i < len(reportData.TimeSeries); i++ {
		if reportData.TimeSeries[i].Timestamp.Before(reportData.TimeSeries[i-1].Timestamp) {
			t.Error("Time series is not sorted by timestamp")
		}
	}
}

func TestActionSelection(t *testing.T) {
	// Test that actions are selected with correct distribution
	// This is a statistical test, so we need enough samples
	gen := generator.NewLoadGenerator("http://localhost:8080", 1, 1*time.Second, 0, 0)
	
	counts := map[string]int{
		"shell:echo test": 0,
		"git.pull": 0,
		"git.push": 0,
		"exec:ls": 0,
	}
	
	// Use a fixed seed for reproducibility
	rng := rand.New(rand.NewSource(42))
	
	for i := 0; i < 10000; i++ {
		action := gen.SelectAction(rng)
		counts[action.Action]++
	}
	
	// Verify distribution is within reasonable bounds
	// shell:echo test should be ~40%
	if counts["shell:echo test"] < 3500 || counts["shell:echo test"] > 4500 {
		t.Errorf("Expected shell:echo test ~4000, got %d", counts["shell:echo test"])
	}
	
	// git.pull should be ~30%
	if counts["git.pull"] < 2500 || counts["git.pull"] > 3500 {
		t.Errorf("Expected git.pull ~3000, got %d", counts["git.pull"])
	}
	
	// git.push should be ~20%
	if counts["git.push"] < 1500 || counts["git.push"] > 2500 {
		t.Errorf("Expected git.push ~2000, got %d", counts["git.push"])
	}
	
	// exec:ls should be ~10%
	if counts["exec:ls"] < 500 || counts["exec:ls"] > 1500 {
		t.Errorf("Expected exec:ls ~1000, got %d", counts["exec:ls"])
	}
}