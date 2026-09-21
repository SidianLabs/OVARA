package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewReporter(t *testing.T) {
	r := NewReporter()
	if r == nil {
		t.Fatal("NewReporter returned nil")
	}
	if r.results == nil {
		t.Error("results slice not initialized")
	}
	if r.secondMap == nil {
		t.Error("secondMap not initialized")
	}
	if r.startTime.IsZero() {
		t.Error("startTime not set")
	}
}

func TestReporter_RecordResult_Single(t *testing.T) {
	r := NewReporter()
	now := time.Now()
	r.RecordResult(RequestResult{
		Latency:   5 * time.Millisecond,
		Success:   true,
		Timestamp: now,
	})

	report := r.GenerateReport()
	if report.TotalRequests != 1 {
		t.Errorf("expected 1 request, got %d", report.TotalRequests)
	}
	if report.TotalSuccesses != 1 {
		t.Errorf("expected 1 success, got %d", report.TotalSuccesses)
	}
	if report.TotalErrors != 0 {
		t.Errorf("expected 0 errors, got %d", report.TotalErrors)
	}
}

func TestReporter_RecordResult_Mixed(t *testing.T) {
	r := NewReporter()
	base := time.Now()

	for i := 0; i < 7; i++ {
		r.RecordResult(RequestResult{
			Latency:   time.Duration(i+1) * time.Millisecond,
			Success:   i%2 == 0,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}

	report := r.GenerateReport()
	if report.TotalRequests != 7 {
		t.Errorf("expected 7 requests, got %d", report.TotalRequests)
	}
	if report.TotalSuccesses != 4 {
		t.Errorf("expected 4 successes, got %d", report.TotalSuccesses)
	}
	if report.TotalErrors != 3 {
		t.Errorf("expected 3 errors, got %d", report.TotalErrors)
	}
}

func TestReporter_GenerateReport_Empty(t *testing.T) {
	r := NewReporter()
	report := r.GenerateReport()
	if report.TotalRequests != 0 {
		t.Errorf("expected 0 requests, got %d", report.TotalRequests)
	}
	if report.ErrorRate != 0 {
		t.Errorf("expected 0 error rate, got %f", report.ErrorRate)
	}
	if report.P50Latency != 0 {
		t.Errorf("expected 0 p50 latency, got %v", report.P50Latency)
	}
}

func TestReporter_GenerateReport_Percentiles(t *testing.T) {
	r := NewReporter()
	base := time.Now()

	for i := 0; i < 100; i++ {
		r.RecordResult(RequestResult{
			Latency:   time.Duration(i) * time.Millisecond,
			Success:   true,
			Timestamp: base,
		})
	}

	report := r.GenerateReport()
	if report.P50Latency != 50*time.Millisecond {
		t.Errorf("expected p50 = 50ms, got %v", report.P50Latency)
	}
	if report.P95Latency != 95*time.Millisecond {
		t.Errorf("expected p95 = 95ms, got %v", report.P95Latency)
	}
	if report.P99Latency != 99*time.Millisecond {
		t.Errorf("expected p99 = 99ms, got %v", report.P99Latency)
	}
	if report.AverageLatency != 4950*time.Millisecond/100 {
		t.Errorf("expected avg = 49.5ms, got %v", report.AverageLatency)
	}
}

func TestReporter_GenerateReport_ErrorRate(t *testing.T) {
	r := NewReporter()
	base := time.Now()

	for i := 0; i < 10; i++ {
		r.RecordResult(RequestResult{
			Latency:   time.Millisecond,
			Success:   i < 8,
			Timestamp: base,
		})
	}

	report := r.GenerateReport()
	expectedRate := 20.0
	if report.ErrorRate != expectedRate {
		t.Errorf("expected error rate = %f, got %f", expectedRate, report.ErrorRate)
	}
}

func TestReporter_GenerateReport_TimeSeries(t *testing.T) {
	r := NewReporter()
	base := time.Now().Truncate(time.Second)

	r.RecordResult(RequestResult{Latency: time.Millisecond, Success: true, Timestamp: base})
	r.RecordResult(RequestResult{Latency: 2 * time.Millisecond, Success: true, Timestamp: base})
	r.RecordResult(RequestResult{Latency: 3 * time.Millisecond, Success: false, Timestamp: base.Add(time.Second)})

	report := r.GenerateReport()
	if len(report.TimeSeries) != 2 {
		t.Errorf("expected 2 time series entries, got %d", len(report.TimeSeries))
	}
	if !report.TimeSeries[0].Timestamp.Before(report.TimeSeries[1].Timestamp) {
		t.Error("time series not sorted by timestamp")
	}
}

func TestReporter_GenerateReport_Throughput(t *testing.T) {
	r := NewReporter()
	base := time.Now()

	for i := 0; i < 1000; i++ {
		r.RecordResult(RequestResult{
			Latency:   time.Microsecond,
			Success:   true,
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
		})
	}

	report := r.GenerateReport()
	// 1000 requests in ~999ms ~= 1000 req/s
	if report.DecisionsPerSecond < 900 || report.DecisionsPerSecond > 1100 {
		t.Errorf("expected throughput ~1000 req/s, got %f", report.DecisionsPerSecond)
	}
}

func TestReporter_Concurrent(t *testing.T) {
	r := NewReporter()
	base := time.Now()
	var wg sync.WaitGroup
	const goroutines = 10
	const perGoroutine = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				r.RecordResult(RequestResult{
					Latency:   time.Millisecond,
					Success:   true,
					Timestamp: base.Add(time.Duration(i) * time.Millisecond),
				})
			}
		}(g)
	}
	wg.Wait()

	report := r.GenerateReport()
	expected := goroutines * perGoroutine
	if report.TotalRequests != expected {
		t.Errorf("expected %d requests, got %d", expected, report.TotalRequests)
	}
}

func TestReporter_WriteJSONReport(t *testing.T) {
	r := NewReporter()
	r.RecordResult(RequestResult{
		Latency:   time.Millisecond,
		Success:   true,
		Timestamp: time.Now(),
	})

	dir := t.TempDir()
	filename := filepath.Join(dir, "report.json")
	err := r.WriteJSONReport(r.GenerateReport(), filename)
	if err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.TotalRequests != 1 {
		t.Errorf("expected 1 request in persisted report, got %d", decoded.TotalRequests)
	}
}

func TestReporter_WriteTimeSeries(t *testing.T) {
	r := NewReporter()
	r.RecordResult(RequestResult{
		Latency:   time.Millisecond,
		Success:   true,
		Timestamp: time.Now(),
	})

	dir := t.TempDir()
	filename := filepath.Join(dir, "timeseries.json")
	err := r.WriteTimeSeries(r.GenerateReport(), filename)
	if err != nil {
		t.Fatalf("WriteTimeSeries failed: %v", err)
	}

	if _, err := os.Stat(filename); err != nil {
		t.Errorf("file not created: %v", err)
	}
}
