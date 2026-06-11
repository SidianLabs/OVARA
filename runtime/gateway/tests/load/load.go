package load

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	Latencies       []time.Duration
	StartTime       time.Time
	EndTime         time.Time
}

type LatencyPercentiles struct {
	P50  time.Duration
	P95  time.Duration
	P99  time.Duration
	Avg  time.Duration
	Min  time.Duration
	Max  time.Duration
}

type LoadConfig struct {
	Target      string
	Duration    time.Duration
	Concurrency int
	RampUp      time.Duration
	Warmup      time.Duration
}

func generateRequest() map[string]interface{} {
	actions := []struct {
		actionType string
		resource   string
		env        string
		weight     int
	}{
		{"shell", "shell:echo test", "local", 40},
		{"git.pull", "git:origin/main", "dev", 30},
		{"git.push", "git:origin/main", "staging", 20},
		{"exec", "exec:ls", "local", 10},
	}

	r := time.Now().UnixNano() % 100
	cumulative := 0
	for _, a := range actions {
		cumulative += a.weight
		if int(r) < cumulative {
			return map[string]interface{}{
				"action_type": a.actionType,
				"resource":    a.resource,
				"environment": a.env,
			}
		}
	}
	return map[string]interface{}{
		"action_type": "shell",
		"resource":    "shell:echo test",
		"environment": "local",
	}
}

func RunLoadTest(config LoadConfig) *Metrics {
	metrics := &Metrics{
		Latencies: make([]time.Duration, 0, 10000),
	}

	if config.Warmup > 0 {
		warmup(config)
	}

	metrics.StartTime = time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			deadline := metrics.StartTime.Add(config.Duration)
			for time.Now().Before(deadline) {
				start := time.Now()
				err := sendRequest(config.Target)
				latency := time.Since(start)

				atomic.AddInt64(&metrics.TotalRequests, 1)
				if err == nil {
					atomic.AddInt64(&metrics.SuccessRequests, 1)
				} else {
					atomic.AddInt64(&metrics.FailedRequests, 1)
				}

				mu.Lock()
				metrics.Latencies = append(metrics.Latencies, latency)
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	metrics.EndTime = time.Now()
	return metrics
}

func warmup(config LoadConfig) {
	var wg sync.WaitGroup
	for i := 0; i < min(config.Concurrency/2, 10); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(config.Warmup)
			for time.Now().Before(deadline) {
				sendRequest(config.Target)
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

func sendRequest(target string) error {
	body, _ := json.Marshal(generateRequest())
	resp, err := http.Post(target+"/v1/runtime/check", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func CalculatePercentiles(latencies []time.Duration) LatencyPercentiles {
	if len(latencies) == 0 {
		return LatencyPercentiles{}
	}

	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, l := range sorted {
		total += l
	}

	return LatencyPercentiles{
		P50: sorted[len(sorted)*50/100],
		P95: sorted[len(sorted)*95/100],
		P99: sorted[len(sorted)*99/100],
		Avg: total / time.Duration(len(sorted)),
		Min: sorted[0],
		Max: sorted[len(sorted)-1],
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Report struct {
	DecisionsPerSec float64
	Latency         LatencyPercentiles
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	ErrorRate       float64
	Duration        time.Duration
}

func GenerateReport(metrics *Metrics) *Report {
	duration := metrics.EndTime.Sub(metrics.StartTime)
	latency := CalculatePercentiles(metrics.Latencies)

	var errorRate float64
	if metrics.TotalRequests > 0 {
		errorRate = float64(metrics.FailedRequests) / float64(metrics.TotalRequests) * 100
	}

	dps := float64(metrics.TotalRequests) / duration.Seconds()

	return &Report{
		DecisionsPerSec: math.Round(dps*100) / 100,
		Latency:         latency,
		TotalRequests:   metrics.TotalRequests,
		SuccessRequests: metrics.SuccessRequests,
		FailedRequests:  metrics.FailedRequests,
		ErrorRate:       math.Round(errorRate*100) / 100,
		Duration:        duration,
	}
}

func NewTestServer(handler http.Handler) *httptest.Server {
	return httptest.NewServer(handler)
}
