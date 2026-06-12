package report

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

type RequestResult struct {
	Latency time.Duration
	Success bool
	Timestamp time.Time
}

type SecondMetrics struct {
	Timestamp time.Time
	Requests int
	Successes int
	Errors int
	Latencies []time.Duration
}

type Report struct {
	StartTime time.Time
	EndTime time.Time
	Duration time.Duration
	TotalRequests int
	TotalSuccesses int
	TotalErrors int
	DecisionsPerSecond float64
	P50Latency time.Duration
	P95Latency time.Duration
	P99Latency time.Duration
	AverageLatency time.Duration
	ErrorRate float64
	MemoryUsageMB float64
	TimeSeries []SecondMetrics
}

type Reporter struct {
	mu sync.Mutex
	results []RequestResult
	secondMap map[int64]*SecondMetrics
	startTime time.Time
}

func NewReporter() *Reporter {
	return &Reporter{
		results: make([]RequestResult, 0),
		secondMap: make(map[int64]*SecondMetrics),
		startTime: time.Now(),
	}
}

func (r *Reporter) RecordResult(result RequestResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.results = append(r.results, result)
	
	secondKey := result.Timestamp.Unix() - r.startTime.Unix()
	if _, exists := r.secondMap[secondKey]; !exists {
		r.secondMap[secondKey] = &SecondMetrics{
			Timestamp: result.Timestamp.Truncate(time.Second),
			Latencies: make([]time.Duration, 0),
		}
	}
	
	sm := r.secondMap[secondKey]
	sm.Requests++
	if result.Success {
		sm.Successes++
	} else {
		sm.Errors++
	}
	sm.Latencies = append(sm.Latencies, result.Latency)
}

func (r *Reporter) GenerateReport() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	report := Report{
		TotalRequests: len(r.results),
	}
	
	if len(r.results) > 0 {
		earliest := r.results[0].Timestamp
		latest := r.results[0].Timestamp
		for _, result := range r.results {
			if result.Timestamp.Before(earliest) {
				earliest = result.Timestamp
			}
			if result.Timestamp.After(latest) {
				latest = result.Timestamp
			}
		}
		report.StartTime = earliest
		report.EndTime = latest
	} else {
		report.StartTime = r.startTime
		report.EndTime = time.Now()
	}
	
	report.Duration = report.EndTime.Sub(report.StartTime)
	
	if report.Duration.Seconds() > 0 {
		report.DecisionsPerSecond = float64(report.TotalRequests) / report.Duration.Seconds()
	}
	
	latencies := make([]time.Duration, 0, len(r.results))
	for _, result := range r.results {
		latencies = append(latencies, result.Latency)
		if result.Success {
			report.TotalSuccesses++
		} else {
			report.TotalErrors++
		}
	}
	
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		report.P50Latency = latencies[len(latencies)*50/100]
		report.P95Latency = latencies[len(latencies)*95/100]
		report.P99Latency = latencies[len(latencies)*99/100]

		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		report.AverageLatency = total / time.Duration(len(latencies))
	}
	
	if report.TotalRequests > 0 {
		report.ErrorRate = float64(report.TotalErrors) / float64(report.TotalRequests) * 100
	}
	
	// Get memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	report.MemoryUsageMB = float64(m.Alloc) / 1024 / 1024
	
	// Build time series
	report.TimeSeries = make([]SecondMetrics, 0, len(r.secondMap))
	for _, sm := range r.secondMap {
		report.TimeSeries = append(report.TimeSeries, *sm)
	}
	sort.Slice(report.TimeSeries, func(i, j int) bool {
		return report.TimeSeries[i].Timestamp.Before(report.TimeSeries[j].Timestamp)
	})
	
	return report
}

func (r *Reporter) PrintSummary(report Report) {
	fmt.Printf("\n=== Ovara Gateway Benchmark Results ===\n")
	fmt.Printf("Duration: %v\n", report.Duration.Round(time.Millisecond))
	fmt.Printf("Total Requests: %d\n", report.TotalRequests)
	fmt.Printf("Decisions/sec: %.2f\n", report.DecisionsPerSecond)
	fmt.Printf("Successes: %d\n", report.TotalSuccesses)
	fmt.Printf("Errors: %d (%.2f%%)\n", report.TotalErrors, report.ErrorRate)
	fmt.Printf("\nLatency Percentiles:\n")
	fmt.Printf("  p50: %v\n", report.P50Latency.Round(time.Microsecond))
	fmt.Printf("  p95: %v\n", report.P95Latency.Round(time.Microsecond))
	fmt.Printf("  p99: %v\n", report.P99Latency.Round(time.Microsecond))
	fmt.Printf("  avg: %v\n", report.AverageLatency.Round(time.Microsecond))
	fmt.Printf("\nMemory Usage: %.2f MB\n", report.MemoryUsageMB)
	fmt.Printf("=======================================\n\n")
}

func (r *Reporter) WriteJSONReport(report Report, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	
	return os.WriteFile(filename, data, 0644)
}

func (r *Reporter) WriteTimeSeries(report Report, filename string) error {
	data, err := json.MarshalIndent(report.TimeSeries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal time series: %w", err)
	}
	
	return os.WriteFile(filename, data, 0644)
}