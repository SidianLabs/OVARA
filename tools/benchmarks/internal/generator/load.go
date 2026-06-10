package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"ovara.tools.benchmarks/internal/report"
)

type ActionRequest struct {
	Action string `json:"action"`
	Payload interface{} `json:"payload"`
}

type LoadGenerator struct {
	target string
	concurrency int
	duration time.Duration
	rampUp time.Duration
	warmupDuration time.Duration
	client *http.Client
	reporter *report.Reporter
}

func NewLoadGenerator(target string, concurrency int, duration, rampUp, warmupDuration time.Duration) *LoadGenerator {
	return &LoadGenerator{
		target: target,
		concurrency: concurrency,
		duration: duration,
		rampUp: rampUp,
		warmupDuration: warmupDuration,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		reporter: report.NewReporter(),
	}
}

func (g *LoadGenerator) GenerateLoad() report.Report {
	fmt.Println("Starting warmup phase...")
	g.runPhase(g.warmupDuration, false)
	
	fmt.Println("Starting main load phase...")
	g.runPhase(g.duration, true)
	
	return g.reporter.GenerateReport()
}

func (g *LoadGenerator) runPhase(duration time.Duration, recordMetrics bool) {
	var wg sync.WaitGroup
	quit := make(chan struct{})
	
	// Start time-based quit
	go func() {
		time.Sleep(duration)
		close(quit)
	}()
	
	// Calculate requests per second based on concurrency
	// Aim for each goroutine to make ~100 requests per second
	requestsPerSecondPerGoroutine := 100
	totalRequestsPerSecond := g.concurrency * requestsPerSecondPerGoroutine
	requestInterval := time.Second / time.Duration(requestsPerSecondPerGoroutine)
	
	// Start worker goroutines with ramp-up
	for i := 0; i < g.concurrency; i++ {
		wg.Add(1)
		go g.worker(&wg, quit, requestInterval, recordMetrics, i)
		
		// Ramp-up delay
		if g.rampUp > 0 && g.concurrency > 1 {
			time.Sleep(g.rampUp / time.Duration(g.concurrency-1))
		}
	}
	
	wg.Wait()
	_ = totalRequestsPerSecond // Used for documentation
}

func (g *LoadGenerator) worker(wg *sync.WaitGroup, quit <-chan struct{}, interval time.Duration, recordMetrics bool, workerID int) {
	defer wg.Done()
	
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
	
	for {
		select {
		case <-quit:
			return
		default:
			start := time.Now()
			action := g.SelectAction(rng)
			success := g.sendRequest(action, rng)
			latency := time.Since(start)
			
			if recordMetrics {
				g.reporter.RecordResult(report.RequestResult{
					Latency: latency,
					Success: success,
					Timestamp: time.Now(),
				})
			}
			
			time.Sleep(interval)
		}
	}
}

func (g *LoadGenerator) SelectAction(rng *rand.Rand) ActionRequest {
	// Traffic distribution:
	// shell:echo test (local, 40%)
	// git.pull (dev, 30%)
	// git.push (staging, 20%)
	// exec:ls (local, 10%)
	
	r := rng.Intn(100)
	
	switch {
	case r < 40: // 40%
		return ActionRequest{
			Action: "shell:echo test",
			Payload: map[string]interface{}{
				"environment": "local",
				"command": "echo test",
			},
		}
	case r < 70: // 30%
		return ActionRequest{
			Action: "git.pull",
			Payload: map[string]interface{}{
				"environment": "dev",
				"repository": "ovara-main",
			},
		}
	case r < 90: // 20%
		return ActionRequest{
			Action: "git.push",
			Payload: map[string]interface{}{
				"environment": "staging",
				"repository": "ovara-main",
				"branch": "feature/benchmark",
			},
		}
	default: // 10%
		return ActionRequest{
			Action: "exec:ls",
			Payload: map[string]interface{}{
				"environment": "local",
				"command": "ls -la",
			},
		}
	}
}

func (g *LoadGenerator) sendRequest(action ActionRequest, rng *rand.Rand) bool {
	payload, err := json.Marshal(action)
	if err != nil {
		return false
	}
	
	url := fmt.Sprintf("%s/v1/runtime/check", g.target)
	
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (g *LoadGenerator) GetReporter() *report.Reporter {
	return g.reporter
}