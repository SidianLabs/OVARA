package generator

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewLoadGenerator(t *testing.T) {
	g := NewLoadGenerator("http://localhost:8080", 5, time.Second, 100*time.Millisecond, 50*time.Millisecond)
	if g == nil {
		t.Fatal("NewLoadGenerator returned nil")
	}
	if g.target != "http://localhost:8080" {
		t.Errorf("expected target = http://localhost:8080, got %s", g.target)
	}
	if g.concurrency != 5 {
		t.Errorf("expected concurrency = 5, got %d", g.concurrency)
	}
	if g.client == nil {
		t.Error("http client not initialized")
	}
	if g.client.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", g.client.Timeout)
	}
	if g.reporter == nil {
		t.Error("reporter not initialized")
	}
}

func TestSelectAction_ShellEcho(t *testing.T) {
	g := NewLoadGenerator("http://localhost:8080", 1, time.Second, 0, 0)
	rng := rand.New(rand.NewSource(42))

	// Sample many times to verify all action types are present
	actionCounts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		action := g.SelectAction(rng)
		key := action.Action
		actionCounts[key]++
	}

	expectedActions := []string{
		"shell:echo test",
		"git.pull",
		"git.push",
		"exec:ls",
	}
	for _, expected := range expectedActions {
		if actionCounts[expected] == 0 {
			t.Errorf("expected action %s to appear, got 0 occurrences", expected)
		}
	}
}

func TestSelectAction_ShellEcho_Distribution(t *testing.T) {
	g := NewLoadGenerator("http://localhost:8080", 1, time.Second, 0, 0)
	rng := rand.New(rand.NewSource(1))

	const samples = 10000
	shellCount := 0
	for i := 0; i < samples; i++ {
		action := g.SelectAction(rng)
		if strings.HasPrefix(action.Action, "shell:") {
			shellCount++
		}
	}

	// Shell should be ~40% of traffic
	ratio := float64(shellCount) / float64(samples)
	if ratio < 0.35 || ratio > 0.45 {
		t.Errorf("expected shell ~40%%, got %f (count=%d)", ratio, shellCount)
	}
}

func TestActionRequest_JSONMarshal(t *testing.T) {
	action := ActionRequest{
		Action: "shell:echo hello",
		Payload: map[string]interface{}{
			"environment": "local",
			"command":     "echo hello",
		},
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded["action"] != "shell:echo hello" {
		t.Errorf("expected action=shell:echo hello, got %v", decoded["action"])
	}
}

func TestSendRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer server.Close()

	g := NewLoadGenerator(server.URL, 1, time.Second, 0, 0)
	rng := rand.New(rand.NewSource(1))

	success := g.sendRequest(ActionRequest{Action: "shell:echo"}, rng)
	if !success {
		t.Error("expected success=true for 200 response")
	}
}

func TestSendRequest_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	g := NewLoadGenerator(server.URL, 1, time.Second, 0, 0)
	rng := rand.New(rand.NewSource(1))

	success := g.sendRequest(ActionRequest{Action: "shell:echo"}, rng)
	if success {
		t.Error("expected success=false for 500 response")
	}
}

func TestSendRequest_ClientError(t *testing.T) {
	g := NewLoadGenerator("http://localhost:1", 1, time.Second, 0, 0)
	rng := rand.New(rand.NewSource(1))

	success := g.sendRequest(ActionRequest{Action: "shell:echo"}, rng)
	if success {
		t.Error("expected success=false for connection error")
	}
}

func TestGenerateLoad_RecordsMetrics(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer server.Close()

	g := NewLoadGenerator(server.URL, 2, 200*time.Millisecond, 0, 0)
	_ = g.GenerateLoad()

	report := g.GetReporter().GenerateReport()
	if report.TotalRequests == 0 {
		t.Error("expected at least one recorded request")
	}
	if report.TotalSuccesses == 0 {
		t.Error("expected at least one success")
	}
	if atomic.LoadInt64(&requestCount) == 0 {
		t.Error("server received no requests")
	}
}

func TestGetReporter(t *testing.T) {
	g := NewLoadGenerator("http://localhost:8080", 1, time.Second, 0, 0)
	reporter := g.GetReporter()
	if reporter == nil {
		t.Fatal("GetReporter returned nil")
	}
	if reporter != g.reporter {
		t.Error("GetReporter did not return internal reporter")
	}
}
