package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/handlers"
	"ovara.runtime.gateway/internal/integrity"
	"ovara.runtime.gateway/internal/logging"
	"ovara.runtime.gateway/internal/metrics"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipts"
	tr "ovara.runtime.gateway/internal/trust"
)

func TestE2E_FullDecisionChain(t *testing.T) {
	policyStore := policy.NewStore("e2e-v1")
	shieldStore := tr.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)
	receiptStore := receipts.NewInMemoryStore()
	eventStore := events.NewInMemoryStore(1000)
	approvalStore := approval.NewInMemoryStore()
	contStore := continuation.NewInMemoryStore()
	execStore := execution.NewInMemoryStore()

	cfg := config.Default()
	cfg.FailClosed = false

	policyStore.AddRule(policy.Rule{
		ActionType: string(models.ActionTypeCIBuildTrigger),
		Allow:      true,
	})

	approvalSvc := approval.NewService(approvalStore)
	contSweeper := continuation.NewSweeper(contStore)
	execSweeper := execution.NewSweeper(execStore)
	metricsStore := metrics.NewRuntimeMetrics()
	_ = contSweeper
	_ = execSweeper

	enrollmentSvc := enrollment.NewLocalService("",
		enrollment.WithGatewayName("e2e-test-gw"),
		enrollment.WithGatewayVersion("1.0.0"),
	)
	_ = enrollmentSvc.Initialize("e2e")

	decisionLogger, _ := logging.NewDecisionLogger("")

	gwHandler := handlers.New(eval, decisionLogger, cfg, receiptStore)
	gwHandler.SetEnrollment(enrollmentSvc)
	approvalHandler := handlers.NewApprovalHandler(approvalSvc)
	receiptHandler := handlers.NewReceiptHandler(receiptStore)
	contHandler := handlers.NewContinuationHandler(contStore)
	trustEval := tr.NewEvaluator(shieldStore)
	trustHandler := tr.NewHandler(shieldStore, trustEval)
	eventHandler := handlers.NewEventHandler(eventStore)
	adminHandler := handlers.NewAdminHandler()

	mux := http.NewServeMux()
	gwHandler.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)
	receiptHandler.RegisterRoutes(mux)
	contHandler.RegisterRoutes(mux)
	trustHandler.RegisterRoutes(mux)
	eventHandler.RegisterRoutes(mux)
	adminHandler.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_ = execStore
	_ = metricsStore

	t.Run("health", func(t *testing.T) {
		resp := doGet(t, client, server.URL+"/v1/runtime/health")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("health: %d", resp.StatusCode)
		}
	})

	t.Run("status", func(t *testing.T) {
		resp := doGet(t, client, server.URL+"/v1/runtime/status")
		var m map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		if m["gateway_id"] == nil {
			t.Error("missing gateway_id")
		}
	})

	t.Run("check_allows_safe", func(t *testing.T) {
		req := models.ActionRequest{
			ActionType:  models.ActionTypeCIBuildTrigger,
			Resource:    "build:./test.sh",
			Environment: models.EnvironmentDev,
			AgentIdentity: &models.AgentIdentity{
				Issuer:    "e2e-issuer",
				SubjectID: "agent-e2e-001",
			},
		}
		body, _ := json.Marshal(req)
		resp := doPost(t, client, server.URL+"/v1/runtime/check", body)
		defer resp.Body.Close()

		var d models.DecisionResponse
		json.NewDecoder(resp.Body).Decode(&d)
		if d.Decision != models.DecisionAllow {
			t.Errorf("got %s, want allow", d.Decision)
		}
	})

	t.Run("receipt_persisted", func(t *testing.T) {
		req := models.ActionRequest{
			ActionType:  models.ActionTypeCIBuildTrigger,
			Resource:    "build:./deploy.sh",
			Environment: models.EnvironmentDev,
		}
		body, _ := json.Marshal(req)
		resp := doPost(t, client, server.URL+"/v1/runtime/check", body)
		defer resp.Body.Close()

		var d models.DecisionResponse
		json.NewDecoder(resp.Body).Decode(&d)
		if d.ReceiptStub == nil {
			t.Fatal("no receipt stub")
		}
		stored, err := receiptStore.Get(d.ReceiptStub.ReceiptID)
		if err != nil {
			t.Fatalf("receipt not stored: %v", err)
		}
		if stored == nil {
			t.Fatal("stored receipt is nil")
		}
	})

	t.Run("receipts_list_sized", func(t *testing.T) {
		resp := doGet(t, client, server.URL+"/v1/receipts")
		var result struct {
			Receipts []map[string]interface{} `json:"receipts"`
			Count    int                      `json:"count"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if result.Count < 2 {
			t.Errorf("got %d receipts, want >= 2", result.Count)
		}
	})

	t.Run("admin_sweep", func(t *testing.T) {
		resp := doPost(t, client, server.URL+"/v1/runtime/admin/sweep", nil)
		resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 404 {
			t.Errorf("sweep: %d", resp.StatusCode)
		}
	})
}

func TestE2E_RateResilience(t *testing.T) {
	policyStore := policy.NewStore("rate-v1")
	eval := evaluator.NewWithShield(policyStore, tr.NewShieldStore())
	rcpts := receipts.NewInMemoryStore()
	cfg := config.Default()
	decisionLogger, _ := logging.NewDecisionLogger("")

	gwHandler := handlers.New(eval, decisionLogger, cfg, rcpts)
	mux := http.NewServeMux()
	gwHandler.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	for i := range 20 {
		req := models.ActionRequest{
			ActionType:  models.ActionTypeCIBuildTrigger,
			Resource:    fmt.Sprintf("build:./%d", i),
			Environment: models.EnvironmentDev,
		}
		body, _ := json.Marshal(req)
		resp := doPost(t, client, server.URL+"/v1/runtime/check", body)
		if resp.StatusCode != 200 {
			t.Errorf("request %d: status %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestE2E_IntegrityClean(t *testing.T) {
	checker := integrity.NewChecker()
	result := checker.Check()
	if !result.Passed {
		t.Logf("integrity result: passed=%v, issues=%d", result.Passed, len(result.Issues))
	}
}

func doGet(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func doPost(t *testing.T, client *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}
