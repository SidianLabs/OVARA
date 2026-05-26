package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestDecisionLogger_LogWritesEntryWithElapsedMs(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "decisions.jsonl")

	logger, err := NewDecisionLogger(logFile)
	if err != nil {
		t.Fatalf("NewDecisionLogger failed: %v", err)
	}
	defer logger.Close()

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:pwd",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "test",
			SubjectID: "agent-001",
		},
	}
	resp := &models.DecisionResponse{
		DecisionID: "dec_test123",
		Decision:   models.DecisionAllow,
		TrustScore: 0.9,
		ReceiptStub: &models.ReceiptStub{
			ReceiptID: "rcpt_abc",
		},
	}

	err = logger.Log(req, resp, 15)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var entry DecisionLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to unmarshal log entry: %v", err)
	}

	if entry.ElapsedMs != 15 {
		t.Errorf("elapsed_ms = %d, want 15", entry.ElapsedMs)
	}
	if entry.DecisionID != "dec_test123" {
		t.Errorf("decision_id = %s, want dec_test123", entry.DecisionID)
	}
	if entry.ReceiptID != "rcpt_abc" {
		t.Errorf("receipt_id = %s, want rcpt_abc", entry.ReceiptID)
	}
	if entry.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestDecisionLogger_LogWithApprovalID(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "decisions.jsonl")

	logger, err := NewDecisionLogger(logFile)
	if err != nil {
		t.Fatalf("NewDecisionLogger failed: %v", err)
	}
	defer logger.Close()

	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentDev,
	}
	resp := &models.DecisionResponse{
		DecisionID: "dec_xyz",
		Decision:   models.DecisionEscalate,
		ApprovalID:  "apr_123",
	}

	err = logger.Log(req, resp, 8)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var entry DecisionLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to unmarshal log entry: %v", err)
	}

	if entry.ApprovalID != "apr_123" {
		t.Errorf("approval_id = %s, want apr_123", entry.ApprovalID)
	}
	if entry.ElapsedMs != 8 {
		t.Errorf("elapsed_ms = %d, want 8", entry.ElapsedMs)
	}
}

func TestDecisionLogger_LogZeroElapsed(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "decisions.jsonl")

	logger, err := NewDecisionLogger(logFile)
	if err != nil {
		t.Fatalf("NewDecisionLogger failed: %v", err)
	}
	defer logger.Close()

	req := &models.ActionRequest{ActionType: models.ActionTypeShell, Resource: "shell:test"}
	resp := &models.DecisionResponse{DecisionID: "dec_fast", Decision: models.DecisionAllow}

	err = logger.Log(req, resp, 0)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var entry DecisionLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to unmarshal log entry: %v", err)
	}

	if entry.ElapsedMs != 0 {
		t.Errorf("elapsed_ms = %d, want 0", entry.ElapsedMs)
	}
}

func TestDecisionLogger_LogEntryTimestampIsRecent(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "decisions.jsonl")

	logger, _ := NewDecisionLogger(logFile)
	defer logger.Close()

	before := time.Now().UTC()
	logger.Log(&models.ActionRequest{ActionType: models.ActionTypeShell, Resource: "shell:x"}, &models.DecisionResponse{DecisionID: "dec", Decision: models.DecisionAllow}, 1)
	after := time.Now().UTC()

	data, _ := os.ReadFile(logFile)
	var entry DecisionLogEntry
	json.Unmarshal(data, &entry)

	if entry.Timestamp.Before(before) || entry.Timestamp.After(after) {
		t.Error("timestamp not in expected window")
	}
}