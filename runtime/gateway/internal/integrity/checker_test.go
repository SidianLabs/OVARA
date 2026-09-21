package integrity

import (
	"testing"
	"time"
)

func TestNewChecker(t *testing.T) {
	c := NewChecker()
	if c == nil {
		t.Fatal("NewChecker returned nil")
	}
}

func TestChecker_SetGatewayInfo(t *testing.T) {
	c := NewChecker()
	c.SetGatewayInfo("gw-test-123", "1.2.3")

	if c.gatewayID != "gw-test-123" {
		t.Errorf("gatewayID = %v, want gw-test-123", c.gatewayID)
	}
	if c.gatewayVersion != "1.2.3" {
		t.Errorf("gatewayVersion = %v, want 1.2.3", c.gatewayVersion)
	}
}

func TestChecker_Check_Empty(t *testing.T) {
	c := NewChecker()
	result := c.Check()

	if !result.Passed {
		t.Error("empty checker should pass")
	}
	if len(result.Issues) != 0 {
		t.Errorf("issues = %v, want empty", result.Issues)
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warnings for unconfigured stores")
	}
}

func TestChecker_Check_VersionInfo(t *testing.T) {
	c := NewChecker()
	c.SetGatewayInfo("gw-abc", "2.0.0")

	result := c.Check()

	if result.VersionInfo["gateway_id"] != "gw-abc" {
		t.Errorf("version_info[gateway_id] = %v", result.VersionInfo["gateway_id"])
	}
	if result.VersionInfo["gateway_version"] != "2.0.0" {
		t.Errorf("version_info[gateway_version] = %v", result.VersionInfo["gateway_version"])
	}
}

func TestChecker_Check_NoStores(t *testing.T) {
	c := NewChecker()
	result := c.Check()

	if !result.Passed {
		t.Error("checker with no stores should pass")
	}
	if len(result.StoreStats) != 0 {
		t.Errorf("store stats should be empty, got %v", result.StoreStats)
	}
}

func TestResult_Fields(t *testing.T) {
	now := time.Now().UTC()
	result := Result{
		Timestamp: now,
		Passed:    true,
		Issues: []Issue{
			{Code: "TEST", Severity: "high", Category: "test", Message: "test issue"},
		},
		Warnings: []Warning{
			{Code: "WARN", Severity: "low", Category: "test", Message: "test warning"},
		},
		Summary: Summary{
			TotalIssues:   1,
			TotalWarnings: 1,
			Critical:     0,
			High:         1,
			Medium:       0,
			Low:          0,
		},
		StoreStats:  map[string]int{"events": 10, "receipts": 5},
		VersionInfo: map[string]string{"gateway_id": "gw-test", "version": "1.0"},
	}

	if result.Timestamp != now {
		t.Errorf("timestamp mismatch")
	}
	if !result.Passed {
		t.Error("result should pass")
	}
	if len(result.Issues) != 1 {
		t.Errorf("issues count = %d, want 1", len(result.Issues))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("warnings count = %d, want 1", len(result.Warnings))
	}
	if result.Summary.TotalIssues != 1 {
		t.Errorf("summary total issues = %d, want 1", result.Summary.TotalIssues)
	}
	if result.StoreStats["events"] != 10 {
		t.Errorf("store_stats[events] = %d, want 10", result.StoreStats["events"])
	}
	if result.VersionInfo["gateway_id"] != "gw-test" {
		t.Errorf("version_info[gateway_id] = %v", result.VersionInfo["gateway_id"])
	}
}

func TestIssue_Fields(t *testing.T) {
	issue := Issue{
		Code:       "EVT_DUP",
		Severity:   "high",
		Category:   "event_store",
		Message:    "found duplicate event IDs",
		EntityID:   "event-123",
		EntityType: "event",
		Detail:     "duplicate IDs: [e1, e2]",
	}

	if issue.Code != "EVT_DUP" {
		t.Errorf("code = %v, want EVT_DUP", issue.Code)
	}
	if issue.Severity != "high" {
		t.Errorf("severity = %v, want high", issue.Severity)
	}
	if issue.Category != "event_store" {
		t.Errorf("category = %v, want event_store", issue.Category)
	}
	if issue.Message != "found duplicate event IDs" {
		t.Errorf("message = %v", issue.Message)
	}
	if issue.EntityID != "event-123" {
		t.Errorf("entity_id = %v", issue.EntityID)
	}
	if issue.EntityType != "event" {
		t.Errorf("entity_type = %v", issue.EntityType)
	}
	if issue.Detail != "duplicate IDs: [e1, e2]" {
		t.Errorf("detail = %v", issue.Detail)
	}
}

func TestWarning_Fields(t *testing.T) {
	warning := Warning{
		Code:       "CONT_ORPHAN_APPR",
		Severity:   "low",
		Category:   "continuation_store",
		Message:    "found continuations with approval IDs in non-approval states",
		EntityID:   "cnt-456",
		EntityType: "continuation",
		Detail:     "examples: [cnt-1]",
	}

	if warning.Code != "CONT_ORPHAN_APPR" {
		t.Errorf("code = %v, want CONT_ORPHAN_APPR", warning.Code)
	}
	if warning.Severity != "low" {
		t.Errorf("severity = %v, want low", warning.Severity)
	}
	if warning.Category != "continuation_store" {
		t.Errorf("category = %v, want continuation_store", warning.Category)
	}
	if warning.EntityID != "cnt-456" {
		t.Errorf("entity_id = %v", warning.EntityID)
	}
}

func TestSummary_AllSeverities(t *testing.T) {
	summary := Summary{
		TotalIssues:   4,
		TotalWarnings: 3,
		Critical:     1,
		High:         2,
		Medium:       1,
		Low:          0,
	}

	if summary.TotalIssues != 4 {
		t.Errorf("total issues = %d, want 4", summary.TotalIssues)
	}
	if summary.TotalWarnings != 3 {
		t.Errorf("total warnings = %d, want 3", summary.TotalWarnings)
	}
	if summary.Critical != 1 {
		t.Errorf("critical = %d, want 1", summary.Critical)
	}
	if summary.High != 2 {
		t.Errorf("high = %d, want 2", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("medium = %d, want 1", summary.Medium)
	}
	if summary.Low != 0 {
		t.Errorf("low = %d, want 0", summary.Low)
	}
}

func TestMin(t *testing.T) {
	if min(1, 2) != 1 {
		t.Errorf("min(1, 2) = %d, want 1", min(1, 2))
	}
	if min(2, 1) != 1 {
		t.Errorf("min(2, 1) = %d, want 1", min(2, 1))
	}
	if min(5, 5) != 5 {
		t.Errorf("min(5, 5) = %d, want 5", min(5, 5))
	}
	if min(0, 1) != 0 {
		t.Errorf("min(0, 1) = %d, want 0", min(0, 1))
	}
	if min(-1, -2) != -2 {
		t.Errorf("min(-1, -2) = %d, want -2", min(-1, -2))
	}
}

func TestChecker_Check_ResultTimestamp(t *testing.T) {
	c := NewChecker()
	before := time.Now().UTC()
	result := c.Check()
	after := time.Now().UTC()

	if result.Timestamp.Before(before) || result.Timestamp.After(after) {
		t.Errorf("timestamp outside expected range: %v", result.Timestamp)
	}
}

func TestChecker_Check_StoreStatsInitialized(t *testing.T) {
	c := NewChecker()
	result := c.Check()

	if result.StoreStats == nil {
		t.Error("StoreStats should not be nil")
	}
	if result.VersionInfo == nil {
		t.Error("VersionInfo should not be nil")
	}
}

func TestIssue_SeverityValues(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		issue := Issue{Severity: sev}
		if issue.Severity != sev {
			t.Errorf("severity = %v, want %v", issue.Severity, sev)
		}
	}
}

func TestWarning_SeverityValues(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		warning := Warning{Severity: sev}
		if warning.Severity != sev {
			t.Errorf("severity = %v, want %v", warning.Severity, sev)
		}
	}
}