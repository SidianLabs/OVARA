package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.services.alerting/internal/models"
)

func newTestAlert() *models.Alert {
	return &models.Alert{
		ID:             "alert_test-123",
		Severity:       models.SeverityHigh,
		Type:           models.AlertTypeAnomaly,
		AgentID:        "agt-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		Action:         "shell.execute",
		Resource:       "sudo",
		TrustScore:     0.3,
		Message:        "test anomaly",
		Timestamp:      time.Now().UTC(),
		State:          models.AlertStateNew,
	}
}

func newTestRule() *models.AlertRule {
	return &models.AlertRule{
		ID:            "rule-001",
		Name:          "Low Trust Alert",
		Condition:     models.ConditionTrustBelow,
		Threshold:     0.5,
		WindowSeconds: 300,
		Severity:      models.SeverityCritical,
		Enabled:       true,
	}
}

func TestCreateAndGetAlert(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestAlert()

	if err := s.CreateAlert(a); err != nil {
		t.Fatalf("CreateAlert failed: %v", err)
	}

	got, err := s.GetAlert(a.ID)
	if err != nil {
		t.Fatalf("GetAlert failed: %v", err)
	}
	if got.Type != a.Type {
		t.Errorf("Type = %v, want %v", got.Type, a.Type)
	}
	if got.State != models.AlertStateNew {
		t.Errorf("State = %v, want %v", got.State, models.AlertStateNew)
	}
}

func TestCreateAlertMaxSize(t *testing.T) {
	s := NewMemoryStore(2)
	s.CreateAlert(newTestAlert())
	s.CreateAlert(newTestAlert())

	a3 := newTestAlert()
	a3.ID = "alert-extra"
	if err := s.CreateAlert(a3); err != nil {
		t.Fatalf("expected eviction, got error: %v", err)
	}
	if s.Count() > 2 {
		t.Errorf("expected max 2 alerts, got %d", s.Count())
	}
}

func TestGetAlertNotFound(t *testing.T) {
	s := NewMemoryStore(100)
	_, err := s.GetAlert("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestAlert()
	s.CreateAlert(a)

	err := s.AcknowledgeAlert(a.ID, "admin")
	if err != nil {
		t.Fatalf("AcknowledgeAlert failed: %v", err)
	}

	got, _ := s.GetAlert(a.ID)
	if got.State != models.AlertStateAcknowledged {
		t.Errorf("State = %v, want acknowledged", got.State)
	}
	if got.AcknowledgedBy != "admin" {
		t.Errorf("AcknowledgedBy = %v, want admin", got.AcknowledgedBy)
	}
}

func TestAcknowledgeAlreadyAcknowledged(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestAlert()
	s.CreateAlert(a)

	s.AcknowledgeAlert(a.ID, "admin")
	err := s.AcknowledgeAlert(a.ID, "admin2")
	if err == nil {
		t.Error("expected already acknowledged error")
	}
}

func TestResolveAlert(t *testing.T) {
	s := NewMemoryStore(100)
	a := newTestAlert()
	s.CreateAlert(a)

	err := s.ResolveAlert(a.ID)
	if err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}

	got, _ := s.GetAlert(a.ID)
	if got.State != models.AlertStateResolved {
		t.Errorf("State = %v, want resolved", got.State)
	}
	if got.ResolvedAt == nil {
		t.Error("ResolvedAt should not be nil")
	}
}

func TestListAlertsBySeverity(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestAlert()
	a1.ID = "alert-crit"
	a1.Severity = models.SeverityCritical
	s.CreateAlert(a1)

	a2 := newTestAlert()
	a2.ID = "alert-low"
	a2.Severity = models.SeverityLow
	s.CreateAlert(a2)

	critical, _ := s.ListAlerts(models.AlertFilter{Severity: models.SeverityCritical})
	if len(critical) != 1 {
		t.Errorf("expected 1 critical, got %d", len(critical))
	}

	low, _ := s.ListAlerts(models.AlertFilter{Severity: models.SeverityLow})
	if len(low) != 1 {
		t.Errorf("expected 1 low, got %d", len(low))
	}
}

func TestListAlertsByState(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestAlert()
	a1.ID = "alert-new-1"
	a1.State = models.AlertStateNew
	s.CreateAlert(a1)

	a2 := newTestAlert()
	a2.ID = "alert-ack-1"
	a2.State = models.AlertStateAcknowledged
	s.CreateAlert(a2)

	newAlerts, _ := s.ListAlerts(models.AlertFilter{State: models.AlertStateNew})
	if len(newAlerts) != 1 {
		t.Errorf("expected 1 new alert, got %d", len(newAlerts))
	}
}

func TestGetUnacknowledged(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestAlert()
	a1.ID = "alert-unack"
	a1.State = models.AlertStateNew
	s.CreateAlert(a1)

	a2 := newTestAlert()
	a2.ID = "alert-ack"
	a2.State = models.AlertStateAcknowledged
	s.CreateAlert(a2)

	unack := s.GetUnacknowledged()
	if len(unack) != 1 {
		t.Errorf("expected 1 unacknowledged, got %d", len(unack))
	}
}

func TestCountBySeverity(t *testing.T) {
	s := NewMemoryStore(100)

	a1 := newTestAlert()
	a1.ID = "alert-c1"
	a1.Severity = models.SeverityCritical
	s.CreateAlert(a1)

	a2 := newTestAlert()
	a2.ID = "alert-c2"
	a2.Severity = models.SeverityCritical
	s.CreateAlert(a2)

	a3 := newTestAlert()
	a3.ID = "alert-l1"
	a3.Severity = models.SeverityLow
	s.CreateAlert(a3)

	counts := s.CountBySeverity()
	if counts[models.SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[models.SeverityCritical])
	}
	if counts[models.SeverityLow] != 1 {
		t.Errorf("expected 1 low, got %d", counts[models.SeverityLow])
	}
}

func TestCreateAndGetRule(t *testing.T) {
	s := NewMemoryStore(100)
	r := newTestRule()

	if err := s.CreateRule(r); err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	got, err := s.GetRule(r.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}
	if got.Name != r.Name {
		t.Errorf("Name = %v, want %v", got.Name, r.Name)
	}
}

func TestCreateDuplicateRule(t *testing.T) {
	s := NewMemoryStore(100)
	r := newTestRule()

	s.CreateRule(r)
	err := s.CreateRule(r)
	if err == nil {
		t.Error("expected duplicate error")
	}
}

func TestUpdateRule(t *testing.T) {
	s := NewMemoryStore(100)
	r := newTestRule()
	s.CreateRule(r)

	r.Name = "Updated Rule"
	r.Threshold = 0.3
	err := s.UpdateRule(r)
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	got, _ := s.GetRule(r.ID)
	if got.Name != "Updated Rule" {
		t.Errorf("Name = %v, want Updated Rule", got.Name)
	}
	if got.Threshold != 0.3 {
		t.Errorf("Threshold = %v, want 0.3", got.Threshold)
	}
}

func TestDeleteRule(t *testing.T) {
	s := NewMemoryStore(100)
	r := newTestRule()
	s.CreateRule(r)

	err := s.DeleteRule(r.ID)
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	_, err = s.GetRule(r.ID)
	if err == nil {
		t.Error("expected not found after delete")
	}
}

func TestDeleteRuleNotFound(t *testing.T) {
	s := NewMemoryStore(100)
	err := s.DeleteRule("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestListRules(t *testing.T) {
	s := NewMemoryStore(100)
	r1 := newTestRule()
	r1.ID = "rule-1"
	s.CreateRule(r1)

	r2 := newTestRule()
	r2.ID = "rule-2"
	s.CreateRule(r2)

	rules := s.ListRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestEmptyList(t *testing.T) {
	s := NewMemoryStore(100)
	results, err := s.ListAlerts(models.AlertFilter{})
	if err != nil {
		t.Fatalf("ListAlerts failed: %v", err)
	}
	if results == nil {
		t.Error("ListAlerts should return empty slice, not nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestFileStorePersistence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "alerts.jsonl")

	s1, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	a := newTestAlert()
	s1.CreateAlert(a)

	r := newTestRule()
	s1.CreateRule(r)

	s2, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("NewFileStore reload failed: %v", err)
	}

	got, err := s2.GetAlert(a.ID)
	if err != nil {
		t.Fatalf("alert not persisted: %v", err)
	}
	if got.Type != a.Type {
		t.Errorf("persisted alert Type = %v, want %v", got.Type, a.Type)
	}

	rules := s2.ListRules()
	if len(rules) != 1 {
		t.Errorf("expected 1 persisted rule, got %d", len(rules))
	}
}

func TestFileStoreNotFound(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "nonexistent.jsonl")

	s, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("NewFileStore should handle missing file: %v", err)
	}

	_, err = s.GetAlert("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestListAlertsPagination(t *testing.T) {
	s := NewMemoryStore(100)

	for i := range 5 {
		a := newTestAlert()
		a.ID = "alert-page-" + string(rune('0'+i))
		s.CreateAlert(a)
	}

	results, _ := s.ListAlerts(models.AlertFilter{Limit: 2})
	if len(results) != 2 {
		t.Errorf("expected 2, got %d", len(results))
	}

	page2, _ := s.ListAlerts(models.AlertFilter{Limit: 2, Offset: 2})
	if len(page2) != 2 {
		t.Errorf("expected 2, got %d", len(page2))
	}

	page3, _ := s.ListAlerts(models.AlertFilter{Limit: 2, Offset: 4})
	if len(page3) != 1 {
		t.Errorf("expected 1, got %d", len(page3))
	}
}

func TestCount(t *testing.T) {
	s := NewMemoryStore(100)
	for i := range 3 {
		a := newTestAlert()
		a.ID = "alert-count-" + string(rune('0'+i))
		s.CreateAlert(a)
	}
	if s.Count() != 3 {
		t.Errorf("count = %d, want 3", s.Count())
	}
}

func TestFileStoreEviction(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "evict.jsonl")

	s, err := NewFileStore(2, filePath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	a1 := newTestAlert()
	a1.ID = "alert-e1"
	a1.Timestamp = time.Now().UTC().Add(-10 * time.Minute)
	s.CreateAlert(a1)

	a2 := newTestAlert()
	a2.ID = "alert-e2"
	a2.Timestamp = time.Now().UTC().Add(-5 * time.Minute)
	s.CreateAlert(a2)

	a3 := newTestAlert()
	a3.ID = "alert-e3"
	a3.Timestamp = time.Now().UTC()
	s.CreateAlert(a3)

	if s.Count() != 2 {
		t.Errorf("expected 2 after eviction, got %d", s.Count())
	}
}

func TestFileStoreReload(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "reload.jsonl")

	s1, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	a := newTestAlert()
	a.ID = "alert-reload"
	s1.CreateAlert(a)

	s1.AcknowledgeAlert(a.ID, "admin")

	s2, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	got, err := s2.GetAlert(a.ID)
	if err != nil {
		t.Fatalf("alert not found after reload: %v", err)
	}
	if got.State != models.AlertStateAcknowledged {
		t.Errorf("State = %v, want acknowledged", got.State)
	}
}

func TestFileStoreDeleteRulePersistence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "delrule.jsonl")

	s1, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	r := newTestRule()
	r.ID = "rule-del"
	s1.CreateRule(r)
	s1.DeleteRule(r.ID)

	s2, err := NewFileStore(100, filePath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	_, err = s2.GetRule(r.ID)
	if err == nil {
		t.Error("expected rule to be deleted after reload")
	}
}

func TestFileStoreCreateNonexistent(t *testing.T) {
	_ = os.Remove("/tmp/nonexistent-alerts-test.jsonl")
	s, err := NewFileStore(100, "/tmp/nonexistent-alerts-test.jsonl")
	if err != nil {
		t.Fatalf("should handle nonexistent file: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("expected 0 alerts, got %d", s.Count())
	}
}
