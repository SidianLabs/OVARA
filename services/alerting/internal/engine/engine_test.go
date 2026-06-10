package engine

import (
	"testing"
	"time"

	"ovara.services.alerting/internal/models"
	"ovara.services.alerting/internal/store"
)

func TestProcessEvent(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	ev := Event{
		Type:       models.AlertTypeAnomaly,
		Severity:   models.SeverityHigh,
		AgentID:    "agt-001",
		GatewayID:  "gw-001",
		Action:     "shell.execute",
		Resource:   "sudo",
		TrustScore: 0.2,
		Message:    "anomalous behavior detected",
	}

	alert, err := e.ProcessEvent(ev)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}
	if alert == nil {
		t.Fatal("expected alert, got nil")
	}
	if alert.Severity != models.SeverityHigh {
		t.Errorf("Severity = %v, want high", alert.Severity)
	}
	if alert.State != models.AlertStateNew {
		t.Errorf("State = %v, want new", alert.State)
	}
}

func TestDeduplicateEvents(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	ev := Event{
		Type:       models.AlertTypeAnomaly,
		AgentID:    "agt-001",
		GatewayID:  "gw-001",
		Resource:   "sudo",
		TrustScore: 0.2,
		Message:    "first event",
	}

	_, err := e.ProcessEvent(ev)
	if err != nil {
		t.Fatalf("first ProcessEvent failed: %v", err)
	}

	_, err = e.ProcessEvent(ev)
	if err == nil {
		t.Error("expected duplicate error")
	}
}

func TestDeduplicateWindowExpiry(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	callCount := 0
	e.nowFunc = func() time.Time {
		callCount++
		if callCount <= 2 {
			return now
		}
		return now.Add(10 * time.Minute)
	}

	ev := Event{
		Type:       models.AlertTypeAnomaly,
		AgentID:    "agt-001",
		GatewayID:  "gw-001",
		Resource:   "sudo",
		TrustScore: 0.2,
		Message:    "event",
	}

	_, err := e.ProcessEvent(ev)
	if err != nil {
		t.Fatalf("first ProcessEvent failed: %v", err)
	}

	_, err = e.ProcessEvent(ev)
	if err != nil {
		t.Errorf("expected dedup window to expire, got: %v", err)
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	ev := Event{
		Type:     models.AlertTypeAnomaly,
		Severity: models.SeverityHigh,
		AgentID:  "agt-001",
		Message:  "test",
	}

	alert, _ := e.ProcessEvent(ev)

	ack, err := e.AcknowledgeAlert(alert.ID, "admin")
	if err != nil {
		t.Fatalf("AcknowledgeAlert failed: %v", err)
	}
	if ack.State != models.AlertStateAcknowledged {
		t.Errorf("State = %v, want acknowledged", ack.State)
	}
}

func TestResolveAlert(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	ev := Event{
		Type:     models.AlertTypeAnomaly,
		Severity: models.SeverityCritical,
		AgentID:  "agt-001",
		Message:  "critical issue",
	}

	alert, _ := e.ProcessEvent(ev)

	resolved, err := e.ResolveAlert(alert.ID)
	if err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}
	if resolved.State != models.AlertStateResolved {
		t.Errorf("State = %v, want resolved", resolved.State)
	}
	if resolved.ResolvedAt == nil {
		t.Error("ResolvedAt should not be nil")
	}
}

func TestAcknowledgeNotFound(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)

	_, err := e.AcknowledgeAlert("nonexistent", "admin")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestResolveNotFound(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)

	_, err := e.ResolveAlert("nonexistent")
	if err == nil {
		t.Error("expected not found error")
	}
}

func TestEvaluateRulesTrustBelow(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	rule := &models.AlertRule{
		ID:            "rule-1",
		Name:          "Low Trust",
		Condition:     models.ConditionTrustBelow,
		Threshold:     0.5,
		WindowSeconds: 300,
		Severity:      models.SeverityCritical,
		Enabled:       true,
	}
	s.CreateRule(rule)

	ev := Event{
		Type:       models.AlertTypeTrustDegradation,
		AgentID:    "agt-001",
		GatewayID:  "gw-001",
		TrustScore: 0.3,
		Message:    "trust dropped",
	}

	alerts := e.EvaluateRules(ev)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 rule alert, got %d", len(alerts))
	}
	if alerts[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %v, want critical", alerts[0].Severity)
	}
}

func TestEvaluateRulesDisabled(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	rule := &models.AlertRule{
		ID:        "rule-dis",
		Name:      "Disabled Rule",
		Condition: models.ConditionTrustBelow,
		Threshold: 0.5,
		Severity:  models.SeverityHigh,
		Enabled:   false,
	}
	s.CreateRule(rule)

	ev := Event{
		Type:       models.AlertTypeTrustDegradation,
		TrustScore: 0.1,
	}

	alerts := e.EvaluateRules(ev)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts from disabled rule, got %d", len(alerts))
	}
}

func TestEvaluateRulesNoMatch(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	rule := &models.AlertRule{
		ID:        "rule-nomatch",
		Name:      "High Trust Only",
		Condition: models.ConditionTrustBelow,
		Threshold: 0.5,
		Severity:  models.SeverityHigh,
		Enabled:   true,
	}
	s.CreateRule(rule)

	ev := Event{
		Type:       models.AlertTypeAnomaly,
		TrustScore: 0.8,
	}

	alerts := e.EvaluateRules(ev)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts when threshold not exceeded, got %d", len(alerts))
	}
}

func TestEvaluateRulesAnomalyCount(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	rule := &models.AlertRule{
		ID:            "rule-anom",
		Name:          "Anomaly Alert",
		Condition:     models.ConditionAnomalyCount,
		Threshold:     5,
		WindowSeconds: 60,
		Severity:      models.SeverityMedium,
		Enabled:       true,
	}
	s.CreateRule(rule)

	ev := Event{
		Type:     models.AlertTypeAnomaly,
		AgentID:  "agt-001",
		GatewayID: "gw-001",
		Resource: "file",
		Message:  "anomaly detected",
	}

	alerts := e.EvaluateRules(ev)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 anomaly rule alert, got %d", len(alerts))
	}
}

func TestCRUDRules(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)

	rule := &models.AlertRule{
		ID:        "rule-crud",
		Name:      "Test Rule",
		Condition: models.ConditionCapabilityChain,
		Threshold: 3,
		Severity:  models.SeverityHigh,
		Enabled:   true,
	}

	if err := e.CreateRule(rule); err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	got, err := e.GetRule(rule.ID)
	if err != nil {
		t.Fatalf("GetRule failed: %v", err)
	}
	if got.Name != "Test Rule" {
		t.Errorf("Name = %v, want Test Rule", got.Name)
	}

	rule.Name = "Updated Rule"
	if err := e.UpdateRule(rule); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	got2, _ := e.GetRule(rule.ID)
	if got2.Name != "Updated Rule" {
		t.Errorf("Name = %v, want Updated Rule", got2.Name)
	}

	if err := e.DeleteRule(rule.ID); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	_, err = e.GetRule(rule.ID)
	if err == nil {
		t.Error("expected not found after delete")
	}
}

func TestListAlerts(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	for i := range 3 {
		ev := Event{
			Type:      models.AlertTypeAnomaly,
			AgentID:   "agt-001",
			GatewayID: "gw-001",
			Resource:  "resource-" + string(rune('a'+i)),
			Message:   "event",
		}
		if i == 0 {
			ev.AgentID = "agt-002"
		}
		e.ProcessEvent(ev)
	}

	results, err := e.ListAlerts(models.AlertFilter{AgentID: "agt-001"})
	if err != nil {
		t.Fatalf("ListAlerts failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 alerts for agt-001, got %d", len(results))
	}
}

func TestGetUnacknowledged(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	ev1 := Event{Type: models.AlertTypeAnomaly, AgentID: "agt-001", GatewayID: "gw-001", Resource: "r1", Message: "a"}
	a1, _ := e.ProcessEvent(ev1)

	ev2 := Event{Type: models.AlertTypeAnomaly, AgentID: "agt-002", GatewayID: "gw-001", Resource: "r2", Message: "b"}
	a2, _ := e.ProcessEvent(ev2)

	e.AcknowledgeAlert(a1.ID, "admin")

	unack := e.GetUnacknowledged()
	if len(unack) != 1 {
		t.Errorf("expected 1 unacknowledged, got %d", len(unack))
	}
	if len(unack) > 0 && unack[0].ID != a2.ID {
		t.Errorf("expected unacknowledged alert %s, got %s", a2.ID, unack[0].ID)
	}
}

func TestCountBySeverity(t *testing.T) {
	s := store.NewMemoryStore(100)
	e := New(s)
	e.nowFunc = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }

	e.ProcessEvent(Event{Type: models.AlertTypeAnomaly, Severity: models.SeverityCritical, AgentID: "a1", GatewayID: "g1", Resource: "r1", Message: "c1"})
	e.ProcessEvent(Event{Type: models.AlertTypeAnomaly, Severity: models.SeverityCritical, AgentID: "a2", GatewayID: "g2", Resource: "r2", Message: "c2"})
	e.ProcessEvent(Event{Type: models.AlertTypeAnomaly, Severity: models.SeverityLow, AgentID: "a3", GatewayID: "g3", Resource: "r3", Message: "l1"})

	counts := e.CountBySeverity()
	if counts[models.SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[models.SeverityCritical])
	}
	if counts[models.SeverityLow] != 1 {
		t.Errorf("expected 1 low, got %d", counts[models.SeverityLow])
	}
}
