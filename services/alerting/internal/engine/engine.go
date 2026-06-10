package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"ovara.services.alerting/internal/models"
	"ovara.services.alerting/internal/store"
)

type Event struct {
	Type           models.AlertType
	Severity       models.Severity
	AgentID        string
	GatewayID      string
	OrganizationID string
	Action         string
	Resource       string
	TrustScore     float64
	Message        string
}

type Engine struct {
	store       store.Store
	mu          sync.Mutex
	dedupe      map[string]time.Time
	dedupeTTL   time.Duration
	nowFunc     func() time.Time
}

func New(s store.Store) *Engine {
	return &Engine{
		store:     s,
		dedupe:    make(map[string]time.Time),
		dedupeTTL: 5 * time.Minute,
		nowFunc:   time.Now,
	}
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func dedupeKey(a *models.Alert) string {
	return fmt.Sprintf("%s:%s:%s:%s", a.Type, a.AgentID, a.GatewayID, a.Resource)
}

func (e *Engine) ProcessEvent(ev Event) (*models.Alert, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	alert := &models.Alert{
		ID:             generateID(),
		Severity:       ev.Severity,
		Type:           ev.Type,
		AgentID:        ev.AgentID,
		GatewayID:      ev.GatewayID,
		OrganizationID: ev.OrganizationID,
		Action:         ev.Action,
		Resource:       ev.Resource,
		TrustScore:     ev.TrustScore,
		Message:        ev.Message,
		Timestamp:      e.nowFunc().UTC(),
		State:          models.AlertStateNew,
	}

	key := dedupeKey(alert)
	if lastSeen, ok := e.dedupe[key]; ok {
		if e.nowFunc().Sub(lastSeen) < e.dedupeTTL {
			return nil, fmt.Errorf("duplicate event within deduplication window")
		}
	}
	e.dedupe[key] = e.nowFunc()

	if err := e.store.CreateAlert(alert); err != nil {
		return nil, err
	}

	return alert, nil
}

func (e *Engine) AcknowledgeAlert(id string, by string) (*models.Alert, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.store.AcknowledgeAlert(id, by); err != nil {
		return nil, err
	}
	return e.store.GetAlert(id)
}

func (e *Engine) ResolveAlert(id string) (*models.Alert, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.store.ResolveAlert(id); err != nil {
		return nil, err
	}
	return e.store.GetAlert(id)
}

func (e *Engine) EvaluateRules(ev Event) []*models.Alert {
	rules := e.store.ListRules()
	var alerts []*models.Alert

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !e.matchCondition(rule, ev) {
			continue
		}

		alert := &models.Alert{
			ID:             generateID(),
			Severity:       rule.Severity,
			Type:           ev.Type,
			AgentID:        ev.AgentID,
			GatewayID:      ev.GatewayID,
			OrganizationID: ev.OrganizationID,
			Action:         ev.Action,
			Resource:       ev.Resource,
			TrustScore:     ev.TrustScore,
			Message:        fmt.Sprintf("Rule '%s' triggered: %s", rule.Name, ev.Message),
			Timestamp:      e.nowFunc().UTC(),
			State:          models.AlertStateNew,
		}

		key := dedupeKey(alert)
		e.mu.Lock()
		if lastSeen, ok := e.dedupe[key]; ok {
			if e.nowFunc().Sub(lastSeen) < e.dedupeTTL {
				e.mu.Unlock()
				continue
			}
		}
		e.dedupe[key] = e.nowFunc()
		e.mu.Unlock()

		if err := e.store.CreateAlert(alert); err == nil {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

func (e *Engine) matchCondition(rule *models.AlertRule, ev Event) bool {
	switch rule.Condition {
	case models.ConditionTrustBelow:
		return ev.TrustScore < rule.Threshold
	case models.ConditionAnomalyCount:
		return ev.Type == models.AlertTypeAnomaly
	case models.ConditionExcessiveEscalations:
		return ev.Type == models.AlertTypeTrustDegradation
	case models.ConditionCapabilityChain:
		return ev.Type == models.AlertTypeCapabilityAbuse
	default:
		return false
	}
}

func (e *Engine) CreateRule(r *models.AlertRule) error {
	return e.store.CreateRule(r)
}

func (e *Engine) GetRule(id string) (*models.AlertRule, error) {
	return e.store.GetRule(id)
}

func (e *Engine) ListRules() []*models.AlertRule {
	return e.store.ListRules()
}

func (e *Engine) UpdateRule(r *models.AlertRule) error {
	return e.store.UpdateRule(r)
}

func (e *Engine) DeleteRule(id string) error {
	return e.store.DeleteRule(id)
}

func (e *Engine) GetAlert(id string) (*models.Alert, error) {
	return e.store.GetAlert(id)
}

func (e *Engine) ListAlerts(filter models.AlertFilter) ([]*models.Alert, error) {
	return e.store.ListAlerts(filter)
}

func (e *Engine) GetUnacknowledged() []*models.Alert {
	return e.store.GetUnacknowledged()
}

func (e *Engine) CountBySeverity() map[models.Severity]int {
	return e.store.CountBySeverity()
}

func (e *Engine) Count() int {
	return e.store.Count()
}
