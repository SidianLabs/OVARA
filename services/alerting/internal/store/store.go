package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"ovara.services.alerting/internal/models"
)

type Store interface {
	CreateAlert(a *models.Alert) error
	GetAlert(id string) (*models.Alert, error)
	ListAlerts(filter models.AlertFilter) ([]*models.Alert, error)
	AcknowledgeAlert(id string, by string) error
	ResolveAlert(id string) error
	GetUnacknowledged() []*models.Alert
	CountBySeverity() map[models.Severity]int
	CreateRule(r *models.AlertRule) error
	GetRule(id string) (*models.AlertRule, error)
	ListRules() []*models.AlertRule
	UpdateRule(r *models.AlertRule) error
	DeleteRule(id string) error
	Count() int
}

type memoryStore struct {
	mu       sync.RWMutex
	alerts   map[string]*models.Alert
	rules    map[string]*models.AlertRule
	maxSize  int
	filePath string
}

func NewMemoryStore(maxSize int) Store {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &memoryStore{
		alerts:  make(map[string]*models.Alert),
		rules:   make(map[string]*models.AlertRule),
		maxSize: maxSize,
	}
}

func NewFileStore(maxSize int, filePath string) (Store, error) {
	if maxSize <= 0 {
		maxSize = 10000
	}
	s := &memoryStore{
		alerts:  make(map[string]*models.Alert),
		rules:   make(map[string]*models.AlertRule),
		maxSize: maxSize,
		filePath: filePath,
	}

	if filePath != "" {
		if err := s.loadFromFile(); err != nil {
			return nil, fmt.Errorf("loading store: %w", err)
		}
	}

	return s, nil
}

func (s *memoryStore) loadFromFile() error {
	f, err := os.Open(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry struct {
			Type string          `json:"_type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		switch entry.Type {
		case "alert":
			var a models.Alert
			if err := json.Unmarshal(entry.Data, &a); err == nil {
				s.alerts[a.ID] = &a
			}
		case "rule":
			var r models.AlertRule
			if err := json.Unmarshal(entry.Data, &r); err == nil {
				s.rules[r.ID] = &r
			}
		case "alert_update":
			var a models.Alert
			if err := json.Unmarshal(entry.Data, &a); err == nil {
				s.alerts[a.ID] = &a
			}
		case "alert_delete":
			var del struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(entry.Data, &del); err == nil {
				delete(s.alerts, del.ID)
			}
		case "rule_delete":
			var del struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(entry.Data, &del); err == nil {
				delete(s.rules, del.ID)
			}
		}
	}
	return scanner.Err()
}

func (s *memoryStore) appendJSONL(entryType string, data any) error {
	if s.filePath == "" {
		return nil
	}
	entry := map[string]any{
		"_type": entryType,
		"data":  data,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

func (s *memoryStore) evict() {
	if len(s.alerts) < s.maxSize {
		return
	}
	var oldest *models.Alert
	for _, a := range s.alerts {
		if oldest == nil || a.Timestamp.Before(oldest.Timestamp) {
			oldest = a
		}
	}
	if oldest != nil {
		delete(s.alerts, oldest.ID)
		if s.filePath != "" {
			delData, _ := json.Marshal(map[string]string{"id": oldest.ID})
			s.appendJSONL("alert_delete", json.RawMessage(delData))
		}
	}
}

func (s *memoryStore) CreateAlert(a *models.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.alerts) >= s.maxSize {
		s.evict()
	}
	s.alerts[a.ID] = a
	return s.appendJSONL("alert", a)
}

func (s *memoryStore) GetAlert(id string) (*models.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert %s not found", id)
	}
	return a, nil
}

func (s *memoryStore) ListAlerts(filter models.AlertFilter) ([]*models.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.Alert
	for _, a := range s.alerts {
		if filter.Severity != "" && a.Severity != filter.Severity {
			continue
		}
		if filter.Type != "" && a.Type != filter.Type {
			continue
		}
		if filter.State != "" && a.State != filter.State {
			continue
		}
		if filter.AgentID != "" && a.AgentID != filter.AgentID {
			continue
		}
		if filter.GatewayID != "" && a.GatewayID != filter.GatewayID {
			continue
		}
		if filter.OrganizationID != "" && a.OrganizationID != filter.OrganizationID {
			continue
		}
		results = append(results, a)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	if results == nil {
		results = []*models.Alert{}
	}
	return results, nil
}

func (s *memoryStore) AcknowledgeAlert(id string, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert %s not found", id)
	}
	if a.State != models.AlertStateNew {
		return fmt.Errorf("alert %s is already %s", id, a.State)
	}
	a.State = models.AlertStateAcknowledged
	a.AcknowledgedBy = by
	return s.appendJSONL("alert_update", a)
}

func (s *memoryStore) ResolveAlert(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert %s not found", id)
	}
	now := time.Now().UTC()
	a.State = models.AlertStateResolved
	a.ResolvedAt = &now
	return s.appendJSONL("alert_update", a)
}

func (s *memoryStore) GetUnacknowledged() []*models.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.Alert
	for _, a := range s.alerts {
		if a.State == models.AlertStateNew {
			results = append(results, a)
		}
	}
	return results
}

func (s *memoryStore) CountBySeverity() map[models.Severity]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[models.Severity]int)
	for _, a := range s.alerts {
		counts[a.Severity]++
	}
	return counts
}

func (s *memoryStore) CreateRule(r *models.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[r.ID]; exists {
		return fmt.Errorf("rule %s already exists", r.ID)
	}
	s.rules[r.ID] = r
	return s.appendJSONL("rule", r)
}

func (s *memoryStore) GetRule(id string) (*models.AlertRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule %s not found", id)
	}
	return r, nil
}

func (s *memoryStore) ListRules() []*models.AlertRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.AlertRule
	for _, r := range s.rules {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})
	if results == nil {
		results = []*models.AlertRule{}
	}
	return results
}

func (s *memoryStore) UpdateRule(r *models.AlertRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[r.ID]; !exists {
		return fmt.Errorf("rule %s not found", r.ID)
	}
	s.rules[r.ID] = r
	return s.appendJSONL("rule", r)
}

func (s *memoryStore) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[id]; !exists {
		return fmt.Errorf("rule %s not found", id)
	}
	delete(s.rules, id)
	delData, _ := json.Marshal(map[string]string{"id": id})
	return s.appendJSONL("rule_delete", json.RawMessage(delData))
}

func (s *memoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.alerts)
}
