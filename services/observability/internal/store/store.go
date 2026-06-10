package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"ovara.services.observability/internal/graph"
	"ovara.services.observability/internal/models"
)

type Store interface {
	Ingest(event *models.TraceEvent) error
	Query(filter TraceFilter) ([]*models.TraceEvent, error)
	GetTrace(traceID string) (*models.LineageRecord, error)
	GetAgentLineage(agentID string, limit int) ([]*models.LineageRecord, error)
	GetGraph(traceID string) (*models.TraceGraph, error)
	Count() int
}

type TraceFilter struct {
	AgentID    string
	Action     string
	Decision   string
	StartTime  time.Time
	EndTime    time.Time
	GatewayID  string
	Limit      int
	Offset     int
}

type memoryStore struct {
	mu       sync.RWMutex
	events   []*models.TraceEvent
	maxSize  int
	filePath string
	builder  *graph.Builder
}

func NewMemoryStore(maxSize int) Store {
	if maxSize <= 0 {
		maxSize = 100000
	}
	return &memoryStore{
		events:  make([]*models.TraceEvent, 0, maxSize),
		maxSize: maxSize,
		builder: graph.NewBuilder(),
	}
}

func NewFileStore(filePath string, maxSize int) (Store, error) {
	s := NewMemoryStore(maxSize).(*memoryStore)
	s.filePath = filePath

	f, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var evt models.TraceEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		s.events = append(s.events, &evt)
	}

	return s, nil
}

func (s *memoryStore) Ingest(event *models.TraceEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.events) >= s.maxSize {
		return fmt.Errorf("store full: max %d events", s.maxSize)
	}

	s.events = append(s.events, event)

	if s.filePath != "" {
		if err := s.appendToFile(event); err != nil {
			return fmt.Errorf("persist event: %w", err)
		}
	}

	return nil
}

func (s *memoryStore) appendToFile(event *models.TraceEvent) error {
	f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = f.Write(append(data, '\n'))
	return err
}

func (s *memoryStore) Query(filter TraceFilter) ([]*models.TraceEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*models.TraceEvent
	for _, evt := range s.events {
		if filter.AgentID != "" && evt.AgentID != filter.AgentID {
			continue
		}
		if filter.Action != "" && evt.Action != filter.Action {
			continue
		}
		if filter.Decision != "" && evt.Decision != filter.Decision {
			continue
		}
		if filter.GatewayID != "" && evt.GatewayID != filter.GatewayID {
			continue
		}
		if !filter.StartTime.IsZero() && evt.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && evt.Timestamp.After(filter.EndTime) {
			continue
		}
		results = append(results, evt)
	}

	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(results) {
		results = results[:filter.Limit]
	}

	if results == nil {
		results = []*models.TraceEvent{}
	}
	return results, nil
}

func (s *memoryStore) GetTrace(traceID string) (*models.LineageRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var events []*models.TraceEvent
	var agentID string
	for _, evt := range s.events {
		if evt.TraceID == traceID {
			events = append(events, evt)
			if agentID == "" {
				agentID = evt.AgentID
			}
		}
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("trace %s not found", traceID)
	}

	graph := s.builder.BuildLineage(eventsToValue(events))
	return &models.LineageRecord{
		ActionDigest: traceID,
		AgentID:      agentID,
		Events:       eventsToRef(events),
		Graph:        graph,
	}, nil
}

func (s *memoryStore) GetAgentLineage(agentID string, limit int) ([]*models.LineageRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	traceMap := make(map[string][]*models.TraceEvent)
	for _, evt := range s.events {
		if evt.AgentID == agentID {
			traceMap[evt.TraceID] = append(traceMap[evt.TraceID], evt)
		}
	}

	if len(traceMap) == 0 {
		return []*models.LineageRecord{}, nil
	}

	var records []*models.LineageRecord
	for traceID, events := range traceMap {
		g := s.builder.BuildLineage(eventsToValue(events))
		records = append(records, &models.LineageRecord{
			ActionDigest: traceID,
			AgentID:      agentID,
			Events:       eventsToRef(events),
			Graph:        g,
		})
		if limit > 0 && len(records) >= limit {
			break
		}
	}

	if records == nil {
		records = []*models.LineageRecord{}
	}
	return records, nil
}

func (s *memoryStore) GetGraph(traceID string) (*models.TraceGraph, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var events []*models.TraceEvent
	for _, evt := range s.events {
		if evt.TraceID == traceID {
			events = append(events, evt)
		}
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("trace %s not found", traceID)
	}

	g := s.builder.BuildLineage(eventsToValue(events))
	return &g, nil
}

func (s *memoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func eventsToValue(events []*models.TraceEvent) []models.TraceEvent {
	result := make([]models.TraceEvent, len(events))
	for i, e := range events {
		result[i] = *e
	}
	return result
}

func eventsToRef(events []*models.TraceEvent) []models.TraceEvent {
	result := make([]models.TraceEvent, len(events))
	for i, e := range events {
		result[i] = *e
	}
	return result
}
