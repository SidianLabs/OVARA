package metrics

import (
	"sync"
	"time"
)

type RuntimeMetrics struct {
	mu                  sync.RWMutex
	DecisionCounts      map[string]int
	ActionCounts        map[string]int
	ApprovalCounts      int
	HeartbeatCount      int
	LastDecisionAt      time.Time
	LastHeartbeatAt     time.Time
	TotalLatencyMs       int64
	DecisionCount       int64
	LastLatencyMs        int64
	PolicyReloadStatus  string
	PolicyReloadLastAt  time.Time
	PolicyReloadErrMsg  string
}

const (
	PolicyReloadStatusNone   = "none"
	PolicyReloadStatusOK     = "ok"
	PolicyReloadStatusFailed = "failed"
)

func NewRuntimeMetrics() *RuntimeMetrics {
	return &RuntimeMetrics{
		DecisionCounts:     make(map[string]int),
		ActionCounts:       make(map[string]int),
		PolicyReloadStatus: "none",
	}
}

func (m *RuntimeMetrics) RecordDecision(decision, actionType string, latencyMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DecisionCounts[decision]++
	m.ActionCounts[actionType]++
	m.TotalLatencyMs += latencyMs
	m.DecisionCount++
	m.LastLatencyMs = latencyMs
	m.LastDecisionAt = time.Now().UTC()
}

func (m *RuntimeMetrics) RecordApproval() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ApprovalCounts++
}

func (m *RuntimeMetrics) RecordHeartbeat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.HeartbeatCount++
	m.LastHeartbeatAt = time.Now().UTC()
}

func (m *RuntimeMetrics) RecordPolicyReload(success bool, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.PolicyReloadStatus = PolicyReloadStatusOK
	} else {
		m.PolicyReloadStatus = PolicyReloadStatusFailed
	}
	m.PolicyReloadLastAt = time.Now().UTC()
	m.PolicyReloadErrMsg = errMsg
}

func (m *RuntimeMetrics) Snapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var avgLatency int64
	if m.DecisionCount > 0 {
		avgLatency = m.TotalLatencyMs / m.DecisionCount
	}

	decisionCounts := make(map[string]int, len(m.DecisionCounts))
	for k, v := range m.DecisionCounts {
		decisionCounts[k] = v
	}
	actionCounts := make(map[string]int, len(m.ActionCounts))
	for k, v := range m.ActionCounts {
		actionCounts[k] = v
	}

	return MetricsSnapshot{
		DecisionCounts:     decisionCounts,
		ActionCounts:       actionCounts,
		ApprovalCounts:     m.ApprovalCounts,
		HeartbeatCount:     m.HeartbeatCount,
		LastDecisionAt:     m.LastDecisionAt,
		LastHeartbeatAt:    m.LastHeartbeatAt,
		TotalDecisions:     int(m.DecisionCount),
		AvgLatencyMs:       avgLatency,
		LastLatencyMs:      m.LastLatencyMs,
		PolicyReloadStatus: m.PolicyReloadStatus,
		PolicyReloadLastAt: m.PolicyReloadLastAt,
		PolicyReloadErrMsg: m.PolicyReloadErrMsg,
	}
}

type MetricsSnapshot struct {
	DecisionCounts     map[string]int
	ActionCounts       map[string]int
	ApprovalCounts     int
	HeartbeatCount     int
	LastDecisionAt     time.Time
	LastHeartbeatAt    time.Time
	TotalDecisions     int
	AvgLatencyMs       int64
	LastLatencyMs      int64
	PolicyReloadStatus string
	PolicyReloadLastAt time.Time
	PolicyReloadErrMsg string
}