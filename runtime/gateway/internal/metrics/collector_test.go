package metrics

import (
	"testing"
	"time"
)

func TestRuntimeMetrics_RecordDecision(t *testing.T) {
	m := NewRuntimeMetrics()
	m.RecordDecision("allow", "shell", 12)
	m.RecordDecision("allow", "shell", 8)
	m.RecordDecision("escalate", "git.push", 15)

	snap := m.Snapshot()
	if snap.DecisionCounts["allow"] != 2 {
		t.Errorf("allow count = %d, want 2", snap.DecisionCounts["allow"])
	}
	if snap.DecisionCounts["escalate"] != 1 {
		t.Errorf("escalate count = %d, want 1", snap.DecisionCounts["escalate"])
	}
	if snap.ActionCounts["shell"] != 2 {
		t.Errorf("shell action count = %d, want 2", snap.ActionCounts["shell"])
	}
	if snap.ActionCounts["git.push"] != 1 {
		t.Errorf("git.push action count = %d, want 1", snap.ActionCounts["git.push"])
	}
	if snap.TotalDecisions != 3 {
		t.Errorf("total decisions = %d, want 3", snap.TotalDecisions)
	}
}

func TestRuntimeMetrics_AvgLatency(t *testing.T) {
	m := NewRuntimeMetrics()
	m.RecordDecision("allow", "shell", 10)
	m.RecordDecision("allow", "shell", 20)

	snap := m.Snapshot()
	if snap.AvgLatencyMs != 15 {
		t.Errorf("avg latency = %d, want 15", snap.AvgLatencyMs)
	}
	if snap.LastLatencyMs != 20 {
		t.Errorf("last latency = %d, want 20", snap.LastLatencyMs)
	}
}

func TestRuntimeMetrics_RecordApproval(t *testing.T) {
	m := NewRuntimeMetrics()
	m.RecordApproval()
	m.RecordApproval()

	snap := m.Snapshot()
	if snap.ApprovalCounts != 2 {
		t.Errorf("approval count = %d, want 2", snap.ApprovalCounts)
	}
}

func TestRuntimeMetrics_RecordHeartbeat(t *testing.T) {
	m := NewRuntimeMetrics()
	before := time.Now().UTC()
	m.RecordHeartbeat()
	after := time.Now().UTC()

	snap := m.Snapshot()
	if snap.HeartbeatCount != 1 {
		t.Errorf("heartbeat count = %d, want 1", snap.HeartbeatCount)
	}
	if snap.LastHeartbeatAt.Before(before) || snap.LastHeartbeatAt.After(after) {
		t.Error("last heartbeat at not in expected window")
	}
}

func TestRuntimeMetrics_RecordPolicyReload(t *testing.T) {
	m := NewRuntimeMetrics()

	m.RecordPolicyReload(true, "")
	snap := m.Snapshot()
	if snap.PolicyReloadStatus != PolicyReloadStatusOK {
		t.Errorf("policy reload status = %v, want ok", snap.PolicyReloadStatus)
	}
	if snap.PolicyReloadErrMsg != "" {
		t.Errorf("err msg should be empty, got %s", snap.PolicyReloadErrMsg)
	}

	m.RecordPolicyReload(false, "file not found")
	snap = m.Snapshot()
	if snap.PolicyReloadStatus != PolicyReloadStatusFailed {
		t.Errorf("policy reload status = %v, want failed", snap.PolicyReloadStatus)
	}
	if snap.PolicyReloadErrMsg != "file not found" {
		t.Errorf("err msg = %s, want 'file not found'", snap.PolicyReloadErrMsg)
	}

	m.RecordPolicyReload(true, "")
	snap = m.Snapshot()
	if snap.PolicyReloadStatus != PolicyReloadStatusOK {
		t.Errorf("policy reload status = %v, want ok after recovery", snap.PolicyReloadStatus)
	}
}

func TestRuntimeMetrics_InitialPolicyReloadStatus(t *testing.T) {
	m := NewRuntimeMetrics()
	snap := m.Snapshot()
	if snap.PolicyReloadStatus != PolicyReloadStatusNone {
		t.Errorf("initial policy reload status = %v, want none", snap.PolicyReloadStatus)
	}
}

func TestRuntimeMetrics_LastDecisionAt(t *testing.T) {
	m := NewRuntimeMetrics()
	before := time.Now().UTC()
	m.RecordDecision("allow", "shell", 5)
	after := time.Now().UTC()

	snap := m.Snapshot()
	if snap.LastDecisionAt.Before(before) || snap.LastDecisionAt.After(after) {
		t.Error("last decision at not in expected window")
	}
}

func TestRuntimeMetrics_SnapshotIsolation(t *testing.T) {
	m := NewRuntimeMetrics()
	m.RecordDecision("allow", "shell", 10)

	snap1 := m.Snapshot()
	m.RecordDecision("deny", "git.push", 5)
	snap2 := m.Snapshot()

	if snap1.TotalDecisions != 1 {
		t.Errorf("snap1 total = %d, want 1", snap1.TotalDecisions)
	}
	if snap2.TotalDecisions != 2 {
		t.Errorf("snap2 total = %d, want 2", snap2.TotalDecisions)
	}
	if snap1.DecisionCounts["deny"] != 0 {
		t.Errorf("snap1 deny count = %d, want 0", snap1.DecisionCounts["deny"])
	}
}