package metrics

import (
	"sync"
)

var (
	global  *RuntimeMetrics
	globalMu sync.RWMutex
)

func Global() *RuntimeMetrics {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global == nil {
		global = NewRuntimeMetrics()
	}
	return global
}

func RecordDecision(decision, actionType string, latencyMs int64) {
	Global().RecordDecision(decision, actionType, latencyMs)
}

func RecordApproval() {
	Global().RecordApproval()
}

func RecordHeartbeat() {
	Global().RecordHeartbeat()
}

func RecordPolicyReload(success bool, errMsg string) {
	Global().RecordPolicyReload(success, errMsg)
}