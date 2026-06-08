package integrity

import (
	"fmt"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/receipts"
)

type Result struct {
	Timestamp   time.Time          `json:"timestamp"`
	Passed      bool               `json:"passed"`
	Issues      []Issue            `json:"issues,omitempty"`
	Warnings    []Warning          `json:"warnings,omitempty"`
	Summary     Summary            `json:"summary"`
	StoreStats  map[string]int     `json:"store_stats"`
	VersionInfo map[string]string  `json:"version_info"`
}

type Summary struct {
	TotalIssues   int `json:"total_issues"`
	TotalWarnings int `json:"total_warnings"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
}

type Issue struct {
	Code       string `json:"code,omitempty"`
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	EntityID   string `json:"entity_id,omitempty"`
	EntityType string `json:"entity_type,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Warning struct {
	Code       string `json:"code,omitempty"`
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	EntityID   string `json:"entity_id,omitempty"`
	EntityType string `json:"entity_type,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Checker struct {
	eventStore       events.Store
	continuationStore continuation.Store
	executionStore   execution.Store
	receiptStore     receipts.Store
	approvalStore    approval.Store
	gatewayID string
	gatewayVersion string
}

func NewChecker() *Checker {
	return &Checker{}
}

func (c *Checker) SetEventStore(store events.Store) {
	c.eventStore = store
}

func (c *Checker) SetContinuationStore(store continuation.Store) {
	c.continuationStore = store
}

func (c *Checker) SetExecutionStore(store execution.Store) {
	c.executionStore = store
}

func (c *Checker) SetReceiptStore(store receipts.Store) {
	c.receiptStore = store
}

func (c *Checker) SetApprovalStore(store approval.Store) {
	c.approvalStore = store
}

func (c *Checker) SetGatewayInfo(id, version string) {
	c.gatewayID = id
	c.gatewayVersion = version
}

func (c *Checker) Check() Result {
	result := Result{
		Timestamp:   time.Now().UTC(),
		Passed:      true,
		StoreStats:  make(map[string]int),
		VersionInfo: make(map[string]string),
	}

	if c.gatewayID != "" {
		result.VersionInfo["gateway_id"] = c.gatewayID
	}
	if c.gatewayVersion != "" {
		result.VersionInfo["gateway_version"] = c.gatewayVersion
	}

	c.checkEventStore(&result)
	c.checkContinuationStore(&result)
	c.checkExecutionStore(&result)
	c.checkReceiptStore(&result)
	c.checkApprovalStore(&result)
	c.checkCrossStoreReferences(&result)

	for _, issue := range result.Issues {
		if issue.Severity == "critical" || issue.Severity == "high" {
			result.Passed = false
			break
		}
	}

	c.summarize(&result)

	return result
}

func (c *Checker) checkEventStore(r *Result) {
	if c.eventStore == nil {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "event_store",
			Message:    "event store not configured",
		})
		return
	}

	count := c.eventStore.Count()
	r.StoreStats["events"] = count

	if count == 0 {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "event_store",
			Message:    "event store is empty",
		})
	}

	events := c.eventStore.List(1000)
	var duplicateIDs []string
	seenIDs := make(map[string]bool)
	for _, evt := range events {
		if seenIDs[evt.EventID] {
			duplicateIDs = append(duplicateIDs, evt.EventID)
		}
		seenIDs[evt.EventID] = true
	}
	if len(duplicateIDs) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "EVT_DUP",
			Severity:   "high",
			Category:   "event_store",
			Message:    fmt.Sprintf("found %d duplicate event IDs", len(duplicateIDs)),
			EntityType: "event",
			Detail:     fmt.Sprintf("duplicate IDs: %v", duplicateIDs[:min(5, len(duplicateIDs))]),
		})
	}

	var zeroTimeEvents []string
	for _, evt := range events {
		if evt.Timestamp.IsZero() {
			zeroTimeEvents = append(zeroTimeEvents, evt.EventID)
		}
	}
	if len(zeroTimeEvents) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "EVT_ZERO_TS",
			Severity:   "medium",
			Category:   "event_store",
			Message:    fmt.Sprintf("found %d events with zero timestamp", len(zeroTimeEvents)),
			EntityType: "event",
			Detail:     fmt.Sprintf("event IDs: %v", zeroTimeEvents[:min(5, len(zeroTimeEvents))]),
		})
	}

	eventTypeCounts := make(map[string]int)
	for _, evt := range events {
		eventTypeCounts[evt.EventType]++
	}
	r.StoreStats["event_types"] = len(eventTypeCounts)
}

func (c *Checker) checkContinuationStore(r *Result) {
	if c.continuationStore == nil {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "continuation_store",
			Message:    "continuation store not configured",
		})
		return
	}

	all := c.continuationStore.ListAll()
	r.StoreStats["continuations"] = len(all)

	stateCounts := make(map[continuation.State]int)
	var orphanedApprovals []string
	now := time.Now().UTC()

	for _, cnt := range all {
		stateCounts[cnt.State]++

		if cnt.ApprovalID != "" {
			if cnt.State != continuation.StateApproved &&
				cnt.State != continuation.StateEscalated && cnt.State != continuation.StateResumed {
				orphanedApprovals = append(orphanedApprovals, cnt.ContinuationID+"[approval="+cnt.ApprovalID+"]")
			}
		}

		if cnt.ExpiresAt != nil && !cnt.ExpiresAt.IsZero() {
			if cnt.State != continuation.StateExpired && now.After(*cnt.ExpiresAt) {
				r.Issues = append(r.Issues, Issue{
					Code:       "CONT_EXPIRED",
					Severity:   "medium",
					Category:   "continuation_store",
					Message:    "continuation past expiry but not marked expired",
					EntityID:   cnt.ContinuationID,
					EntityType: "continuation",
					Detail:     fmt.Sprintf("state=%s, expired_at=%v", cnt.State, cnt.ExpiresAt),
				})
			}
		}

		if cnt.State == continuation.StateEscalated {
			r.Warnings = append(r.Warnings, Warning{
				Severity:   "low",
				Category:   "continuation_store",
				Message:    "continuation stuck in escalated state",
				EntityID:   cnt.ContinuationID,
				EntityType: "continuation",
			})
		}
	}

	r.StoreStats["continuation_states"] = len(stateCounts)

	if len(orphanedApprovals) > 0 {
		r.Warnings = append(r.Warnings, Warning{
			Code:     "CONT_ORPHAN_APPR",
			Severity: "low",
			Category: "continuation_store",
			Message:  fmt.Sprintf("found %d continuations with approval IDs in non-approval states", len(orphanedApprovals)),
			Detail:   fmt.Sprintf("examples: %v", orphanedApprovals[:min(3, len(orphanedApprovals))]),
		})
	}

	var zeroTimeConts []string
	for _, cnt := range all {
		if cnt.CreatedAt.IsZero() {
			zeroTimeConts = append(zeroTimeConts, cnt.ContinuationID)
		}
	}
	if len(zeroTimeConts) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "CONT_ZERO_CREATED",
			Severity:   "medium",
			Category:   "continuation_store",
			Message:    fmt.Sprintf("found %d continuations with zero CreatedAt", len(zeroTimeConts)),
			EntityType: "continuation",
			Detail:     fmt.Sprintf("IDs: %v", zeroTimeConts[:min(5, len(zeroTimeConts))]),
		})
	}
}

func (c *Checker) checkExecutionStore(r *Result) {
	if c.executionStore == nil {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "execution_store",
			Message:    "execution store not configured",
		})
		return
	}

	total, succeeded, failed, running, timedOut := c.executionStore.Stats()
	r.StoreStats["executions_total"] = total
	r.StoreStats["executions_succeeded"] = succeeded
	r.StoreStats["executions_failed"] = failed
	r.StoreStats["executions_running"] = running
	r.StoreStats["executions_timed_out"] = timedOut

	all := c.executionStore.ListAll()
	var zeroTimeExecs []string
	var duplicateIDs []string
	seenIDs := make(map[string]bool)

	for _, exe := range all {
		if exe.StartedAt.IsZero() {
			zeroTimeExecs = append(zeroTimeExecs, exe.ExecutionID)
		}
		if seenIDs[exe.ExecutionID] {
			duplicateIDs = append(duplicateIDs, exe.ExecutionID)
		}
		seenIDs[exe.ExecutionID] = true

		if exe.ContinuationID != "" && c.continuationStore != nil {
			if _, exists := c.continuationStore.Get(exe.ContinuationID); !exists {
				r.Issues = append(r.Issues, Issue{
					Code:       "EXEC_ORPHAN_CNT",
					Severity:   "high",
					Category:   "cross_store",
					Message:    "execution references non-existent continuation",
					EntityID:   exe.ExecutionID,
					EntityType: "execution",
					Detail:     fmt.Sprintf("continuation_id=%s", exe.ContinuationID),
				})
			}
		}
	}

	if len(zeroTimeExecs) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "EXEC_ZERO_START",
			Severity:   "medium",
			Category:   "execution_store",
			Message:    fmt.Sprintf("found %d executions with zero StartedAt", len(zeroTimeExecs)),
			EntityType: "execution",
			Detail:     fmt.Sprintf("IDs: %v", zeroTimeExecs[:min(5, len(zeroTimeExecs))]),
		})
	}

	if len(duplicateIDs) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "EXEC_DUP",
			Severity:   "high",
			Category:   "execution_store",
			Message:    fmt.Sprintf("found %d duplicate execution IDs", len(duplicateIDs)),
			EntityType: "execution",
			Detail:     fmt.Sprintf("IDs: %v", duplicateIDs[:min(5, len(duplicateIDs))]),
		})
	}

	if running > 10 {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "medium",
			Category:   "execution_store",
			Message:    fmt.Sprintf("unusually high running execution count: %d", running),
		})
	}
}

func (c *Checker) checkReceiptStore(r *Result) {
	if c.receiptStore == nil {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "receipt_store",
			Message:    "receipt store not configured",
		})
		return
	}

	all := c.receiptStore.ListAll()
	r.StoreStats["receipts"] = len(all)

	var duplicateIDs []string
	seenIDs := make(map[string]bool)
	for _, rec := range all {
		if seenIDs[rec.ReceiptID] {
			duplicateIDs = append(duplicateIDs, rec.ReceiptID)
		}
		seenIDs[rec.ReceiptID] = true
	}

	if len(duplicateIDs) > 0 {
		r.Issues = append(r.Issues, Issue{
			Code:       "RECEIPT_DUP",
			Severity:   "high",
			Category:   "receipt_store",
			Message:    fmt.Sprintf("found %d duplicate receipt IDs", len(duplicateIDs)),
			EntityType: "receipt",
			Detail:     fmt.Sprintf("IDs: %v", duplicateIDs[:min(5, len(duplicateIDs))]),
		})
	}
}

func (c *Checker) checkApprovalStore(r *Result) {
	if c.approvalStore == nil {
		r.Warnings = append(r.Warnings, Warning{
			Severity:   "low",
			Category:   "approval_store",
			Message:    "approval store not configured",
		})
		return
	}

	pending := c.approvalStore.ListByStatus(approval.StatusPending)
	r.StoreStats["approvals_pending"] = len(pending)

	for _, appr := range pending {
		if appr.ApprovalID == "" {
			r.Issues = append(r.Issues, Issue{
				Code:       "APPR_EMPTY_ID",
				Severity:   "medium",
				Category:   "approval_store",
				Message:    "approval with empty approval ID in pending list",
				EntityType: "approval",
			})
		}
	}
}

func (c *Checker) checkCrossStoreReferences(r *Result) {
	if c.eventStore == nil || c.continuationStore == nil {
		return
	}

	events := c.eventStore.List(1000)
	for _, evt := range events {
		if evt.ApprovalID != "" && c.approvalStore != nil {
			if _, err := c.approvalStore.Get(evt.ApprovalID); err != nil {
				r.Warnings = append(r.Warnings, Warning{
					Code:       "EVT_ORPHAN_APPR",
					Severity:   "low",
					Category:   "cross_store",
					Message:    "event references non-existent approval",
					EntityID:   evt.EventID,
					EntityType: "event",
					Detail:     fmt.Sprintf("approval_id=%s", evt.ApprovalID),
				})
			}
		}
	}

	if c.executionStore == nil || c.continuationStore == nil {
		return
	}

	execs := c.executionStore.ListAll()
	for _, exe := range execs {
		if exe.ContinuationID != "" {
			if _, exists := c.continuationStore.Get(exe.ContinuationID); !exists {
				r.Issues = append(r.Issues, Issue{
					Severity:   "high",
					Category:   "cross_store",
					Message:    "execution references non-existent continuation",
					EntityID:   exe.ExecutionID,
					EntityType: "execution",
					Detail:     fmt.Sprintf("continuation_id=%s", exe.ContinuationID),
				})
			}
		}
	}
}

func (c *Checker) summarize(r *Result) {
	r.Summary.TotalIssues = len(r.Issues)
	r.Summary.TotalWarnings = len(r.Warnings)

	for _, issue := range r.Issues {
		switch issue.Severity {
		case "critical":
			r.Summary.Critical++
		case "high":
			r.Summary.High++
		case "medium":
			r.Summary.Medium++
		case "low":
			r.Summary.Low++
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}