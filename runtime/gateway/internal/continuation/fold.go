package continuation

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"ovara.runtime.gateway/internal/record"
)

// Signed-journal fold (C5): the continuation journal is a total state
// machine — every (folded state, event) pair is either a legal
// transition applied to the fold or an error that refuses the store.
// There are no ignored events, no skipped events, no best-effort
// events, and no unknown-type acceptance. Terminal states cannot be
// resurrected; the immutable authority core of a record_id can never
// change across its history.

// foldEvent applies one verified envelope to the folded state.
// Signature/seq/parent/domain are already verified by record.Open —
// this callback owns semantic legality only.
func (s *FileBackedStore) foldEvent(env *record.Envelope) error {
	switch env.Type {
	case "continuation":
		var c Continuation
		if err := json.Unmarshal(env.Payload, &c); err != nil {
			return fmt.Errorf("corrupt continuation payload: %w", err)
		}
		if env.RecordID != c.ContinuationID {
			return fmt.Errorf("envelope record_id %q does not match payload continuation_id %q", env.RecordID, c.ContinuationID)
		}
		return s.foldContinuation(&c)
	case record.TypeTombstone:
		var tb struct {
			State string `json:"state"`
		}
		if err := json.Unmarshal(env.Payload, &tb); err != nil || tb.State == "" {
			return fmt.Errorf("corrupt tombstone payload")
		}
		return s.foldTombstone(env.RecordID, State(tb.State))
	case record.TypeCompact:
		var cc struct {
			RemovedIDs []string `json:"removed_ids"`
			// compacted-start marker fields (set when this record heads a
			// rewritten journal — record.Open already validated them)
			CompactedThrough uint64 `json:"compacted_through"`
			PriorTip         string `json:"prior_tip"`
		}
		if err := json.Unmarshal(env.Payload, &cc); err != nil {
			return fmt.Errorf("corrupt compact payload: %w", err)
		}
		s.foldCompact(cc.RemovedIDs)
		return nil
	case record.TypeMigration:
		return nil // provenance marker; imported records follow as normal lines
	default:
		return fmt.Errorf("unknown record type %q", env.Type)
	}
}

// foldContinuation folds one continuation snapshot through the total
// transition table.
func (s *FileBackedStore) foldContinuation(c *Continuation) error {
	id := c.ContinuationID
	if id == "" {
		return fmt.Errorf("record_id-less continuation")
	}
	prev, ok := s.continuations[id]
	if !ok {
		if c.IsTerminal() {
			return fmt.Errorf("terminal genesis for %s", id)
		}
		s.continuations[id] = c
		s.loadedCount++
		return nil
	}
	if !sameCore(prev, c) {
		return fmt.Errorf("immutable core of %s mutated", id)
	}
	if err := checkTransition(prev, c); err != nil {
		return fmt.Errorf("illegal transition %s: %w", id, err)
	}
	s.continuations[id] = c
	return nil
}

// foldTombstone folds a compaction tombstone: the record's payload is
// pruned but its terminality survives. A tombstone over live state is
// a fold error — tombstones may only rest on terminal or pruned
// records.
func (s *FileBackedStore) foldTombstone(id string, st State) error {
	if !isTerminalState(st) {
		return fmt.Errorf("non-terminal tombstone for %s", id)
	}
	prev, ok := s.continuations[id]
	if ok && !prev.IsTerminal() {
		return fmt.Errorf("tombstone over live record %s (%s)", id, prev.State)
	}
	s.continuations[id] = &Continuation{ContinuationID: id, State: st}
	s.tombstones[id] = true
	return nil
}

// foldCompact applies a signed compact event: terminal records become
// tombstones (existence survives, payload pruned); live records are
// deleted outright.
func (s *FileBackedStore) foldCompact(removed []string) {
	for _, id := range removed {
		c, ok := s.continuations[id]
		if !ok {
			continue
		}
		if c.IsTerminal() {
			s.continuations[id] = &Continuation{ContinuationID: id, State: c.State}
			s.tombstones[id] = true
			continue
		}
		delete(s.continuations, id)
		delete(s.tombstones, id)
	}
}

func isTerminalState(st State) bool {
	return st == StateDenied || st == StateExpired || st == StateExecuted || st == StateCancelled
}

// sameCore verifies the immutable authority core is byte-identical
// across two snapshots of one record_id.
func sameCore(a, b *Continuation) bool {
	return a.DecisionID == b.DecisionID &&
		a.ApprovalID == b.ApprovalID &&
		a.AgentID == b.AgentID &&
		a.ActionType == b.ActionType &&
		a.Resource == b.Resource &&
		a.Environment == b.Environment &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.PolicyVersion == b.PolicyVersion &&
		a.CapabilityRef == b.CapabilityRef &&
		a.LeaseID == b.LeaseID &&
		equalPtrTime(a.AuthorityExpiresAt, b.AuthorityExpiresAt) &&
		equalPtrTime(a.ExpiresAt, b.ExpiresAt) &&
		slices.Equal(a.DelegationKeys, b.DelegationKeys) &&
		slices.Equal(a.Issuers, b.Issuers) &&
		a.MaxRetries == b.MaxRetries
}

func equalPtrTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// checkTransition is the C5 total table, encoding exactly the guards
// the store methods apply — nothing the runtime can write is rejected,
// nothing else is accepted.
func checkTransition(prev, next *Continuation) error {
	if prev.State == next.State {
		// Idempotent rewrite: legal for non-terminal states. A terminal
		// same-state write restates evidence; the executed outcome may
		// never flip — that would undo the retry boundary.
		if next.State == StateExecuted &&
			prev.LastExecutionSucceeded != next.LastExecutionSucceeded {
			return fmt.Errorf("executed outcome flip")
		}
		// Terminal same-state rewrites restate evidence (a raced
		// MarkRequeue+Update on a denied record writes it back
		// unchanged) — semantically a no-op, and the immutable core is
		// already enforced, so they fold legally.
		return nil
	}
	if prev.IsTerminal() {
		// Sole legal exit from terminal: retry of a FAILED execution.
		if prev.State == StateExecuted && next.State == StateResumed &&
			!prev.LastExecutionSucceeded {
			return nil
		}
		return fmt.Errorf("terminal resurrection %s → %s", prev.State, next.State)
	}
	switch next.State {
	case StateApproved, StateDenied, StateResumed, StateExpired:
		return nil // every non-terminal state may approve/deny/resume/expire
	case StateQueued:
		if prev.State == StateApproved || prev.State == StateExecuting {
			return nil // MarkQueued, MarkRequeue
		}
	case StateExecuting:
		if prev.State == StateApproved || prev.State == StateQueued ||
			prev.State == StateResumed {
			return nil // claim boundary
		}
	case StateExecuted:
		if prev.State == StateExecuting || prev.State == StateResumed {
			return nil // MarkExecuted, MarkExecutionFailed
		}
	case StateCancelled:
		if prev.State == StateQueued || prev.State == StateResumed {
			return nil // MarkCancelled
		}
	case StateEscalated:
		return fmt.Errorf("back-transition to escalated")
	default:
		return fmt.Errorf("unknown state %q", next.State)
	}
	return fmt.Errorf("illegal transition %s → %s", prev.State, next.State)
}
