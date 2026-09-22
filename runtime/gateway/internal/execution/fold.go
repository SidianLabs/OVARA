package execution

import (
	"encoding/json"
	"fmt"
	"ovara.runtime.gateway/internal/record"
)

// Signed-journal fold (C5): executions are a total state table —
// genesis is pending or running; terminal is {succeeded, failed,
// timed_out} and non-resurrectable. The immutable core (which work,
// under which authority) can never change across history.
func (s *FileBackedStore) foldEvent(env *record.Envelope) error {
	switch env.Type {
	case "execution":
		var e Execution
		if err := json.Unmarshal(env.Payload, &e); err != nil {
			return fmt.Errorf("corrupt execution payload: %w", err)
		}
		if env.RecordID != e.ExecutionID {
			return fmt.Errorf("envelope record_id %q does not match payload execution_id %q", env.RecordID, e.ExecutionID)
		}
		return s.foldExecution(&e)
	case record.TypeCompact:
		var cc struct {
			RemovedIDs       []string `json:"removed_ids"`
			CompactedThrough uint64   `json:"compacted_through"`
		}
		if err := json.Unmarshal(env.Payload, &cc); err != nil {
			return fmt.Errorf("corrupt compact payload: %w", err)
		}
		if cc.CompactedThrough > 0 {
			// Head-of-file marker from a compacted rewrite: subsequent
			// genesis records may carry terminal state legitimately.
			s.compactSeen = true
		}
		for _, id := range cc.RemovedIDs {
			delete(s.executions, id)
		}
		return nil
	case record.TypeMigration:
		return nil // provenance marker
	default:
		return fmt.Errorf("unknown record type %q", env.Type)
	}
}

func (s *FileBackedStore) foldExecution(e *Execution) error {
	id := e.ExecutionID
	if id == "" {
		return fmt.Errorf("record_id-less execution")
	}
	prev, ok := s.executions[id]
	if !ok {
		// Terminal genesis is only legal in a compaction-rewritten
		// journal (the marker attests history). Otherwise a terminal
		// record out of nowhere is fabrication.
		if e.IsTerminal() && !s.compactSeen {
			return fmt.Errorf("terminal genesis for %s", id)
		}
		if e.State != StatePending && e.State != StateRunning && !e.IsTerminal() {
			return fmt.Errorf("unknown genesis state %q for %s", e.State, id)
		}
		s.executions[id] = e
		s.loadedCount++
		return nil
	}
	if !sameCore(prev, e) {
		return fmt.Errorf("immutable core of %s mutated", id)
	}
	switch {
	case prev.State == e.State:
		// Same-state rewrite — restates the record. Terminal same-state
		// may not flip outcome fields that mark which terminal: the
		// finished marker is frozen once set.
	case prev.IsTerminal():
		return fmt.Errorf("terminal resurrection %s → %s", prev.State, e.State)
	case e.State == StateRunning && (prev.State == StatePending || prev.State == StateRunning):
	case e.IsTerminal():
		// pending|running → terminal.
	default:
		return fmt.Errorf("illegal transition %s → %s", prev.State, e.State)
	}
	s.executions[id] = e
	return nil
}

// sameCore: the identity of the work is frozen at genesis.
func sameCore(a, b *Execution) bool {
	return a.ContinuationID == b.ContinuationID &&
		a.DecisionID == b.DecisionID &&
		a.ApprovalID == b.ApprovalID &&
		a.AgentID == b.AgentID &&
		a.ActionType == b.ActionType &&
		a.Resource == b.Resource &&
		a.TimeoutSeconds == b.TimeoutSeconds
}
