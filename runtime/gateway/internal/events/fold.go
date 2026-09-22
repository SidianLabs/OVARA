package events

import (
	"encoding/json"
	"fmt"

	"ovara.runtime.gateway/internal/record"
)

// Signed-journal fold (C5): events are append-only audit records — an
// envelope's record_id is the event's EventID; duplicates are errors;
// compact records carry {removed_ids} and mark them stale (the legacy
// _cleanup pseudo-record's journal form).
func (s *FileBackedStore) foldEvent(env *record.Envelope) error {
	switch env.Type {
	case "event":
		var evt Event
		if err := json.Unmarshal(env.Payload, &evt); err != nil {
			return fmt.Errorf("corrupt event payload: %w", err)
		}
		if env.RecordID != evt.EventID {
			return fmt.Errorf("envelope record_id %q does not match payload event_id %q", env.RecordID, evt.EventID)
		}
		if evt.EventID == "" {
			return fmt.Errorf("record_id-less event")
		}
		for _, stale := range s.staleEvents {
			if stale == evt.EventID {
				return fmt.Errorf("event %s resurrected after sweep", evt.EventID)
			}
		}
		s.loadedCount++
		s.events = append(s.events, &evt)
		return nil
	case record.TypeCompact:
		var cc struct {
			RemovedIDs []string `json:"removed_ids"`
		}
		if err := json.Unmarshal(env.Payload, &cc); err != nil {
			return fmt.Errorf("corrupt compact payload: %w", err)
		}
		s.staleEvents = append(s.staleEvents, cc.RemovedIDs...)
		s.removeByIDsInMemory(cc.RemovedIDs)
		return nil
	case record.TypeMigration:
		return nil // provenance marker
	default:
		return fmt.Errorf("unknown record type %q", env.Type)
	}
}
