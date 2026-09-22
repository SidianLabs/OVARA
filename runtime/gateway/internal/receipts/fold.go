package receipts

import (
	"encoding/json"
	"fmt"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

// Signed-journal fold (C5): the receipts journal is the durable decision
// journal (D9). Receipts are immutable once written — a second record
// for the same receipt_id is a fold error, as is any unknown record
// type.
func (s *FileBackedStore) foldEvent(env *record.Envelope) error {
	switch env.Type {
	case "receipt":
		var r models.Receipt
		if err := json.Unmarshal(env.Payload, &r); err != nil {
			return fmt.Errorf("corrupt receipt payload: %w", err)
		}
		if env.RecordID != r.ReceiptID {
			return fmt.Errorf("envelope record_id %q does not match payload receipt_id %q", env.RecordID, r.ReceiptID)
		}
		if r.ReceiptID == "" {
			return fmt.Errorf("record_id-less receipt")
		}
		if _, exists := s.receipts[r.ReceiptID]; exists {
			return fmt.Errorf("duplicate receipt record for %s", r.ReceiptID)
		}
		s.receipts[r.ReceiptID] = &r
		return nil
	case record.TypeCompact:
		var cc struct {
			RemovedIDs []string `json:"removed_ids"`
		}
		if err := json.Unmarshal(env.Payload, &cc); err != nil {
			return fmt.Errorf("corrupt compact payload: %w", err)
		}
		for _, id := range cc.RemovedIDs {
			delete(s.receipts, id)
		}
		return nil
	case record.TypeTombstone:
		delete(s.receipts, env.RecordID)
		return nil
	case record.TypeMigration:
		return nil // provenance marker
	default:
		return fmt.Errorf("unknown record type %q", env.Type)
	}
}
