// The emitting domain's lineage store — a signed, hash-chained,
// tip-ledgered journal like every other authority store. Each emitted
// bundle is appended as one record; the store also resolves "the
// latest bundle for a decision" so a later stage emits an enriched
// (never rewritten) artifact.
package lineage

import (
	"encoding/json"
	"fmt"

	"ovara.runtime.gateway/internal/record"
)

// Store is the emitting domain's durable record of emitted bundles.
type Store struct {
	j          *record.Journal
	byDecision map[string]*Bundle // decision_id → latest-stage bundle
	tipsSink   func(seq uint64, hash string) error
}

// OpenStore opens (or creates) the lineage journal. binding is the
// gateway's journal binding — emitted bundles are authority records,
// so they carry the same signed/chained/floor-checked guarantees.
func OpenStore(path string, binding *record.Binding) (*Store, error) {
	s := &Store{byDecision: map[string]*Bundle{}}
	j, err := record.Open("lineage", path, binding.Signer.Domain(), binding.Signer, binding.Resolve, binding.Floor,
		func(env *record.Envelope) error {
			if env.Type != "lineage" {
				return fmt.Errorf("lineage store: unexpected record type %s", env.Type)
			}
			var b Bundle
			if err := json.Unmarshal(env.Payload, &b); err != nil {
				return fmt.Errorf("lineage store: corrupt bundle: %w", err)
			}
			decID := ""
			if b.Receipt != nil {
				decID = b.Receipt.DecisionID
			}
			if decID == "" {
				return fmt.Errorf("lineage store: bundle %s carries no decision binding", b.LineageID)
			}
			s.byDecision[decID] = &b
			return nil
		})
	if err != nil {
		return nil, err
	}
	s.j = j
	return s, nil
}

// Put appends the emitted bundle (post-inclusion, so the durable
// record is exactly what a verifier would check). Failure propagates —
// the emitter treats it like any evidence-write failure.
func (s *Store) Put(b *Bundle) error {
	// Same rule as the fold below: a bundle without a receipt carries no
	// decision binding — refuse it BEFORE the append, or the journal
	// would hold a record no reopen can fold (and the index deref below
	// would panic after the damage was done).
	if b.Receipt == nil || b.Receipt.DecisionID == "" {
		return fmt.Errorf("lineage store: bundle %s carries no decision binding", b.LineageID)
	}
	seq, tip, err := s.j.Append("lineage", b.LineageID, b, nil)
	if err != nil {
		return err
	}
	if s.tipsSink != nil {
		if err := s.tipsSink(seq, tip); err != nil {
			return err
		}
	}
	if s.byDecision == nil {
		s.byDecision = map[string]*Bundle{}
	}
	s.byDecision[b.Receipt.DecisionID] = b
	return nil
}

// SetTipsSink wires the committed-floor hook (gwidentity tip-ledger),
// same convention as the other signed stores.
func (s *Store) SetTipsSink(fn func(seq uint64, hash string) error) { s.tipsSink = fn }

// JournalTip exposes the journal's committed (seq, tip hash) for
// open-time floor ratcheting.
func (s *Store) JournalTip() (uint64, string) { return s.j.Tip() }

// ByDecision returns the latest emitted bundle for a decision id — the
// base a later stage enriches. Nil when no lineage exists yet.
func (s *Store) ByDecision(decisionID string) *Bundle { return s.byDecision[decisionID] }

// Close flushes and closes the journal.
func (s *Store) Close() error { return s.j.Close() }
