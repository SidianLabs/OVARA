package gwidentity

import (
	"path/filepath"
	"testing"
)

// The tip ledger is a floor: it only moves forward. A store that re-seals
// the same seq with different contents (or goes backwards) must be refused
// when it records the tip, not discovered as "equivocation" at next start.
func TestRecordTips_FloorOnlyAdvances(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		var reg *Registry
		if persisted {
			var err error
			if reg, err = Open(filepath.Join(t.TempDir(), "gw.jsonl")); err != nil {
				t.Fatal(err)
			}
			defer reg.Close() // Windows cannot remove the temp dir while the journal is open
		} else {
			reg = NewInMemory()
		}
		rec := func(seq uint64, hash string) error {
			return reg.RecordTips("gw1", map[string]Tip{"idregistry": {Seq: seq, Hash: hash}})
		}
		if err := rec(1, "aa"); err != nil {
			t.Fatal(err)
		}
		if err := rec(1, "aa"); err != nil {
			t.Fatalf("persisted=%v: re-recording the same tip (startup ratchet) refused: %v", persisted, err)
		}
		if err := rec(1, "bb"); err == nil {
			t.Fatalf("persisted=%v: same seq with a different hash accepted", persisted)
		}
		if err := rec(2, "cc"); err != nil {
			t.Fatal(err)
		}
		if err := rec(1, "aa"); err == nil {
			t.Fatalf("persisted=%v: a tip below the floor accepted", persisted)
		}
		if got := reg.LatestTips("gw1")["idregistry"]; got.Seq != 2 || got.Hash != "cc" {
			t.Fatalf("persisted=%v: floor = %+v, want seq 2 cc", persisted, got)
		}
		// another store's tips are independent
		if err := reg.RecordTips("gw1", map[string]Tip{"events": {Seq: 1, Hash: "ee"}}); err != nil {
			t.Fatal(err)
		}
	}
}
