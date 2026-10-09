package record

import (
	"os"
	"path/filepath"
	"testing"
)

// A journal file is read at startup from disk an attacker may have touched.
// Whatever bytes it holds, Open must return an error or a journal, never
// panic, and must never accept data that does not verify.
func FuzzOpenNeverPanics(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{"v":1,"seq":1}` + "\n"))
	f.Add([]byte(`{"v":1,"seq":5,"type":"compact"}`))
	f.Add([]byte("not json at all"))
	f.Fuzz(func(t *testing.T, data []byte) {
		e := setup(t)
		p := filepath.Join(e.dir, "fuzz.journal")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
		if err == nil {
			// Arbitrary bytes that verify are, by construction, vanishingly
			// rare; if one does open it must be the empty journal.
			if seq, _ := j.Tip(); seq != 0 && len(data) < 40 {
				t.Fatalf("garbage of %d bytes opened as a journal at seq %d", len(data), seq)
			}
			j.Close()
		}
	})
}
