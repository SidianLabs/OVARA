package record

import (
	"os"
	"path/filepath"
	"testing"
)

// Crash injection: a process can die at any byte while appending. For every
// possible torn length of a valid journal, Open must either fail cleanly or
// yield a journal at a committed position, and that journal must stay
// usable: it accepts another append and reopens afterwards. A tear that
// leaves a journal which cannot be appended to or reopened is exactly the
// "one crash bricks the store" failure.
func TestCrashAtEveryByteOffsetLeavesAUsableJournal(t *testing.T) {
	e := setup(t)
	master := filepath.Join(e.dir, "master.journal")
	write3(t, e, master)
	full, err := os.ReadFile(master)
	if err != nil {
		t.Fatal(err)
	}

	for n := 0; n <= len(full); n++ {
		p := filepath.Join(e.dir, "torn.journal")
		if err := os.WriteFile(p, full[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
		if err != nil {
			// A clean refusal is acceptable; panics and hangs are not.
			continue
		}
		seq, _ := j.Tip()
		if seq > 3 {
			t.Fatalf("offset %d: tip %d beyond what was written", n, seq)
		}
		if _, _, err := j.Append("continuation", "after-crash", map[string]string{"v": "x"}, nil); err != nil {
			t.Fatalf("offset %d: journal opened but cannot be appended to: %v", n, err)
		}
		j.Close()

		j2, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
		if err != nil {
			t.Fatalf("offset %d: journal bricked after a post-crash append: %v", n, err)
		}
		if s2, _ := j2.Tip(); s2 != seq+1 {
			t.Fatalf("offset %d: tip %d after reopen, want %d", n, s2, seq+1)
		}
		j2.Close()
	}
}
