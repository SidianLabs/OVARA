package idregistry

import (
	"testing"

	"ovara.runtime.gateway/internal/record"
)

// Two mutations against a sealed file-backed registry must advance file_seq
// monotonically (previously the second mutation re-sealed at seq 1, and the
// next Open refused with "equivocation").
func TestMutateAdvancesSealSeq(t *testing.T) {
	signer, resolve := advSigner(t)
	p := t.TempDir() + "/id.json"
	reg, err := Open(p, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.SeedConfig([]string{"tok-a"}, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := reg.SeedConfig([]string{"tok-b"}, "agent"); err != nil {
		t.Fatal(err)
	}
	seq, _ := reg.JournalTip()
	if seq != 2 {
		t.Fatalf("file_seq = %d, want 2", seq)
	}
	// The real failure was on reopen: the floor check saw two different
	// files sealed at the same seq.
	if _, err := Open(p, &record.Binding{Signer: signer, Resolve: resolve}); err != nil {
		t.Fatalf("reopen after two mutations: %v", err)
	}
}
