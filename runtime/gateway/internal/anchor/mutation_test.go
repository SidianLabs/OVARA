package anchor

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Checkpoint preimage mutation property: the monotonic checkpoint's
// signature binds (domain, seq, tip_hash, key_id) — a same-length
// substitution in any of them must move the preimage bytes.
func TestPreimage_FieldMutationChangesBytes(t *testing.T) {
	cp := testCP()
	base, err := cp.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	altTip := strings.Repeat("ac", 32)
	mutations := []struct {
		name string
		mut  func(*Checkpoint)
	}{
		{"domain", func(c *Checkpoint) { c.DomainID = "dom_abc124" }},
		{"seq", func(c *Checkpoint) { c.Seq = 43 }},
		{"tip_hash", func(c *Checkpoint) { c.TipHash = altTip }},
		{"key_id", func(c *Checkpoint) { c.KeyID = "gwk_test2" }},
	}
	for _, m := range mutations {
		c := testCP()
		m.mut(&c)
		got, err := c.Preimage()
		if err != nil {
			t.Fatalf("%s: preimage errored: %v", m.name, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s: checkpoint mutation produced identical preimage", m.name)
		}
	}
	// Malformed tip_hash stays an error — not silently digested.
	c := testCP()
	c.TipHash = hex.EncodeToString([]byte("short"))
	if _, err := c.Preimage(); err == nil {
		t.Error("short tip_hash accepted")
	}
}
