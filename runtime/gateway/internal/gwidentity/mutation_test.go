package gwidentity

import (
	"bytes"
	"testing"
)

// PoP preimage mutation property: (domain, gateway_id, key_id,
// challenge) are all inside the signed message — a same-length swap
// of any of them must change the bytes a prover signs.
func TestPopMessage_FieldMutationChangesPreimage(t *testing.T) {
	ch := bytes.Repeat([]byte{0x42}, ChallengeLen)
	base := popMessage("gw_a", "gk_a", ch)
	mutations := []struct {
		name string
		got  []byte
	}{
		{"gateway_id", popMessage("gw_b", "gk_a", ch)},
		{"key_id", popMessage("gw_a", "gk_b", ch)},
		{"challenge", popMessage("gw_a", "gk_a", bytes.Repeat([]byte{0x43}, ChallengeLen))},
	}
	for _, m := range mutations {
		if bytes.Equal(m.got, base) {
			t.Errorf("%s: pop message unchanged by mutation", m.name)
		}
	}
}
