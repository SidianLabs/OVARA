package lineage

import (
	"crypto/ed25519"
	"testing"

	"ovara.runtime.gateway/internal/revocation"
)

func TestAnchorFile_RoundTrip(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	a := &Anchor{
		DomainID:         "dom_x",
		GatewayKeys:      map[string]ed25519.PublicKey{"gw|k1": pub},
		IssuerKeys:       map[string]ed25519.PublicKey{"iss": pub},
		ApproverKeys:     map[string]ed25519.PublicKey{"a1": pub},
		LedgerKeys:       map[string]ed25519.PublicKey{"dom_x/ledger": pub},
		ExpectedAudience: "gw",
		Revocations:      map[revocation.Pair]bool{{Class: "issuer", Target: "x"}: true},
		Epoch:            7,
	}
	back, err := a.File().Anchor()
	if err != nil {
		t.Fatal(err)
	}
	if back.DomainID != a.DomainID || back.Epoch != a.Epoch ||
		back.ExpectedAudience != a.ExpectedAudience ||
		len(back.GatewayKeys) != 1 || len(back.Revocations) != 1 {
		t.Fatalf("round trip drifted: %+v", back)
	}
}

func TestAnchorFile_MalformedKey(t *testing.T) {
	for _, h := range []string{"zzzz", "abcd"} {
		f := &AnchorFile{GatewayKeys: map[string]string{"gw|k1": h}}
		if _, err := f.Anchor(); err == nil {
			t.Errorf("key %q accepted", h)
		}
	}
}
