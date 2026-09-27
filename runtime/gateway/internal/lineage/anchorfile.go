package lineage

// AnchorFile is the JSON wire form of Anchor — the pinned view of the
// issuing domain a receiving domain holds, moved between domains as
// one document. `gwctl export-anchor` produces it from the domain
// registry; `linverify -anchor` consumes it. It carries public
// material only — an anchor never contains private keys. Keys inside
// a bundle are never trusted; this file IS the trust.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"

	"ovara.runtime.gateway/internal/revocation"
)

type AnchorFile struct {
	DomainID         string            `json:"domain_id"`
	GatewayKeys      map[string]string `json:"gateway_keys"`  // "gateway_id|key_id" → hex pub
	IssuerKeys       map[string]string `json:"issuer_keys"`   // issuer → hex pub
	ApproverKeys     map[string]string `json:"approver_keys"` // key_id → hex pub
	LedgerKeys       map[string]string `json:"ledger_keys"`   // ledger_domain → hex pub
	ExpectedAudience string            `json:"expected_audience,omitempty"`
	Revocations      []revocation.Pair `json:"revocations,omitempty"`
	Epoch            uint64            `json:"epoch,omitempty"`
}

// File renders the anchor in its portable form for hand-off.
func (a *Anchor) File() *AnchorFile {
	f := &AnchorFile{
		DomainID:         a.DomainID,
		ExpectedAudience: a.ExpectedAudience,
		Epoch:            a.Epoch,
		GatewayKeys:      hexKeys(a.GatewayKeys),
		IssuerKeys:       hexKeys(a.IssuerKeys),
		ApproverKeys:     hexKeys(a.ApproverKeys),
		LedgerKeys:       hexKeys(a.LedgerKeys),
	}
	for p := range a.Revocations {
		f.Revocations = append(f.Revocations, p)
	}
	sort.Slice(f.Revocations, func(i, j int) bool {
		if f.Revocations[i].Class != f.Revocations[j].Class {
			return f.Revocations[i].Class < f.Revocations[j].Class
		}
		return f.Revocations[i].Target < f.Revocations[j].Target
	})
	return f
}

// Anchor decodes the file form into the verifier's Anchor. A malformed
// key is a hard error — a degraded anchor must never silently weaken
// the pin set.
func (f *AnchorFile) Anchor() (*Anchor, error) {
	a := &Anchor{DomainID: f.DomainID, ExpectedAudience: f.ExpectedAudience, Epoch: f.Epoch}
	var err error
	if a.GatewayKeys, err = parseKeys(f.GatewayKeys); err != nil {
		return nil, err
	}
	if a.IssuerKeys, err = parseKeys(f.IssuerKeys); err != nil {
		return nil, err
	}
	if a.ApproverKeys, err = parseKeys(f.ApproverKeys); err != nil {
		return nil, err
	}
	if a.LedgerKeys, err = parseKeys(f.LedgerKeys); err != nil {
		return nil, err
	}
	a.Revocations = make(map[revocation.Pair]bool, len(f.Revocations))
	for _, p := range f.Revocations {
		a.Revocations[p] = true
	}
	return a, nil
}

func hexKeys(in map[string]ed25519.PublicKey) map[string]string {
	out := make(map[string]string, len(in))
	for name, k := range in {
		out[name] = hex.EncodeToString(k)
	}
	return out
}

func parseKeys(in map[string]string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(in))
	for name, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: not hex ed25519 (%d bytes)", name, len(b))
		}
		out[name] = b
	}
	return out, nil
}
