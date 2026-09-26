// The verifier — domain B's side. Verify is offline: the pinned Anchor
// is the entire trust input; no call to the issuing domain, no shared
// database. The pass is layered and fail-closed — every layer must
// hold, and the verdict names whichever one failed.
package lineage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/record"
	"ovara.runtime.gateway/internal/revocation"
)

// Anchor is the receiving domain's pinned view of the issuing domain:
// the public keys and revocation snapshot the lineage is judged
// against. Keys inside the artifact are NEVER trusted — only
// resolution hints. Distribution is out-of-band (registry export /
// anchor sync); staleness is the caller's policy problem.
type Anchor struct {
	// DomainID — bundles from any other domain are rejected outright.
	DomainID string
	// GatewayKeys resolves (gateway_id, key_id) → the issuing
	// gateway's public key. The bundle and its receipt verify under it.
	GatewayKeys map[string]ed25519.PublicKey
	// IssuerKeys resolves delegation-hop / lease issuers → public key.
	// A hop signed by an untrusted issuer fails — caller-minted chains
	// cannot verify.
	IssuerKeys map[string]ed25519.PublicKey
	// ApproverKeys is the pinned set of USABLE approver-role keys
	// (key_id → pub). An approval envelope signed under a key absent
	// here — e.g. revoked before the snapshot — fails provenance.
	ApproverKeys map[string]ed25519.PublicKey
	// LedgerKeys resolves inclusion.ledger_domain → the transparency
	// ledger's countersigning key.
	LedgerKeys map[string]ed25519.PublicKey
	// ExpectedAudience is the audience string the chain/lease were
	// minted for (the issuing gateway's audience). Empty = skip.
	ExpectedAudience string
	// Revocations is the pinned revocation view: the pairs the lineage
	// derives must not be present. This is the "still valid?" half.
	Revocations map[revocation.Pair]bool
	// Epoch is the snapshot epoch — informational only.
	Epoch uint64
}

// Verdict reports accept/reject plus the layer that decided.
type Verdict struct {
	Accept bool     `json:"accept"`
	Layer  string   `json:"layer"`
	Detail string   `json:"detail,omitempty"`
	Layers []string `json:"layers,omitempty"` // layers passed, in order
}

func layerOK(layers []string, layer string) []string { return append(layers, layer) }
func reject(layer, format string, args ...any) *Verdict {
	return &Verdict{Accept: false, Layer: layer, Detail: fmt.Sprintf(format, args...)}
}

// ResolvePublicKey makes Anchor a receipt.KeyResolver — the receipt's
// existing edsig verifier runs unmodified against the pinned view.
func (a *Anchor) ResolvePublicKey(gatewayID, keyID string) (ed25519.PublicKey, error) {
	pub, ok := a.GatewayKeys[gatewayID+"|"+keyID]
	if !ok {
		return nil, fmt.Errorf("lineage: gateway key %s/%s not pinned", gatewayID, keyID)
	}
	return pub, nil
}

// Verify checks one bundle against the pinned anchor. Offline and
// fail-closed: shape → inclusion → bundle signature → receipt →
// delegation → lease → approval → revocation. Returns a verdict even
// when a stage errors — an unverifiable artifact is a rejection, not
// a crash.
func Verify(b *Bundle, a *Anchor) *Verdict {
	if b == nil || a == nil {
		return reject("input", "nil bundle or anchor")
	}
	var passed []string

	// 1 — shape & domain.
	if b.V != Version || b.LineageID == "" || b.DomainID == "" ||
		b.Action.ActionType == "" || b.Action.Resource == "" || b.IssuedAt.IsZero() {
		return reject("shape", "malformed bundle")
	}
	switch b.Stage {
	case StageDecision, StageApproval, StageExecution:
	default:
		return reject("shape", "unknown stage %q", b.Stage)
	}
	if b.DomainID != a.DomainID {
		return reject("domain", "bundle belongs to domain %q, not %q", b.DomainID, a.DomainID)
	}
	passed = layerOK(passed, "shape")

	// 2 — ledger inclusion (SCITT receipt): digest must cover the
	// signed statement and the countersignature must verify under the
	// pinned ledger key for the named ledger domain.
	if b.Inclusion == nil {
		return reject("inclusion", "no ledger inclusion receipt")
	}
	if digest := b.StatementDigest(); digest != b.Inclusion.Digest {
		return reject("inclusion", "inclusion digest does not match the signed statement")
	}
	ledPub, ok := a.LedgerKeys[b.Inclusion.LedgerDomain]
	if !ok {
		return reject("inclusion", "ledger %q not pinned", b.Inclusion.LedgerDomain)
	}
	if !VerifyInclusion(ledPub, b.Inclusion) {
		return reject("inclusion", "ledger countersignature invalid")
	}
	passed = layerOK(passed, "inclusion")

	// 3 — bundle signature under the emitting gateway's journal key.
	if !b.Signed() {
		return reject("signature", "bundle unsigned")
	}
	sigBytes, err := hex.DecodeString(b.Sig[len(sigPrefix):])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return reject("signature", "malformed bundle signature")
	}
	gwPub, ok := a.GatewayKeys[b.GatewayID+"|"+b.GatewayKeyID]
	if !ok {
		return reject("signature", "gateway key %s/%s not pinned", b.GatewayID, b.GatewayKeyID)
	}
	if !ed25519.Verify(gwPub, b.Payload(), sigBytes) {
		return reject("signature", "bundle signature invalid")
	}
	passed = layerOK(passed, "signature")

	// 4 — receipt: must exist, must carry the gateway's edsig
	// signature verifying under the pinned key, and must describe the
	// same action the bundle attests.
	if b.Receipt == nil {
		return reject("receipt", "no decision receipt")
	}
	if b.Receipt.ActionType != b.Action.ActionType ||
		b.Receipt.Resource != b.Action.Resource ||
		(b.Receipt.AgentID != "" && b.Action.AgentID != "" && b.Receipt.AgentID != b.Action.AgentID) {
		return reject("receipt", "receipt/action mismatch")
	}
	valid, err := receipt.VerifySignature(a, b.Receipt)
	if err != nil || !valid {
		return reject("receipt", "receipt signature invalid: %v", err)
	}
	passed = layerOK(passed, "receipt")

	// 5+6 — presented authority through the REAL eval-side validator:
	// hop signatures, linkage, non-amplification, expiry, audience,
	// terminal subject binding; lease signature and scope coverage.
	val := identity.NewValidatorWithTrustedKeys(issuerKeysAsBytes(a))
	val.SetExpectedAudience(a.ExpectedAudience)
	val.SetRevocation(anchorChecker{a})
	if b.Delegation != nil {
		res := val.ValidateDelegationChain(b.Delegation, b.Action.AgentID, nil)
		if !res.Valid {
			return reject("delegation", "%s", strings.Join(res.Reasons, "; "))
		}
		passed = layerOK(passed, "delegation")
	}
	if b.Lease != nil {
		res := val.ValidateCapabilityLease(b.Lease)
		if !res.Valid {
			return reject("lease", "%s", strings.Join(res.Reasons, "; "))
		}
		if scope := val.ValidateCapabilityLeaseScope(b.Lease, b.Action.ActionType, b.Action.Resource); !scope.Valid {
			return reject("lease", "%s", strings.Join(scope.Reasons, "; "))
		}
		passed = layerOK(passed, "lease")
	}

	// 7 — approval provenance (when claimed): the approval record must
	// match the action/decision context, and its journal envelope must
	// verify under a PINNED approver key — a key revoked before the
	// snapshot is absent from the anchor and fails here.
	if b.Approval != nil {
		ap := b.Approval
		if ap.Status != approval.StatusApproved {
			return reject("approval", "approval %s not approved (status %s)", ap.ApprovalID, ap.Status)
		}
		if ap.DecisionID != b.Receipt.DecisionID ||
			string(ap.ActionType) != b.Action.ActionType ||
			ap.Resource != b.Action.Resource {
			return reject("approval", "approval/action-decision mismatch")
		}
		env := b.ApprovalEnv
		if env == nil {
			return reject("approval", "no approver-signed envelope")
		}
		if env.KeyRef.GatewayID != gwidentity.ApproverID {
			return reject("approval", "envelope not signed under the approver root")
		}
		apPub, ok := a.ApproverKeys[env.KeyRef.KeyID]
		if !ok {
			return reject("approval", "approver key %s not pinned/usable in this view", env.KeyRef.KeyID)
		}
		envSig, err := hex.DecodeString(env.Sig)
		if err != nil || !ed25519.Verify(apPub, record.SigningPayload(env), envSig) {
			return reject("approval", "approval envelope signature invalid")
		}
		raw, err := json.Marshal(ap)
		if err != nil || !bytes.Equal(raw, env.Payload) {
			return reject("approval", "envelope payload does not match the approval record")
		}
		passed = layerOK(passed, "approval")
	}

	// 8 — revocation view: every pair the lineage implies must be
	// absent from the pinned snapshot.
	pairs := pairsFor(b)
	if len(pairs) > 0 {
		for _, p := range pairs {
			if a.Revocations[p] {
				return reject("revocation", "%s %q is revoked in the pinned view", p.Class, p.Target)
			}
		}
	}
	passed = layerOK(passed, "revocation")

	return &Verdict{Accept: true, Layer: "accept", Layers: passed}
}

// pairsFor derives the revocation pairs the lineage asserts:
// lease id, every delegation hop's presentation key + issuer, and the
// pairs the approval record itself captured — the same set the
// gateway's own claim-time boundary checks.
func pairsFor(b *Bundle) []revocation.Pair {
	var pairs []revocation.Pair
	if b.Lease != nil {
		pairs = append(pairs, revocation.P(revocation.ClassLease, b.Lease.LeaseID))
	}
	delegKeys, issuers := identity.ChainRevocationIDs(b.Delegation)
	pairs = append(pairs, revocation.PairsFor("", delegKeys, issuers)...)
	if b.Approval != nil {
		pairs = append(pairs, revocation.PairsFor(b.Approval.LeaseID, b.Approval.DelegationKeys, b.Approval.Issuers)...)
	}
	return pairs
}

func issuerKeysAsBytes(a *Anchor) map[string][]byte {
	out := make(map[string][]byte, len(a.IssuerKeys))
	for k, v := range a.IssuerKeys {
		out[k] = v
	}
	return out
}

// anchorChecker adapts the pinned revocation snapshot to the
// identity validator's revocation.Checker.
type anchorChecker struct{ a *Anchor }

func (c anchorChecker) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	for _, p := range pairs {
		if c.a.Revocations[p] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

func (c anchorChecker) Epoch() (uint64, error) { return c.a.Epoch, nil }
