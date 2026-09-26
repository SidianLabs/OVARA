// Package lineage implements cross-domain action lineage: a portable,
// offline-verifiable record of which chain of authority produced an
// action. The emitting domain composes artifacts it already minted —
// the signed decision receipt, the presented capability lease and
// delegation chain, the approver-signed approval journal envelope —
// into one bundle, countersigns it under its gateway journal key, and
// registers the bundle digest on a transparency ledger (SCITT RFC 9943
// semantics: signed statement → registration → inclusion receipt).
//
// A receiving party verifies the bundle offline against a pinned
// trust anchor (issuer/gateway/approver/ledger public keys + a
// revocation snapshot): signature chain, delegation narrowing,
// approval provenance, revocation freshness, and ledger inclusion —
// no contact with the issuing domain.
//
// Specification: docs/ACTION_LINEAGE.md
package lineage

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

const Version = 1

// Stage names the authority boundary the bundle was emitted at.
// Later stages embed the earlier stages' material verbatim — an
// execution bundle is self-contained proof of the whole path.
const (
	StageDecision  = "decision"  // evaluate: receipt + presented authority
	StageApproval  = "approval"  // resolve: approval record + approver env
	StageExecution = "execution" // dispatch: continuation + execution ref
)

// sigPrefix tags bundle signatures, domain-separated from receipts.
const sigPrefix = "lin_v1:"

// BundleDomain separates bundle signatures from every other artifact
// the gateway journal key signs.
const BundleDomain = "OVARA-LINEAGE-BUNDLE-V1"

// InclusionDomain separates ledger inclusion countersignatures.
const InclusionDomain = "OVARA-LINEAGE-INCLUSION-V1"

// ActionRef is the action under attestation.
type ActionRef struct {
	ActionType  string `json:"action_type"`
	Resource    string `json:"resource"`
	AgentID     string `json:"agent_id,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// ExecRef binds the dispatch the lineage culminates in.
type ExecRef struct {
	ContinuationID string `json:"continuation_id"`
	ExecutionID    string `json:"execution_id"`
	State          string `json:"state"`
}

// Inclusion is the SCITT-analogous transparency receipt: the ledger's
// countersignature binding a statement digest to a position in its
// append-only journal.
type Inclusion struct {
	LedgerDomain string `json:"ledger_domain"`
	Seq          uint64 `json:"seq"`
	Parent       string `json:"parent"`
	Digest       string `json:"digest"`
	KeyID        string `json:"key_id"`
	Sig          string `json:"sig"` // "lininc_v1:<hex>"
}

// Bundle is the lineage record: every element is already a signed
// artifact (receipt edsig_v1; per-hop delegation signatures; approval
// bound by its approver-signed journal envelope); the bundle signature
// binds the composition under the emitting gateway's journal key.
type Bundle struct {
	V         int       `json:"v"`
	LineageID string    `json:"lineage_id"`
	DomainID  string    `json:"domain_id"`
	Stage     string    `json:"stage"`
	IssuedAt  time.Time `json:"issued_at"`

	Action      ActionRef                 `json:"action"`
	Receipt     *models.Receipt           `json:"receipt"`
	Lease       *models.CapabilityLease   `json:"capability_lease,omitempty"`
	Delegation  *models.DelegationChain   `json:"delegation_chain,omitempty"`
	Approval    *approval.ApprovalRequest `json:"approval,omitempty"`
	ApprovalEnv *record.Envelope          `json:"approval_env,omitempty"`
	Execution   *ExecRef                  `json:"execution,omitempty"`

	Inclusion *Inclusion `json:"inclusion,omitempty"`

	GatewayID    string `json:"gateway_id"`
	GatewayKeyID string `json:"gateway_key_id"`
	Sig          string `json:"sig"` // "lin_v1:<hex>"
}

func lp(b []byte, s string) []byte {
	var l [4]byte
	// #nosec G115 -- the frame is u32-bounded by design (same convention
	// as identity/canon.go); in-memory strings cannot exceed it.
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	return append(l[:], b...)
}

func lpu64(b []byte, v uint64) []byte {
	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], v)
	return append(b, vb[:]...)
}

func digestHex(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Payload is the canonical preimage the bundle signature covers:
// every field except Inclusion (registered after signing) and Sig.
// Member digests bind the opaque signed artifacts without encoding
// their internals twice.
func (b *Bundle) Payload() []byte {
	out := lp(nil, BundleDomain)
	out = lp(out, b.LineageID)
	out = lp(out, b.DomainID)
	out = lp(out, b.Stage)
	// #nosec G115 -- u64 unix nanos is the wire format (same convention
	// as record.signingPayload); post-epoch timestamps only.
	out = lpu64(out, uint64(b.IssuedAt.UnixNano()))
	out = lp(out, b.Action.ActionType)
	out = lp(out, b.Action.Resource)
	out = lp(out, b.Action.AgentID)
	out = lp(out, b.Action.Environment)
	out = lp(out, digestHex(b.Receipt))
	out = lp(out, digestHex(b.Lease))
	out = lp(out, digestHex(b.Delegation))
	out = lp(out, digestHex(b.Approval))
	out = lp(out, digestHex(b.ApprovalEnv))
	out = lp(out, digestHex(b.Execution))
	out = lp(out, b.GatewayID)
	out = lp(out, b.GatewayKeyID)
	return out
}

// StatementDigest is the SCITT "signed statement" digest the ledger
// registers: sha256 over the bundle with signature but without the
// inclusion receipt.
func (b *Bundle) StatementDigest() string {
	cp := *b
	cp.Inclusion = nil
	return digestHex(&cp)
}

// Signed reports whether the bundle carries a well-formed signature tag.
func (b *Bundle) Signed() bool {
	return len(b.Sig) > len(sigPrefix) && b.Sig[:len(sigPrefix)] == sigPrefix
}

// InclusionPayload is the preimage the ledger countersigns: the
// statement digest bound to a position in the ledger's own chain.
func InclusionPayload(ledgerDomain, digest string, seq uint64, parent string) []byte {
	out := lp(nil, InclusionDomain)
	out = lp(out, ledgerDomain)
	out = lp(out, digest)
	out = lpu64(out, seq)
	return lp(out, parent)
}
