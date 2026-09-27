// Preimage-binding tests (lp class): every canonical builder must
// commit every field's BYTES — a same-length mutation that leaves the
// preimage unchanged means an existing signature still verifies over
// tampered content. Regression coverage for the lp body that returned
// len(s)‖b and dropped s entirely.
package lineage

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// mutSameLen returns s with one byte flipped, preserving length — the
// adversary's move against a length-only preimage.
func mutSameLen(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	b[0] ^= 0x01
	if b[0] == 0 || b[0] == '|' { // stay printable/harmless
		b[0] = 'z'
	}
	return string(b)
}

// TestLinPreimage_PayloadCommitsEveryField mutates each signed field
// (same-length where lp-framed) and asserts Payload() differs. Any
// field that does NOT change the preimage is a signature-blind spot.
func TestLinPreimage_PayloadCommitsEveryField(t *testing.T) {
	d := domASetup(t)
	base := d.honestLineage(t)
	baseP := base.Payload()

	cases := map[string]func(*Bundle){
		"lineage_id":     func(b *Bundle) { b.LineageID = mutSameLen(b.LineageID) },
		"domain_id":      func(b *Bundle) { b.DomainID = mutSameLen(b.DomainID) },
		"stage":          func(b *Bundle) { b.Stage = StageDecision }, // execution→decision, same length family
		"issued_at":      func(b *Bundle) { b.IssuedAt = b.IssuedAt.Add(time.Nanosecond) },
		"action_type":    func(b *Bundle) { b.Action.ActionType = mutSameLen(b.Action.ActionType) },
		"resource":       func(b *Bundle) { b.Action.Resource = mutSameLen(b.Action.Resource) },
		"agent_id":       func(b *Bundle) { b.Action.AgentID = mutSameLen(b.Action.AgentID) },
		"environment":    func(b *Bundle) { b.Action.Environment = mutSameLen(b.Action.Environment) },
		"gateway_id":     func(b *Bundle) { b.GatewayID = mutSameLen(b.GatewayID) },
		"gateway_key_id": func(b *Bundle) { b.GatewayKeyID = mutSameLen(b.GatewayKeyID) },
		"receipt_member": func(b *Bundle) { b.Receipt.ReceiptID = mutSameLen(b.Receipt.ReceiptID) },
		"lease_member":   func(b *Bundle) { b.Lease.LeaseID = mutSameLen(b.Lease.LeaseID) },
		"delegation_member": func(b *Bundle) {
			b.Delegation.Authorities[0].Nonce = mutSameLen(b.Delegation.Authorities[0].Nonce)
		},
		"approval_member": func(b *Bundle) { b.Approval.Reason = mutSameLen(b.Approval.Reason) },
		"approval_env_member": func(b *Bundle) {
			b.ApprovalEnv.RecordID = mutSameLen(b.ApprovalEnv.RecordID)
		},
		"execution_member": func(b *Bundle) { b.Execution.ExecutionID = mutSameLen(b.Execution.ExecutionID) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := cloneBundle(t, base)
			mut(b)
			if string(b.Payload()) == string(baseP) {
				t.Fatalf("Payload() is blind to %s mutation — signature would still verify", name)
			}
		})
	}
}

// TestLinPreimage_MemberDigestSwap is the sharpest regression pin for
// the lp bug: every member contributes digestHex (a 64-char string, so
// a length-blind preimage sees six identical frames no matter what the
// artifacts contain). Swapping in a different member must change the
// preimage even though every field's length is unchanged.
func TestLinPreimage_MemberDigestSwap(t *testing.T) {
	d := domASetup(t)
	base := d.honestLineage(t)
	// A second valid receipt — different content, same digest length.
	_, rc2 := d.buildAuthority(t)
	rc2.ReceiptID = "rcpt_other"
	b := cloneBundle(t, base)
	b.Receipt = rc2
	if string(b.Payload()) == string(base.Payload()) {
		t.Fatal("Payload() blind to member swap — digests committed length-only")
	}
}

// TestLinPreimage_InclusionPayloadCommitsFields: the ledger
// countersignature preimage must bind the digest bytes, not just a
// 64-char length — otherwise one inclusion receipt vouches for every
// digest at that ledger position.
func TestLinPreimage_InclusionPayloadCommitsFields(t *testing.T) {
	base := InclusionPayload(ledgerDom, strings.Repeat("a", 64), 7, strings.Repeat("b", 64))
	cases := map[string][]byte{
		"domain": InclusionPayload(mutSameLen(ledgerDom), strings.Repeat("a", 64), 7, strings.Repeat("b", 64)),
		"digest": InclusionPayload(ledgerDom, strings.Repeat("c", 64), 7, strings.Repeat("b", 64)),
		"seq":    InclusionPayload(ledgerDom, strings.Repeat("a", 64), 8, strings.Repeat("b", 64)),
		"parent": InclusionPayload(ledgerDom, strings.Repeat("a", 64), 7, strings.Repeat("d", 64)),
	}
	for name, got := range cases {
		if string(got) == string(base) {
			t.Fatalf("InclusionPayload blind to %s", name)
		}
	}
}

// TestLinAdv_InclusionReuseIsForgery — the end-to-end shape of the lp
// bug at the inclusion layer: an attacker re-points an honest
// countersignature at a digest the ledger never registered. With the
// field bytes committed, the countersignature covers THIS digest —
// reuse fails.
func TestLinAdv_InclusionReuseIsForgery(t *testing.T) {
	d := domASetup(t)
	b := d.honestLineage(t)
	// Attacker presents an arbitrary statement digest under the honest
	// countersignature — only the Digest field is re-pointed.
	forge := cloneBundle(t, b)
	forge.Inclusion.Digest = digestHex("attacker statement")
	rejectAt(t, Verify(forge, d.anchor()), "inclusion")
}

// TestLinAdv_SameLengthFieldForgery — mutate a bundle field to a
// same-length value WITHOUT re-signing and re-point the inclusion
// digest at the mutated statement. Both the bundle sig and the ledger
// countersig must reject; pre-fix both still verified (the preimage
// saw only lengths, and every digest is 64 chars).
func TestLinAdv_SameLengthFieldForgery(t *testing.T) {
	d := domASetup(t)
	b := d.honestLineage(t)
	forge := cloneBundle(t, b)
	forge.Action.Environment = mutSameLen(forge.Action.Environment) // "local" → same length
	forge.LineageID = mutSameLen(forge.LineageID)
	// The attacker's re-pointed digest is the only field they can fix
	// — the countersignature must still fail over the forged content.
	forge.Inclusion.Digest = forge.StatementDigest()
	v := Verify(forge, d.anchor())
	if v.Accept {
		t.Fatalf("same-length mutated bundle ACCEPTED (sig %s unchanged) — content-blind preimage", forge.Sig[:20])
	}
}

// TestLinPreimage_StatementDigestCommits — StatementDigest is a JSON
// digest of the whole bundle (sans inclusion): mutating any field,
// signed or not, must move it. This is what makes the inclusion
// digest-mismatch check meaningful.
func TestLinPreimage_StatementDigestCommits(t *testing.T) {
	d := domASetup(t)
	base := d.honestLineage(t)
	baseD := base.StatementDigest()
	b := cloneBundle(t, base)
	b.Action.Environment = mutSameLen(b.Action.Environment)
	if b.StatementDigest() == baseD {
		t.Fatal("StatementDigest blind to field mutation")
	}
	// Sig is deliberately part of the statement (SCITT signed-statement
	// digest covers the signature).
	b2 := cloneBundle(t, base)
	b2.Sig = sigPrefix + hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	if b2.StatementDigest() == baseD {
		t.Fatal("StatementDigest blind to sig — must cover the signed statement")
	}
}
