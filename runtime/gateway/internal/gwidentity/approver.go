// Approval-root key class (C2-B Phase A1): the authority that signs
// approval records is a DIFFERENT signing domain from the gateway
// journal key, so possessing gateway.key alone can no longer mint
// a claimable continuation — provenance now requires a record signed
// by a key registered with role=approver.
//
// Role is part of the trust decision, not metadata: a key record
// carrying role=approver folds ONLY when its public key equals the
// configured approver pin (the operator-held bootstrap root — a C2-A
// input, deliberately outside the C2-B model). A forged role=approver
// record appended to the registry file is a fold error: fail closed.
package gwidentity

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
)

// ApproverID is the reserved registry principal for the approval
// root key. Gateway ids come from enrollment and never equal it.
const ApproverID = "approver"

// SetApproverPin installs the approver root-of-trust. Existing
// approver records are revalidated — a record inconsistent with the
// pin means the registry's approver state was forged and the registry
// must not be trusted. Subsequent folds enforce the same rule.
func (r *Registry) SetApproverPin(pub ed25519.PublicKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.approverPin = hex.EncodeToString(pub)
	for _, rec := range r.keys[ApproverID] {
		if rec.State != KeyActive {
			// retired keys remain folded — history signed under them
			// must keep verifying; the pin governs live authority only
			continue
		}
		if err := r.validateApproverLocked(rec); err != nil {
			return err
		}
	}
	return nil
}

// validateApproverLocked enforces the pin rule on a folded/being-
// folded approver record. Called with r.mu held. When the pin is not
// yet installed (initial open precedes SetApproverPin) the record
// folds unchecked — SetApproverPin's revalidation pass catches any
// forgery that folded before the pin existed. Once the pin IS set,
// a foreign approver record absorbed from disk is a hard fold error:
// mutate and Lookup both fail closed.
func (r *Registry) validateApproverLocked(rec *KeyRecord) error {
	if rec.Role != "approver" {
		return nil
	}
	if r.approverPin == "" {
		return nil
	}
	if rec.PublicKey != r.approverPin {
		return fmt.Errorf("gateway registry: approver record %s does not match pinned approver root", rec.KeyID)
	}
	return nil
}

// AdmitApprover registers the approver root key under the reserved
// ApproverID principal. The presented public key must equal the
// configured pin — the pin IS the admission; no grant path exists for
// the approver role (the operator owns it, not the domain).
// Idempotent on same-key re-admission; a live conflicting approver
// key is a conflict (rotate by updating the pin + revoking the old key).
func (r *Registry) AdmitApprover(pub ed25519.PublicKey) (*KeyRecord, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gateway registry: bad approver public key length %d", len(pub))
	}
	pubHex := hex.EncodeToString(pub)
	var rec *KeyRecord
	err := r.mutate(func() ([]any, error) {
		if r.approverPin == "" {
			return nil, fmt.Errorf("gateway registry: no approver pin configured")
		}
		if pubHex != r.approverPin {
			return nil, fmt.Errorf("%w: approver key does not match pinned approver root", ErrUnauthorized)
		}
		for _, k := range r.keys[ApproverID] {
			if k.PublicKey == pubHex && k.State != KeyDestroyed {
				cp := *k
				rec = &cp
				return nil, nil // idempotent adopt
			}
		}
		for _, k := range r.keys[ApproverID] {
			if Usable(k) {
				return nil, fmt.Errorf("%w: live approver key %s conflicts", ErrGatewayConflict, k.KeyID)
			}
		}
		now := time.Now().UTC()
		nr := &KeyRecord{Kind: "key", GatewayID: ApproverID,
			KeyID: newKeyID(), PublicKey: pubHex, Role: "approver",
			State: KeyActive, CreatedAt: now, ActivatedAt: now, Generation: 1}
		rec = nr
		return []any{nr}, nil
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// ResolveApproverKey is a record.ResolveFunc for the approvals
// journal: only keys registered under the approver principal resolve.
// A gateway-key-signed approval record fails resolution → fold error
// → the store refuses to open. That is the Phase-A theorem: forged
// approval provenance is impossible without the approver root.
func (r *Registry) ResolveApproverKey(gatewayID, keyID string) (ed25519.PublicKey, error) {
	if gatewayID != ApproverID {
		return nil, fmt.Errorf("gateway registry: %w — approval records must be signed under %s", ErrUnknownKey, ApproverID)
	}
	recs, err := r.Lookup(ApproverID)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		if rec.KeyID != keyID || rec.Role != "approver" {
			continue
		}
		pub, err := hex.DecodeString(rec.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gateway registry: approver key %s undecodable", keyID)
		}
		return ed25519.PublicKey(pub), nil
	}
	return nil, fmt.Errorf("gateway registry: %w for approver key %s", ErrUnknownKey, keyID)
}

// ApproverUsable reports whether keyID is a live approver-role key —
// used at claim time so a signature made by a since-revoked approver
// key no longer carries authority.
func (r *Registry) ApproverUsable(keyID string) bool {
	recs, err := r.Lookup(ApproverID)
	if err != nil {
		return false
	}
	for _, rec := range recs {
		if rec.KeyID == keyID && rec.Role == "approver" {
			return Usable(rec)
		}
	}
	return false
}
