// Emitter and ledger edge cases: an emitter that cannot sign, ledger,
// or journal must refuse to mint claims, and its failure must surface
// through the error hook — emission is evidence, never silent.
package lineage

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/record"
)

// NewEmitter refuses each missing ingredient — a partially-configured
// emitter would emit claims that never happened.
func TestNewEmitter_RequiresAllInputs(t *testing.T) {
	d := domASetup(t)
	cases := []struct {
		name   string
		domain string
		signer *record.Signer
		ledger Publisher
		store  *Store
	}{
		{"no_domain", "", d.gwSigner, d.ledger, d.lstore},
		{"no_signer", domAID, nil, d.ledger, d.lstore},
		{"no_ledger", domAID, d.gwSigner, nil, d.lstore},
		{"no_store", domAID, d.gwSigner, d.ledger, nil},
	}
	for _, tc := range cases {
		if _, err := NewEmitter(tc.domain, tc.signer, tc.ledger, tc.store); err == nil {
			t.Errorf("%s: emitter accepted a missing ingredient", tc.name)
		}
	}
}

// The error hook must see every emission failure — the operator's
// SECURITY log is the only place an evidence-write failure lives.
func TestEmitter_ErrorHookSeesFailures(t *testing.T) {
	d := domASetup(t)
	var hooked []error
	d.emitter.SetErrorHook(func(err error) { hooked = append(hooked, err) })
	req, rc := d.buildAuthority(t)
	ap, _ := d.approve(t, rc, req.DelegationChain)
	// EmitApproval with a nil envelope fails before signing.
	if _, err := d.emitter.EmitApproval(rc.DecisionID, ap, nil); err == nil {
		t.Fatal("nil approval envelope emitted")
	}
	if len(hooked) == 0 {
		t.Fatal("error hook not invoked on emit failure")
	}
}

// EmitApproval with no envelope refuses — provenance would be
// unverifiable (the approver-signed journal line is the evidence).
func TestEmitApproval_NilEnvelopeRefused(t *testing.T) {
	d := domASetup(t)
	req, rc := d.buildAuthority(t)
	if _, err := d.emitter.EmitDecision(req, rc); err != nil {
		t.Fatalf("EmitDecision: %v", err)
	}
	ap, _ := d.approve(t, rc, req.DelegationChain)
	if _, err := d.emitter.EmitApproval(rc.DecisionID, ap, nil); err == nil {
		t.Fatal("nil envelope accepted — provenance unverifiable")
	}
}

// A stage emission whose action disagrees with the recorded action is
// a broken pipeline, not a new lineage — refuse rather than mint a
// self-contradicting bundle.
func TestEmit_ActionMismatchRefused(t *testing.T) {
	d := domASetup(t)
	req, rc := d.buildAuthority(t)
	if _, err := d.emitter.EmitDecision(req, rc); err != nil {
		t.Fatalf("EmitDecision: %v", err)
	}
	// Approval record for a different resource under the same decision.
	ap, env := d.approve(t, rc, req.DelegationChain)
	ap.Resource = "shell:rm"
	if _, err := d.emitter.EmitApproval(rc.DecisionID, ap, env); err == nil ||
		!strings.Contains(err.Error(), "action mismatch") {
		t.Fatalf("contradicting stage emitted: %v", err)
	}
}

// The store fold's own guard: a bundle with no decision binding can
// never be journaled (a record no reopen could fold).
func TestStore_PutRefusesUnboundBundle(t *testing.T) {
	d := domASetup(t)
	if err := d.lstore.Put(&Bundle{V: Version, LineageID: "lin_x"}); err == nil {
		t.Fatal("receipt-less bundle journaled")
	}
	// A tips-sink failure must propagate as an emit failure — the
	// write becomes evidence only once the floor knows about it.
	d.lstore.SetTipsSink(func(uint64, string) error { return errors.New("sink failed") })
	req, rc := d.buildAuthority(t)
	if _, err := d.emitter.EmitDecision(req, rc); err == nil {
		t.Fatal("tips-sink failure swallowed by emit")
	}
}

// UnmarshalBundle is transport, not trust — but malformed bytes must
// still reject cleanly.
func TestUnmarshalBundle_RejectsGarbage(t *testing.T) {
	if _, err := UnmarshalBundle([]byte("{not json")); err == nil {
		t.Fatal("garbage bundle unmarshaled")
	}
	if _, err := UnmarshalBundle([]byte("")); err == nil {
		t.Fatal("empty bundle unmarshaled")
	}
}

// VerifyInclusion fail-closed shapes: nil, wrong prefix, bad hex,
// truncated signature — none may pass the pinned ledger key.
func TestVerifyInclusion_MalformedReceipts(t *testing.T) {
	d := domASetup(t)
	inc, err := d.ledger.Register("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(d.ledPub, inc) {
		t.Fatal("honest inclusion rejected")
	}
	cases := []struct {
		name string
		mut  func(*Inclusion)
	}{
		{"wrong_prefix", func(i *Inclusion) { i.Sig = "edsig_v1:" + i.Sig[len("lininc_v1:"):] }},
		{"bad_hex", func(i *Inclusion) { i.Sig = "lininc_v1:zz" }},
		{"truncated_sig", func(i *Inclusion) {
			i.Sig = "lininc_v1:" + hex.EncodeToString([]byte("short"))
		}},
		{"seq_shift", func(i *Inclusion) { i.Seq++ }},
		{"digest_swap", func(i *Inclusion) { i.Digest = "beefdead" }},
		{"domain_swap", func(i *Inclusion) { i.LedgerDomain = "domB/ledger" }},
	}
	for _, tc := range cases {
		bad := *inc
		tc.mut(&bad)
		if VerifyInclusion(d.ledPub, &bad) {
			t.Errorf("%s: forged inclusion verified", tc.name)
		}
	}
	if VerifyInclusion(d.ledPub, nil) {
		t.Error("nil inclusion verified")
	}
	// A foreign ledger's countersignature never verifies under the
	// pinned domA ledger key.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	otherLedger, err := NewFileLedger(filepath.Join(t.TempDir(), "l.jsonl"), "domB/ledger", otherPriv, "l2")
	if err != nil {
		t.Fatal(err)
	}
	inc2, err := otherLedger.Register("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyInclusion(d.ledPub, inc2) {
		t.Error("foreign ledger's inclusion verified under domA key")
	}
}

// Register on a nil ledger fails closed rather than panicking —
// emission is optional wiring, its absence must be an error value.
func TestFileLedger_NilRegisterFails(t *testing.T) {
	var l *FileLedger
	if _, err := l.Register("x"); err == nil {
		t.Fatal("nil ledger registered")
	}
}
