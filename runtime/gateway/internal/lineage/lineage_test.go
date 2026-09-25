// Verifiable cross-domain action lineage — two-domain proof plus the
// adversarial suite (docs/ACTION_LINEAGE.md).
//
//	Domain A (issuer): the gateway emits a signed lineage bundle at
//	each authority boundary — decision, approval, execution — and
//	registers each bundle's digest on its own transparency ledger.
//	Domain B (relying party): receives a bundle over the wire and
//	verifies it OFFLINE against a pinned anchor — A's gateway key,
//	trusted issuers, usable approver keys, the ledger key, and a
//	revocation snapshot. No call to A, no shared database: the
//	artifact itself is the evidence.
//
// Threat model: the artifact is untrusted, the anchor is not. Every
// forged / truncated / rolled-back / revoked variant must reject at
// a named layer; the honest lineage must accept.
package lineage

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipt"
	"ovara.runtime.gateway/internal/record"
	"ovara.runtime.gateway/internal/revocation"
)

const (
	domAID    = "domA"
	gwID      = "gw1"
	ledgerDom = "domA/ledger"
	agentID   = "agt_a"
)

// domA is the emitting domain: registry, journal signer, approver
// root, issuer set, transparency ledger, lineage store, emitter.
type domA struct {
	dir      string
	reg      *gwidentity.Registry
	gwPub    ed25519.PublicKey
	gwPriv   ed25519.PrivateKey
	gwRec    *gwidentity.KeyRecord
	gwSigner *record.Signer
	apPub    ed25519.PublicKey
	apRec    *gwidentity.KeyRecord
	issuers  map[string]ed25519.PrivateKey
	ledPub   ed25519.PublicKey
	ledger   *FileLedger
	lstore   *Store
	emitter  *Emitter
	apStore  *approval.FileBackedStore
}

// resolveGW mirrors the production gateway-journal resolver rule:
// approver-role records never resolve for gateway-signed journals.
func resolveGW(reg *gwidentity.Registry) record.ResolveFunc {
	return func(gw, kid string) (ed25519.PublicKey, error) {
		recs, err := reg.Lookup(gw)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if rec.KeyID == kid && rec.Role != "approver" {
				pub, _ := hex.DecodeString(rec.PublicKey)
				return ed25519.PublicKey(pub), nil
			}
		}
		return nil, fmt.Errorf("no key %s/%s", gw, kid)
	}
}

func domASetup(t *testing.T) *domA {
	t.Helper()
	dir := t.TempDir()
	reg := gwidentity.NewInMemory()

	gwPub, gwPriv, _ := ed25519.GenerateKey(nil)
	apPub, apPriv, _ := ed25519.GenerateKey(nil)
	gwRec, err := reg.Admit(gwID, gwPub, true)
	if err != nil {
		t.Fatalf("gateway admit: %v", err)
	}
	if err := reg.SetApproverPin(apPub); err != nil {
		t.Fatalf("approver pin: %v", err)
	}
	apRec, err := reg.AdmitApprover(apPub)
	if err != nil {
		t.Fatalf("approver admit: %v", err)
	}

	issuers := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"root-iss", "mid-iss"} {
		_, k, _ := ed25519.GenerateKey(nil)
		issuers[id] = k
	}
	ledPub, ledPriv, _ := ed25519.GenerateKey(nil)

	ledger, err := NewFileLedger(filepath.Join(dir, "ledger.jsonl"), ledgerDom, ledPriv, "l1")
	if err != nil {
		t.Fatalf("ledger open: %v", err)
	}
	gwSigner := record.NewSigner(gwPriv, domAID, gwID, gwRec.KeyID)
	lstore, err := OpenStore(filepath.Join(dir, "lineage.jsonl"),
		&record.Binding{Signer: gwSigner, Resolve: resolveGW(reg)})
	if err != nil {
		t.Fatalf("lineage store open: %v", err)
	}
	em, err := NewEmitter(domAID, gwSigner, ledger, lstore)
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	apStore, err := approval.NewFileBackedStore(filepath.Join(dir, "approvals.jsonl"),
		&record.Binding{
			Signer:  record.NewSigner(apPriv, domAID, gwidentity.ApproverID, apRec.KeyID),
			Resolve: reg.ResolveApproverKey,
		})
	if err != nil {
		t.Fatalf("approval store open: %v", err)
	}
	return &domA{
		dir: dir, reg: reg,
		gwPub: gwPub, gwPriv: gwPriv, gwRec: gwRec, gwSigner: gwSigner,
		apPub: apPub, apRec: apRec, issuers: issuers, ledPub: ledPub,
		ledger: ledger, lstore: lstore, emitter: em, apStore: apStore,
	}
}

// --- test-side canonical signing (mirrors evaluator's convention:
// the unexported identity payload builders are replicated byte-for-
// byte so fixtures carry genuinely valid signatures) ---

func lpStr(b *[]byte, s string) {
	n := len(s)
	*b = append(*b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	*b = append(*b, s...)
}
func lpI64(b *[]byte, v int64) {
	for i := 7; i >= 0; i-- {
		*b = append(*b, byte(v>>(8*i)))
	}
}
func lpU32(b *[]byte, v uint32) {
	for i := 3; i >= 0; i-- {
		*b = append(*b, byte(v>>(8*i)))
	}
}
func lpStrs(b *[]byte, ss []string) {
	n := len(ss)
	*b = append(*b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	for _, s := range ss {
		lpStr(b, s)
	}
}

func testHopPayload(auths []models.Authority, i int, prevSig string) []byte {
	a := auths[i]
	var b []byte
	lpStr(&b, a.Issuer)
	lpStr(&b, a.SubjectID)
	lpStr(&b, a.Audience)
	lpStr(&b, a.ResourceScope)
	lpStrs(&b, a.Actions)
	lpI64(&b, a.ExpiresAt.Unix())
	lpI64(&b, a.DelegatedAt.Unix())
	lpStr(&b, a.Nonce)
	lpStr(&b, prevSig)
	return b
}

func testLeasePayload(l *models.CapabilityLease) []byte {
	var b []byte
	lpStr(&b, l.LeaseID)
	lpStr(&b, l.Issuer)
	lpStr(&b, l.Subject)
	lpStr(&b, l.Audience)
	lpStrs(&b, l.AllowedActions)
	lpStr(&b, l.ResourceScope)
	lpI64(&b, l.Expiry.Unix())
	lpI64(&b, l.IssuedAt.Unix())
	lpU32(&b, uint32(l.DelegationDepth))
	return b
}

func signChain(chain *models.DelegationChain, keys map[string]ed25519.PrivateKey) {
	prevSig := ""
	for i := range chain.Authorities {
		priv, ok := keys[chain.Authorities[i].Issuer]
		if !ok {
			panic("no test key for issuer " + chain.Authorities[i].Issuer)
		}
		chain.Authorities[i].Signature = ed25519.Sign(priv, testHopPayload(chain.Authorities, i, prevSig))
		prevSig = hex.EncodeToString(chain.Authorities[i].Signature)
	}
	chain.Depth = len(chain.Authorities)
}

// buildAuthority assembles a well-formed presented authority: a
// narrowing chain root-iss → mid-iss → agt_a plus a root-iss-signed
// lease, the evaluated request, and an edsig-signed decision receipt.
func (d *domA) buildAuthority(t *testing.T) (*models.ActionRequest, *models.Receipt) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	chain := &models.DelegationChain{Authorities: []models.Authority{
		{Issuer: "root-iss", SubjectID: "mid-iss",
			Actions: []string{"*"}, Audience: domAID,
			ExpiresAt: now.Add(time.Hour), DelegatedAt: now, Nonce: "n-root"},
		{Issuer: "mid-iss", SubjectID: agentID,
			Actions: []string{"shell"}, ResourceScope: "shell:*", Audience: domAID,
			ExpiresAt: now.Add(30 * time.Minute), DelegatedAt: now, Nonce: "n-mid"},
	}}
	signChain(chain, d.issuers)
	lease := &models.CapabilityLease{
		LeaseID: "lease_1", Issuer: "root-iss", Subject: agentID,
		AllowedActions: []string{"shell"}, ResourceScope: "*",
		Expiry: now.Add(time.Hour), IssuedAt: now,
		Audience: domAID, DelegationDepth: 1,
	}
	lease.Signature = ed25519.Sign(d.issuers["root-iss"], testLeasePayload(lease))
	req := &models.ActionRequest{
		ActionType:      models.ActionTypeShell,
		Resource:        "shell:ls",
		AgentIdentity:   &models.AgentIdentity{Issuer: "mid-iss", SubjectID: agentID},
		CapabilityLease: lease,
		DelegationChain: chain,
		Environment:     models.EnvironmentLocal,
		Nonce:           "req-n1",
		IssuedAt:        now,
	}
	rc := &models.Receipt{
		ReceiptID:         "rcpt_1",
		DecisionID:        "dec_1",
		ActionDigest:      receipt.ComputeActionDigest("shell", "shell:ls", now),
		ActionType:        "shell",
		Resource:          "shell:ls",
		AgentID:           agentID,
		CapabilityLeaseID: "lease_1",
		Decision:          "escalated",
		PolicyVersion:     "p1",
		TrustScore:        0.4,
		ApprovalID:        "app_1",
		IssuedAt:          now,
		Signature:         "sig_v1:test-hmac",
	}
	receipt.NewEdSigner(d.gwPriv, gwID, d.gwRec.KeyID).SignReceipt(rc)
	return req, rc
}

// approve runs the honest approval pipeline: pending → approved under
// the approver root; returns the record + its signed journal envelope.
func (d *domA) approve(t *testing.T, rc *models.Receipt, chain *models.DelegationChain) (*approval.ApprovalRequest, *record.Envelope) {
	t.Helper()
	dk, iss := identity.ChainRevocationIDs(chain)
	ap := &approval.ApprovalRequest{
		ApprovalID: "app_1", DecisionID: rc.DecisionID,
		ActionType: models.ActionTypeShell, Resource: "shell:ls",
		Environment: models.EnvironmentLocal, Status: approval.StatusPending,
		AgentID:   agentID,
		CreatedAt: time.Now().UTC(),
		// The context binding a real approval carries (populated by the
		// handler from the recorded decision — never caller-asserted).
		RequestHash:    rc.ActionDigest,
		LeaseID:        "lease_1",
		DelegationKeys: dk,
		Issuers:        iss,
	}
	if err := d.apStore.Create(ap); err != nil {
		t.Fatalf("approval create: %v", err)
	}
	got, err := d.apStore.Resolve("app_1", approval.StatusApproved, "op", "")
	if err != nil {
		t.Fatalf("approval resolve: %v", err)
	}
	env := d.apStore.EnvelopeFor("app_1")
	if env == nil {
		t.Fatal("no signed envelope for approval")
	}
	return got, env
}

// anchor is domain B's pinned view of A — assembled out-of-band from
// registry exports, never from the artifact under test.
func (d *domA) anchor() *Anchor {
	return &Anchor{
		DomainID:    domAID,
		GatewayKeys: map[string]ed25519.PublicKey{gwID + "|" + d.gwRec.KeyID: d.gwPub},
		IssuerKeys: map[string]ed25519.PublicKey{
			"root-iss": d.issuers["root-iss"].Public().(ed25519.PublicKey),
			"mid-iss":  d.issuers["mid-iss"].Public().(ed25519.PublicKey),
		},
		ApproverKeys:     map[string]ed25519.PublicKey{d.apRec.KeyID: d.apPub},
		LedgerKeys:       map[string]ed25519.PublicKey{ledgerDom: d.ledPub},
		ExpectedAudience: domAID,
		Revocations:      map[revocation.Pair]bool{},
		Epoch:            1,
	}
}

// honestLineage runs the full emit path: decision → approval →
// execution, all through real stores and the real ledger.
func (d *domA) honestLineage(t *testing.T) *Bundle {
	t.Helper()
	req, rc := d.buildAuthority(t)
	b1, err := d.emitter.EmitDecision(req, rc)
	if err != nil {
		t.Fatalf("EmitDecision: %v", err)
	}
	if b1.Stage != StageDecision || !b1.Signed() || b1.Inclusion == nil {
		t.Fatalf("decision bundle malformed: stage=%q signed=%v inc=%v", b1.Stage, b1.Signed(), b1.Inclusion != nil)
	}

	updated, env := d.approve(t, rc, req.DelegationChain)
	b2, err := d.emitter.EmitApproval(rc.DecisionID, updated, env)
	if err != nil {
		t.Fatalf("EmitApproval: %v", err)
	}
	if b2.Stage != StageApproval || b2.Approval == nil || b2.ApprovalEnv == nil {
		t.Fatal("approval bundle did not carry provenance material")
	}

	b3, err := d.emitter.EmitExecution(rc.DecisionID, ExecRef{
		ContinuationID: "cnt_1", ExecutionID: "exe_1", State: "running",
	})
	if err != nil {
		t.Fatalf("EmitExecution: %v", err)
	}
	if b3.Stage != StageExecution || b3.Execution == nil {
		t.Fatal("execution bundle did not carry the dispatch ref")
	}
	return b3
}

func cloneBundle(t *testing.T, b *Bundle) *Bundle {
	t.Helper()
	wire, err := MarshalBundle(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalBundle(wire)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// rebind re-wraps a mutated bundle the way an attacker holding the
// stolen gateway key would: fresh honest signature + fresh ledger
// registration for the mutated digest — leaving the layer under test
// as the only thing that can catch the forgery. (Ledger registration
// is open: the ledger attests a statement was submitted; validity is
// the verifier's job, SCITT-style.)
func (d *domA) rebind(t *testing.T, b *Bundle) {
	t.Helper()
	sig, err := d.gwSigner.Sign(b.Payload())
	if err != nil {
		t.Fatalf("rebind sign: %v", err)
	}
	b.Sig = sigPrefix + hex.EncodeToString(sig)
	inc, err := d.ledger.Register(b.StatementDigest())
	if err != nil {
		t.Fatalf("rebind register: %v", err)
	}
	b.Inclusion = inc
}

func rejectAt(t *testing.T, v *Verdict, layer string) {
	t.Helper()
	if v.Accept {
		t.Fatalf("forgery accepted — layers passed: %v", v.Layers)
	}
	if v.Layer != layer {
		t.Fatalf("rejected at %q (detail %q), expected %q", v.Layer, v.Detail, layer)
	}
	t.Logf("rejected as designed at %s: %s", v.Layer, v.Detail)
}

// Two-domain proof: A emits the full lineage, B verifies the wire form
// offline against its pinned anchor — signature chain, delegation
// narrowing, approval provenance, ledger inclusion, revocation view.
func TestLineage_TwoDomain_EndToEnd(t *testing.T) {
	d := domASetup(t)
	honest := d.honestLineage(t)

	got := cloneBundle(t, honest) // B receives bytes, not the object
	v := Verify(got, d.anchor())
	if !v.Accept {
		t.Fatalf("honest lineage rejected at %s: %s", v.Layer, v.Detail)
	}
	want := []string{"shape", "inclusion", "signature", "receipt", "delegation", "lease", "approval", "revocation"}
	if len(v.Layers) != len(want) {
		t.Fatalf("layers passed %v, want %v", v.Layers, want)
	}
	for i, l := range want {
		if v.Layers[i] != l {
			t.Fatalf("layers passed %v, want %v", v.Layers, want)
		}
	}

	// An earlier-stage emission is independently verifiable: the
	// decision-stage bundle carries no approval yet.
	d2 := domASetup(t)
	req, rc := d2.buildAuthority(t)
	b1, err := d2.emitter.EmitDecision(req, rc)
	if err != nil {
		t.Fatalf("EmitDecision: %v", err)
	}
	v1 := Verify(cloneBundle(t, b1), d2.anchor())
	if !v1.Accept {
		t.Fatalf("decision-stage lineage rejected at %s: %s", v1.Layer, v1.Detail)
	}
}

// Durability: the emitted lineage is journaled — reopening the store
// folds the signed journal and yields the latest stage per decision.
func TestLineage_StoreRefolds(t *testing.T) {
	d := domASetup(t)
	honest := d.honestLineage(t)
	if err := d.lstore.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	re, err := OpenStore(filepath.Join(d.dir, "lineage.jsonl"),
		&record.Binding{Signer: d.gwSigner, Resolve: resolveGW(d.reg)})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := re.ByDecision(honest.Receipt.DecisionID)
	if got == nil || got.Stage != StageExecution || got.LineageID != honest.LineageID {
		t.Fatalf("refolded lineage lost the latest stage: %+v", got)
	}
}

// Regression — a stage emit for a decision with NO prior decision
// bundle must fail cleanly: no ledger registration, no journaled
// (unfoldable) record, no nil-deref. Found in e2e review: reachable
// when the decision-stage emission itself failed earlier.
func TestLineage_OrphanedStageEmitRefuses(t *testing.T) {
	d := domASetup(t)
	_, rc := d.buildAuthority(t)
	ap := &approval.ApprovalRequest{
		ApprovalID: "app_orph", DecisionID: rc.DecisionID,
		ActionType: models.ActionTypeShell, Resource: "shell:ls",
		Status: approval.StatusApproved, AgentID: agentID,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := d.emitter.EmitApproval(rc.DecisionID, ap, &record.Envelope{}); err == nil {
		t.Fatal("orphaned approval emission succeeded — unbound bundle accepted")
	}
	if got := d.lstore.ByDecision(rc.DecisionID); got != nil {
		t.Fatal("orphaned emission journaled an unbound bundle")
	}
	// The journal must still open — nothing poisoned was appended.
	if err := d.lstore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(filepath.Join(d.dir, "lineage.jsonl"),
		&record.Binding{Signer: d.gwSigner, Resolve: resolveGW(d.reg)}); err != nil {
		t.Fatalf("journal poisoned by orphaned emission: %v", err)
	}
}

// LIN-01 — forged lineage: attacker re-signs the honest bundle under
// their own key while still claiming the real gateway identity.
func TestLinAdv_ForgedBundleSignature(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	_, atk, _ := ed25519.GenerateKey(nil)
	b.Sig = sigPrefix + hex.EncodeToString(ed25519.Sign(atk, b.Payload()))
	// fresh honest inclusion for the mutated digest — signature layer
	// must still catch the wrong-key signature
	inc, err := d.ledger.Register(b.StatementDigest())
	if err != nil {
		t.Fatal(err)
	}
	b.Inclusion = inc
	rejectAt(t, Verify(b, d.anchor()), "signature")
}

// LIN-02 — tampered content: mutating a signed member breaks the
// member digest inside the bundle signature.
func TestLinAdv_TamperedReceiptField(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	b.Receipt.Resource = "shell:rm -rf /" // escalate the attested action
	d.rebind(t, b)                        // even honestly re-signed, the receipt self-sig breaks
	rejectAt(t, Verify(b, d.anchor()), "receipt")
}

// LIN-03 — truncated chain: drop the terminal hop so the agent's
// authority derivation ends one hop early. The remaining prefix is
// still well-formed — the subject binding must catch it.
func TestLinAdv_TruncatedChain(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	b.Delegation.Authorities = b.Delegation.Authorities[:1]
	d.rebind(t, b)
	rejectAt(t, Verify(b, d.anchor()), "delegation")
}

// LIN-04 — untrusted issuer: attacker re-roots the chain at their own
// key. The hop is correctly signed — under a key B never pinned.
func TestLinAdv_UntrustedIssuer(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	_, roguePriv, _ := ed25519.GenerateKey(nil)
	b.Delegation.Authorities[0].Issuer = "rogue"
	b.Delegation.Authorities[0].Signature = ed25519.Sign(
		roguePriv, testHopPayload(b.Delegation.Authorities, 0, ""))
	d.rebind(t, b)
	rejectAt(t, Verify(b, d.anchor()), "delegation")
}

// LIN-05 — revoked approver mid-lineage: the approver key that signed
// the approval envelope is absent from B's pinned usable set — as it
// is once A's registry records it revoked and B refreshes.
func TestLinAdv_RevokedApproverKey(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	a := d.anchor()
	a.ApproverKeys = map[string]ed25519.PublicKey{} // key revoked before snapshot
	rejectAt(t, Verify(b, a), "approval")
}

// LIN-06 — forged approval provenance: attacker re-signs the envelope
// under a key they control while still claiming the approver identity.
func TestLinAdv_ForgedApprovalEnvelope(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	_, atk, _ := ed25519.GenerateKey(nil)
	b.ApprovalEnv.Sig = hex.EncodeToString(ed25519.Sign(atk, record.SigningPayload(b.ApprovalEnv)))
	// bundle must still self-consist: re-sign the mutated bundle
	// honestly so the approval layer is what adjudicates.
	d.rebind(t, b)
	rejectAt(t, Verify(b, d.anchor()), "approval")
}

// LIN-07 — stale domain: a bundle minted for another domain never
// verifies under A's anchor (domain confusion).
func TestLinAdv_WrongDomain(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	a := d.anchor()
	a.DomainID = "domB"
	rejectAt(t, Verify(b, a), "domain")
}

// LIN-08 — ledger countersignature forged: inclusion claims seq/parent
// a real ledger never signed.
func TestLinAdv_TamperedInclusion(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	b.Inclusion.Seq += 10 // replay a shifted position
	rejectAt(t, Verify(b, d.anchor()), "inclusion")
}

// LIN-09 — revoked issuer in the pinned snapshot: the chain verifies
// cryptographically but the "still valid?" half answers no.
func TestLinAdv_RevokedIssuerInSnapshot(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	a := d.anchor()
	a.Revocations[revocation.P(revocation.ClassIssuer, "mid-iss")] = true
	rejectAt(t, Verify(b, a), "delegation")
}

// LIN-10 — revoked lease in the pinned snapshot.
func TestLinAdv_RevokedLeaseInSnapshot(t *testing.T) {
	d := domASetup(t)
	b := cloneBundle(t, d.honestLineage(t))
	a := d.anchor()
	a.Revocations[revocation.P(revocation.ClassLease, "lease_1")] = true
	rejectAt(t, Verify(b, a), "lease")
}

// LIN-11 — stolen gateway.key (C2-KEY-ROOT rerun): the attacker holds
// A's journal signing key and filesystem — but NOT the ledger key. A
// bundle they mint wholesale cannot produce a countersigned inclusion.
func TestLinAdv_StolenGatewayKeyCannotLedger(t *testing.T) {
	d := domASetup(t)

	// Attacker builds a complete counterfeit bundle: their own request,
	// a receipt signed with the STOLEN gateway key (valid edsig!), a
	// bundle signed with the stolen key — everything except the
	// inclusion, which needs the separate ledger root.
	req, rc := d.buildAuthority(t)
	rc.DecisionID = "dec_evil"
	rc.Resource = "shell:payload"
	rc.ActionDigest = receipt.ComputeActionDigest("shell", "shell:payload", req.IssuedAt)
	receipt.NewEdSigner(d.gwPriv, gwID, d.gwRec.KeyID).SignReceipt(rc) // stolen key still signs
	b := &Bundle{
		V: Version, LineageID: "lin_evil", DomainID: domAID,
		Stage: StageDecision, IssuedAt: time.Now().UTC(),
		Action:  ActionRef{ActionType: "shell", Resource: "shell:payload", AgentID: agentID},
		Receipt: rc, Lease: req.CapabilityLease, Delegation: req.DelegationChain,
		GatewayID: gwID, GatewayKeyID: d.gwRec.KeyID,
	}
	sig, err := d.gwSigner.Sign(b.Payload()) // attacker possesses gw key
	if err != nil {
		t.Fatal(err)
	}
	b.Sig = sigPrefix + hex.EncodeToString(sig)

	// No honest inclusion exists for their digest; they forge the field.
	b.Inclusion = &Inclusion{
		LedgerDomain: ledgerDom, Seq: 1, Parent: "0",
		Digest: b.StatementDigest(), KeyID: "l1", Sig: "lininc_v1:deadbeef",
	}
	rejectAt(t, Verify(cloneBundle(t, b), d.anchor()), "inclusion")
}

// LIN-12 — honest lineage accepts (positive control of the suite).
func TestLinAdv_HonestAccepts(t *testing.T) {
	d := domASetup(t)
	v := Verify(cloneBundle(t, d.honestLineage(t)), d.anchor())
	if !v.Accept {
		t.Fatalf("honest lineage rejected at %s: %s", v.Layer, v.Detail)
	}
}

// Ensure the compiled bundle stays marshalable — the wire contract is
// JSON and the verifier sees only bytes.
func TestLinAdv_MarshalRoundTripStable(t *testing.T) {
	d := domASetup(t)
	b := d.honestLineage(t)
	w1, _ := MarshalBundle(b)
	w2, _ := MarshalBundle(cloneBundle(t, b))
	if string(w1) != string(w2) {
		t.Fatal("bundle wire form is not canonical — digests would diverge")
	}
}
