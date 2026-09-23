// C2-B Phase A1 adversarial suite — dual-root provenance.
//
// Threat model (unchanged from C2): attacker can write the trust-
// domain filesystem and holds gateway.key, but NOT the approver root
// key and NOT the operator pin. The theorem under test:
//
//	gateway.key + fs-write alone must be insufficient to produce a
//	continuation that survives fold, passes CheckClaimProvenance,
//	and reaches executor dispatch.
//
// Signer separation is mutual: the approvals journal resolves ONLY
// approver-role keys (reg.ResolveApproverKey), and the gateway-key
// resolver refuses approver records — so neither root can forge in
// the other's journal.
package continuation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

type c2bEnv struct {
	t         *testing.T
	dir       string
	reg       *gwidentity.Registry
	gwSigner  *record.Signer
	apSigner  *record.Signer
	resolveGW record.ResolveFunc
	gwRec     *gwidentity.KeyRecord
	apRec     *gwidentity.KeyRecord
	apPath    string
	contPath  string
}

func c2bSetup(t *testing.T) *c2bEnv {
	t.Helper()
	dir := t.TempDir()
	reg := gwidentity.NewInMemory()

	gwPub, gwPriv, _ := ed25519.GenerateKey(nil)
	apPub, apPriv, _ := ed25519.GenerateKey(nil)

	gwRec, err := reg.Admit("gw1", gwPub, true)
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

	resolveGW := func(gw, kid string) (ed25519.PublicKey, error) {
		recs, err := reg.Lookup(gw)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			// mirror of the production resolver rule: approver-role
			// keys never resolve for gateway-signed journals
			if rec.KeyID == kid && rec.Role != "approver" {
				pub, _ := hex.DecodeString(rec.PublicKey)
				return ed25519.PublicKey(pub), nil
			}
		}
		return nil, fmt.Errorf("test resolver: no key %s/%s", gw, kid)
	}

	return &c2bEnv{
		t: t, dir: dir, reg: reg,
		gwSigner:  record.NewSigner(gwPriv, "dom-test", "gw1", gwRec.KeyID),
		apSigner:  record.NewSigner(apPriv, "dom-test", gwidentity.ApproverID, apRec.KeyID),
		resolveGW: resolveGW,
		gwRec:     gwRec, apRec: apRec,
		apPath:   filepath.Join(dir, "approvals.jsonl"),
		contPath: filepath.Join(dir, "conts.jsonl"),
	}
}

// c2bApprovalStore opens the approvals journal under the approver
// binding — the production wiring shape.
func (e *c2bEnv) approvalStore(t *testing.T) *approval.FileBackedStore {
	t.Helper()
	st, err := approval.NewFileBackedStore(e.apPath, &record.Binding{
		Signer: e.apSigner, Resolve: e.reg.ResolveApproverKey,
	})
	if err != nil {
		t.Fatalf("approval store open: %v", err)
	}
	return st
}

// c2bLegitApproval writes a real approver-signed approval (pending →
// approved) through the store — the honest pipeline path.
func (e *c2bEnv) c2bLegitApproval(t *testing.T, st *approval.FileBackedStore, id, decID string) *approval.ApprovalRequest {
	t.Helper()
	req := &approval.ApprovalRequest{
		ApprovalID: id, DecisionID: decID,
		ActionType: models.ActionType("shell"), Resource: "shell:ls",
		Status: approval.StatusPending, AgentID: "agt_a",
		CreatedAt: time.Now().UTC(),
	}
	if err := st.Create(req); err != nil {
		t.Fatalf("approval create: %v", err)
	}
	got, err := st.Resolve(id, approval.StatusApproved, "op", "")
	if err != nil {
		t.Fatalf("approval resolve: %v", err)
	}
	return got
}

// c2bContStore opens the continuation journal under the gateway
// binding (gateway-signed records only).
func (e *c2bEnv) contStore(t *testing.T) *FileBackedStore {
	t.Helper()
	b := &record.Binding{Signer: e.gwSigner, Resolve: e.resolveGW}
	st, err := NewFileBackedStoreWithRetention(e.contPath, 0, 0, 0, b)
	if err != nil {
		t.Fatalf("continuation store open: %v", err)
	}
	return st
}

// c2bForgeCont appends a signed-but-unprovenanced queued continuation
// via the raw journal — the attacker's filesystem write.
func (e *c2bEnv) c2bForgeCont(t *testing.T, c *Continuation) {
	t.Helper()
	j, err := record.Open("continuation", e.contPath, e.gwSigner.Domain(), e.gwSigner, e.resolveGW, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("open continuation journal: %v", err)
	}
	defer j.Close()
	data, _ := json.Marshal(c)
	if _, _, err := j.Append("continuation", c.ContinuationID, json.RawMessage(data), nil); err != nil {
		t.Fatalf("forge append: %v", err)
	}
}

// C2B-01: forge continuation, no approval → provenance DENY.
func TestAdvC2B_ForgeContNoApproval(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	c := NewContinuation("dec_x", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_ghost")
	c.MarkApproved("attacker")
	c.MarkQueued()
	e.c2bForgeCont(t, c)

	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("forged continuation not claimable")
	}
	deny, why, err := CheckClaimProvenance(apSt, e.reg, got)
	if err != nil || !deny {
		t.Fatalf("forged no-approval continuation passed provenance: deny=%v why=%q err=%v", deny, why, err)
	}
}

// C2B-02: forge a gateway-key-signed approval record into the
// approvals file → store REFUSES TO OPEN (fold is fail-closed), and
// an in-memory fallback denies the claim as unresolvable.
func TestAdvC2B_ForgeApprovalUnderGatewayKey(t *testing.T) {
	e := c2bSetup(t)
	// attacker writes an approval line signed by the STOLEN gateway key
	j, err := record.Open("approval", e.apPath, e.gwSigner.Domain(), e.gwSigner, e.resolveGW, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("open approval journal for forge: %v", err)
	}
	ap := &approval.ApprovalRequest{
		ApprovalID: "app_forge", DecisionID: "dec_x",
		ActionType: models.ActionType("shell"), Resource: "shell:ls",
		Status: approval.StatusApproved, AgentID: "agt_a",
		CreatedAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(ap)
	if _, _, err := j.Append("approval", ap.ApprovalID, json.RawMessage(data), nil); err != nil {
		t.Fatalf("forge approval append: %v", err)
	}
	j.Close()

	// honest reopen under the approver resolver → gateway-signed
	// record cannot resolve → fold error → fail closed
	if _, err := approval.NewFileBackedStore(e.apPath, &record.Binding{
		Signer: e.apSigner, Resolve: e.reg.ResolveApproverKey,
	}); err == nil {
		t.Fatal("approval journal opened with a gateway-signed record — fold boundary failed")
	}

	// and a forged continuation referencing it still can't claim
	c := NewContinuation("dec_x", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_forge")
	c.MarkApproved("attacker")
	c.MarkQueued()
	e.c2bForgeCont(t, c)
	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("forged continuation not claimable")
	}
	apFallback := approval.NewInMemoryStore() // gateway degraded to in-memory approvals
	deny, why, err := CheckClaimProvenance(apFallback, e.reg, got)
	if !deny || err != nil {
		t.Fatalf("continuation with unresolvable forged approval passed: deny=%v why=%q err=%v", deny, why, err)
	}
}

// C2B-03: attacker references a REAL approved approval but changes
// the bound context → DENY on context mismatch.
func TestAdvC2B_ReferenceRealApprovalWrongContext(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	e.c2bLegitApproval(t, apSt, "app_real", "dec_1")

	c := NewContinuation("dec_1", "shell", "shell:rm -rf /").WithAgentID("agt_evil")
	c.WithApprovalID("app_real")
	c.MarkApproved("attacker")
	c.MarkQueued()
	e.c2bForgeCont(t, c)

	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("forged continuation not claimable")
	}
	deny, why, _ := CheckClaimProvenance(apSt, e.reg, got)
	if !deny {
		t.Fatalf("context-swapped continuation passed provenance: %q", why)
	}
}

// C2B-04: approver key alone cannot forge a continuation — the
// gateway resolver refuses approver-role keys → fold fails closed.
func TestAdvC2B_ApproverKeyCannotForgeContinuation(t *testing.T) {
	e := c2bSetup(t)
	j, err := record.Open("continuation", e.contPath, e.apSigner.Domain(), e.apSigner, e.resolveGW, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatalf("open continuation journal: %v", err)
	}
	c := NewContinuation("dec_x", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_x")
	c.MarkApproved("approver-key-holder")
	c.MarkQueued()
	data, _ := json.Marshal(c)
	if _, _, err := j.Append("continuation", c.ContinuationID, json.RawMessage(data), nil); err != nil {
		t.Fatalf("forge append: %v", err)
	}
	j.Close()

	// honest open: key_ref=(approver, apkid) → gateway resolver must
	// not bless an approver-role record → ErrUnknownKey → refuse
	if _, err := NewFileBackedStoreWithRetention(e.contPath, 0, 0, 0, &record.Binding{
		Signer: e.gwSigner, Resolve: e.resolveGW,
	}); err == nil {
		t.Fatal("continuation journal opened an approver-signed record — mutual separation failed")
	}
}

// C2B-05: tamper with a signed approval line → store refuses to open.
func TestAdvC2B_TamperApprovalLine(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	e.c2bLegitApproval(t, apSt, "app_1", "dec_1")

	// attacker flips a byte inside the signed record
	data, _ := os.ReadFile(e.apPath)
	for i := len(data) - 2; i > len(data)-200 && i > 0; i-- {
		if data[i] == 'a' {
			data[i] = 'b'
			break
		}
	}
	if err := os.WriteFile(e.apPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := approval.NewFileBackedStore(e.apPath, &record.Binding{
		Signer: e.apSigner, Resolve: e.reg.ResolveApproverKey,
	}); err == nil {
		t.Fatal("tampered approval journal opened — signature/parent verification failed")
	}
}

// C2B-06: happy path — approver-signed approval + gateway-signed
// continuation → provenance passes. Guards against over-blocking.
func TestAdvC2B_LegitPathPasses(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	e.c2bLegitApproval(t, apSt, "app_1", "dec_1")

	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_1")
	c.MarkApproved("op")
	c.MarkQueued()
	e.c2bForgeCont(t, c) // legitimate record (gateway-signed, as production)

	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("legit continuation not claimable")
	}
	// reopen approvals so folded records carry SignerKeyID
	// (FileBackedStore has no Close — a second open refolds)
	apSt = e.approvalStore(t)
	deny, why, err := CheckClaimProvenance(apSt, e.reg, got)
	if deny || err != nil {
		t.Fatalf("legit claim denied: deny=%v why=%q err=%v", deny, why, err)
	}
}

// C2B-07: revoke the approver key → approvals signed under it no
// longer carry live authority → claim DENY.
func TestAdvC2B_RevokedApproverKeyDenies(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	e.c2bLegitApproval(t, apSt, "app_1", "dec_1")

	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_1")
	c.MarkApproved("op")
	c.MarkQueued()
	e.c2bForgeCont(t, c)

	// emergency: approver key revoked
	if err := e.reg.RevokeKey(gwidentity.ApproverID, e.apRec.KeyID); err != nil {
		t.Fatalf("revoke approver: %v", err)
	}

	apSt = e.approvalStore(t) // refold → SignerKeyID stamped; any-state resolver still verifies
	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("continuation not claimable")
	}
	deny, why, _ := CheckClaimProvenance(apSt, e.reg, got)
	if !deny {
		t.Fatalf("claim under revoked approver key passed: %q", why)
	}
}

// C2B-08: the kill chain end-to-end — ANCHOR-01 rerun under dual
// roots. Forge with gateway.key → honest open → fold → the forged
// continuation claims mechanically, but the provenance gate denies
// because no approver-signed approval exists. No execution.
func TestAdvC2B_AnchorChainStillDenied(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)

	// attacker's forge: valid gateway sig, references a nonexistent
	// approval (they cannot sign one — no approver key)
	c := NewContinuation("dec_NONE", "shell", "shell:payload").WithAgentID("agt_live")
	c.WithApprovalID("app_forged")
	c.MarkApproved("attacker")
	c.MarkQueued()
	e.c2bForgeCont(t, c)

	// honest gateway boots: fold, claim, provenance boundary
	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("forge didn't even fold — journal boundary already refused")
	}
	deny, why, err := CheckClaimProvenance(apSt, e.reg, got)
	if err != nil {
		t.Fatalf("provenance check errored (should be clean deny): %v", err)
	}
	if !deny {
		t.Fatal("ANCHOR-01-style forge passed provenance — Phase A failed")
	}
	t.Logf("forged chain denied: %q", why)
}

// errGetter returns a non-"not found" error — the read-fail class.
type c2bErrGetter struct{}

func (c2bErrGetter) Get(string) (*approval.ApprovalRequest, error) {
	return nil, fmt.Errorf("approval store unavailable")
}

// C2B-09: approval store unavailable → UNKNOWN → deny-not-requeue is
// preserved upstream (UNKNOWN leaves the record claimed for retry).
func TestAdvC2B_StoreUnavailable(t *testing.T) {
	e := c2bSetup(t)
	c := NewContinuation("dec_x", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_x")
	deny, _, err := CheckClaimProvenance(c2bErrGetter{}, e.reg, c)
	if deny || err == nil {
		t.Fatalf("store-unavailable must surface UNKNOWN (deny=false, err!=nil): deny=%v err=%v", deny, err)
	}
}

// C2B-10: approver rotation — new pin + new key admits; approvals
// signed under the retired key deny at claim (rotation is a kill
// switch for in-flight authority — documented semantics).
func TestAdvC2B_RotateApproverKey(t *testing.T) {
	e := c2bSetup(t)
	apSt := e.approvalStore(t)
	e.c2bLegitApproval(t, apSt, "app_old", "dec_1")

	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.WithApprovalID("app_old")
	c.MarkApproved("op")
	c.MarkQueued()
	e.c2bForgeCont(t, c)

	// rotation: operator revokes the old key, rotates the pin, admits
	// the replacement — order matters (pin must change before admit)
	newPub, _, _ := ed25519.GenerateKey(nil)
	if err := e.reg.RevokeKey(gwidentity.ApproverID, e.apRec.KeyID); err != nil {
		t.Fatalf("revoke old approver: %v", err)
	}
	if err := e.reg.SetApproverPin(newPub); err != nil {
		t.Fatalf("rotate pin: %v", err)
	}
	if _, err := e.reg.AdmitApprover(newPub); err != nil {
		t.Fatalf("admit rotated approver: %v", err)
	}

	apSt = e.approvalStore(t)
	st := e.contStore(t)
	got, ok := st.ClaimForExecution(c.ContinuationID)
	if !ok {
		t.Fatal("continuation not claimable")
	}
	deny, why, _ := CheckClaimProvenance(apSt, e.reg, got)
	if !deny {
		t.Fatalf("old-approver-key approval survived rotation: %q", why)
	}
}
