// Signed-journal mode (P2.4 + C2-B A1): approvals are hash-chained,
// approver-signed envelopes folded through the total transition table.
// The legacy whole-file tests cover unsigned mode; these cover the
// durable authority path — fold/reopen must replay every legal record
// and refuse every forged one.
package approval

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

type signedFixture struct {
	store   *FileBackedStore
	path    string
	signer  *record.Signer
	pub     ed25519.PublicKey
	resolve record.ResolveFunc
}

func signedStore(t *testing.T) *signedFixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := record.NewSigner(priv, "domA", gwidentity.ApproverID, "ak1")
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw == gwidentity.ApproverID && kid == "ak1" {
			return pub, nil
		}
		return nil, errNoApproverKey
	}
	p := filepath.Join(t.TempDir(), "approvals.jsonl")
	s, err := NewFileBackedStore(p, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatalf("signed store open: %v", err)
	}
	return &signedFixture{store: s, path: p, signer: signer, pub: pub, resolve: resolve}
}

var errNoApproverKey = errString("no approver key")

type errString string

func (e errString) Error() string { return string(e) }

func (f *signedFixture) reopenErr() (*FileBackedStore, error) {
	return NewFileBackedStore(f.path, &record.Binding{Signer: f.signer, Resolve: f.resolve})
}

func (f *signedFixture) reopen(t *testing.T) *FileBackedStore {
	t.Helper()
	s, err := f.reopenErr()
	if err != nil {
		t.Fatalf("signed store reopen: %v", err)
	}
	return s
}

func pendingReq(id, decisionID string) *ApprovalRequest {
	return &ApprovalRequest{
		ApprovalID:  id,
		DecisionID:  decisionID,
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:ls",
		Environment: models.EnvironmentLocal,
		Status:      StatusPending,
		AgentID:     "agt_a",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		RequestHash: "rh1",
	}
}

// Journal-mode CRUD: every write is an approver-signed envelope whose
// signature verifies detached via record.SigningPayload, and a reopen
// folds the journal back into identical state.
func TestSignedStore_RoundTripAndRefold(t *testing.T) {
	f := signedStore(t)
	s := f.store

	if err := s.Create(pendingReq("app_1", "dec_1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(pendingReq("app_2", "dec_1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(pendingReq("app_3", "dec_2")); err != nil {
		t.Fatal(err)
	}

	// The create envelope proves approver-root provenance offline.
	env := s.EnvelopeFor("app_1")
	if env == nil {
		t.Fatal("no signed envelope for journaled approval")
	}
	if env.KeyRef.GatewayID != gwidentity.ApproverID || env.KeyRef.KeyID != "ak1" {
		t.Fatalf("envelope not under approver root: %+v", env.KeyRef)
	}
	sig, _ := hex.DecodeString(env.Sig)
	if !ed25519.Verify(f.pub, record.SigningPayload(env), sig) {
		t.Fatal("approval envelope does not verify detached")
	}

	if _, err := s.Resolve("app_1", StatusApproved, "op", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve("app_2", StatusDenied, "op", "no"); err != nil {
		t.Fatal(err)
	}
	// Resume consume — once.
	got, err := s.ConsumeResume("app_1")
	if err != nil || got.ResumedAt == nil {
		t.Fatalf("resume consume: %v resumed_at=%v", err, got)
	}
	if _, err := s.ConsumeResume("app_1"); err == nil {
		t.Fatal("resume token consumed twice")
	}
	if _, err := s.ConsumeResume("app_2"); err == nil {
		t.Fatal("denied approval resumed")
	}
	if _, err := s.Resolve("app_1", StatusDenied, "op", ""); err == nil {
		t.Fatal("second resolve accepted — approvals must decide once")
	}
	if _, err := s.Resolve("app_1", "bogus", "op", ""); err == nil {
		t.Fatal("invalid decision accepted")
	}
	if _, err := s.Resolve("missing", StatusApproved, "op", ""); err == nil {
		t.Fatal("resolve on unknown id accepted")
	}
	if _, err := s.Get("missing"); err == nil {
		t.Fatal("get on unknown id accepted")
	}

	// List/read paths reflect live state.
	if all := s.ListAll(); len(all) != 3 {
		t.Fatalf("ListAll = %d, want 3", len(all))
	}
	if l := s.ListByDecision("dec_1"); len(l) != 2 {
		t.Fatalf("ListByDecision = %d, want 2", len(l))
	}
	if l := s.ListByStatus(StatusPending); len(l) != 1 || l[0].ApprovalID != "app_3" {
		t.Fatalf("ListByStatus pending = %v", l)
	}
	if p, tot := s.Stats(); p != 1 || tot != 3 {
		t.Fatalf("Stats = %d/%d", p, tot)
	}
	seq, tip := s.JournalTip()
	if seq == 0 || tip == "" {
		t.Fatal("journal tip not committed")
	}

	// Fold/reopen: state must be rebuilt from signed history alone —
	// including resume consumption and tombstones.
	re := f.reopen(t)
	a1, err := re.Get("app_1")
	if err != nil || a1.Status != StatusApproved || a1.ResumedAt == nil {
		t.Fatalf("refolded app_1 wrong: %+v err=%v", a1, err)
	}
	if a1.SignerKeyID != "ak1" {
		t.Fatalf("folded record lost signer key_ref: %q", a1.SignerKeyID)
	}
	if re.EnvelopeFor("app_1") == nil {
		t.Fatal("reopen lost the provenance envelope")
	}
	if _, err := re.ConsumeResume("app_1"); err == nil {
		t.Fatal("consumed resume token accepted after reopen")
	}
	if s2, _ := re.JournalTip(); s2 != seq {
		t.Fatalf("reopened tip seq %d, want %d", s2, seq)
	}
}

// Tombstones are permanent: the id stays dead across delete and
// reopen — genesis-over-tombstone is a fold error, not a recreate.
func TestSignedStore_TombstonePersistsAcrossReopen(t *testing.T) {
	f := signedStore(t)
	s := f.store
	if err := s.Create(pendingReq("app_1", "dec_1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("app_1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(pendingReq("app_1", "dec_1")); err == nil {
		t.Fatal("recreate over tombstone accepted")
	}
	re := f.reopen(t)
	if _, err := re.Get("app_1"); err == nil {
		t.Fatal("tombstoned approval resurrected on reopen")
	}
	if err := re.Create(pendingReq("app_1", "dec_1")); err == nil {
		t.Fatal("tombstoned id re-created after reopen")
	}
}

// An immutable-core mutation must fail the fold. The journal appends
// any correctly-signed line — legality is the fold's verdict, not the
// writer's — so a poisoned record survives on disk but a reopen
// refuses it, failing closed rather than serving mutated history.
func TestSignedStore_CoreMutationFailsFold(t *testing.T) {
	f := signedStore(t)
	s := f.store
	req := pendingReq("app_1", "dec_1")
	if err := s.Create(req); err != nil {
		t.Fatal(err)
	}
	// Same-state rewrite is legal (restates, never mutates).
	if err := s.Update(req); err != nil {
		t.Fatalf("same-state update refused: %v", err)
	}
	mut := pendingReq("app_1", "dec_1")
	mut.Resource = "shell:rm -rf /"
	mut.CreatedAt = req.CreatedAt // core equality includes CreatedAt
	if err := s.Update(mut); err != nil {
		t.Fatalf("signed append of an illegal record failed at write time: %v", err)
	}
	if _, err := f.reopenErr(); err == nil {
		t.Fatal("immutable-core mutation survived a journal fold")
	}
}

// A tips-sink failure on append must surface — the write is only
// committed-floor evidence once the ledger knows the tip.
func TestSignedStore_TipsSinkErrorPropagates(t *testing.T) {
	f := signedStore(t)
	f.store.SetTipsSink(func(uint64, string) error { return errNoApproverKey })
	if err := f.store.Create(pendingReq("app_1", "dec_1")); err == nil {
		t.Fatal("tips-sink failure swallowed on create")
	}
}
