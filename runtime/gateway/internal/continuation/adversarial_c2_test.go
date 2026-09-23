package continuation

// C2 / key-compromise adversarial suite — quantifies the blast radius
// when the attacker can WRITE the trust-domain filesystem and/or HOLD
// the gateway signing key (gateway.key), while the external anchor
// and revocation view remain honest. These tests establish, in code,
// which boundaries hold and which fail — the results are the C2
// evaluation's evidence, not assumptions.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/record"
	"ovara.runtime.gateway/internal/revocation"
)

type setChecker map[revocation.Pair]bool

func (m setChecker) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	for _, p := range pairs {
		if m[p] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

func (m setChecker) Epoch() (uint64, error) { return 1, nil }

const (
	c2LegitID  = "cont_legit"
	c2ForgedID = "cont_forged"
)

// KEY-01: a correctly-signed, attacker-crafted "queued" continuation
// survives fold, is claimable, and passes the claim-time authority
// check — proving signature authenticates a record but does NOT prove
// it came through the evaluate→approve pipeline. With the key, the
// attacker IS indistinguishable from the gateway to the journal.
func TestAdvC2_KEY01_ForgedQueuedContinuationIsClaimable(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")

	j, err := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	legit := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	legit.ContinuationID = c2LegitID
	legit.MarkApproved("admin")
	legit.MarkQueued()
	appendCont(t, j, legit)

	// attacker (holding the key) appends a forged queued genesis:
	// no approval decision, no lease, no delegation — chosen action.
	forged := NewContinuation("dec_NONE", "shell", "shell:rm -rf /").WithAgentID("agt_live")
	forged.ContinuationID = c2ForgedID
	forged.MarkApproved("attacker")
	forged.MarkQueued()
	// authority fields deliberately EMPTY: LeaseID/DelegationKeys/
	// Issuers nil, AuthorityExpiresAt nil → claim-time checks no-op.
	appendCont(t, j, forged)
	j.Close()

	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("forged journal rejected — this would close the scenario: %v", err)
	}
	got, ok := st.Get(c2ForgedID)
	if !ok || got.State != StateQueued {
		t.Fatalf("forged record not folded to queued: %v %v", got, ok)
	}
	claimed, ok := st.ClaimForExecution(c2ForgedID)
	if !ok || claimed == nil {
		t.Fatal("forged record not claimable")
	}
	deny, why, err := CheckClaimAuthority(nil, claimed)
	if deny || err != nil {
		t.Fatalf("forged continuation denied (%s) — boundary holds here: %v", why, err)
	}
	st.journal.Close()
}

// KEY-02: the honest gateway's own tip-ledger ratchet commits the
// attacker's forged tip — the anchor then seals malicious state as
// genuine. The attacker never touches the ledger: boot-time fold
// adopts the forged tip and JournalTip() reports it for commitment.
func TestAdvC2_KEY02_RatchetCommitsForgedTip(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")

	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = c2LegitID
	c.MarkApproved("admin")
	c.MarkQueued()
	appendCont(t, j, c)
	legitSeq, legitTip := j.Tip()
	j.Close()

	// attacker appends one forged line — valid signature + chain,
	// because the key is theirs.
	j, err := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	forged := NewContinuation("dec_NONE", "shell", "shell:payload").WithAgentID("agt_live")
	forged.ContinuationID = c2ForgedID
	forged.MarkApproved("attacker")
	forged.MarkQueued()
	appendCont(t, j, forged)
	j.Close()

	// honest reboot: folds fine, store opens, and JournalTip — the
	// value postOpenRatchet commits to the anchored ledger — is the
	// forged tip.
	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatal(err)
	}
	seq, tip := st.JournalTip()
	if seq != legitSeq+1 || tip == legitTip {
		t.Fatalf("expected tip to advance onto forged line: seq=%d tip=%s", seq, tip)
	}
	st.journal.Close()
	// consequence: RecordTips(seq, tip) commits the forged tip inside
	// the anchored gwidentity chain; the anchor seals it. The ratchet
	// cannot distinguish forged-from-genuine.
}

// KEY-03: the floor DOES bound the attacker below the last committed
// tip — a forged rewrite that truncates committed history is refused.
// The bound is backward-looking only.
func TestAdvC2_KEY03_FloorBlocksRewriteBelowTip(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")

	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = c2LegitID
	c.MarkApproved("admin")
	c.MarkQueued()
	appendCont(t, j, c)
	d := *c
	d.MarkDenied("revocation", "killed")
	appendCont(t, j, &d)
	seq, tip := j.Tip()
	j.Close()

	// attacker truncates the denial and re-signs a forged tail — valid
	// signatures, but below the committed floor.
	data, _ := os.ReadFile(p)
	os.WriteFile(p, joinLines(splitLines(data)[:1]), 0o600)
	j, err := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	forged := *c
	forged.State = StateExecuting
	appendCont(t, j, &forged)
	j.Close()

	b := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq, Hash: tip}}
	if _, err := NewFileBackedStoreWithRetention(p, 0, 0, 0, b); err == nil {
		t.Fatal("rewrite below committed floor accepted")
	}
}

// KEY-04: revocation bounds the forge only when the forged record
// carries authority pairs that can be revoked. Empty authority fields
// are out of revocation's reach — pairs==0 → pass.
func TestAdvC2_KEY04_RevocationBoundIsPairsScoped(t *testing.T) {
	rc := setChecker{revocation.P(revocation.ClassLease, "lease_fake"): true}
	c := NewContinuation("dec_NONE", "shell", "shell:payload").WithAgentID("agt_live")
	c.LeaseID = "lease_fake"
	deny, _, err := CheckClaimAuthority(rc, c)
	if !deny || err != nil {
		t.Fatalf("revoked forged lease not denied: deny=%v err=%v", deny, err)
	}

	// same forge with EMPTY authority fields → nothing to revoke → pass
	c2 := NewContinuation("dec_NONE", "shell", "shell:payload").WithAgentID("agt_live")
	deny, _, err = CheckClaimAuthority(rc, c2)
	if deny || err != nil {
		t.Fatalf("empty-authority forge was denied — unexpected: %v", err)
	}
}

// KEY-05: key rotation does not retroactively revoke the stolen key —
// records signed under the old key remain verifiable while the old
// key_id stays in the registry (required for history), so an attacker
// forges NEW records under the old key until it is deregistered.
func TestAdvC2_KEY05_RotationKeepsOldKeyVerifiable(t *testing.T) {
	pubOld, privOld, _ := ed25519.GenerateKey(nil)
	pubNew, _, _ := ed25519.GenerateKey(nil)
	attacker := record.NewSigner(privOld, "dom-test", "gw1", "k-old")
	// rotation keeps k-old resolvable — otherwise every pre-rotation
	// record fails to open; that necessity is the forge's window.
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		switch kid {
		case "k-old":
			return pubOld, nil
		case "k-new":
			return pubNew, nil
		}
		return nil, errTestNoKey("no key")
	}

	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, attacker.Domain(), attacker, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.MarkApproved("attacker")
	c.MarkQueued()
	appendCont(t, j, c)
	j.Close()

	st, err := openBoundStore(t, p, attacker, resolve)
	if err != nil {
		t.Fatalf("old-key forge refused — this would mean rotation bounds forward-forge: %v", err)
	}
	st.journal.Close()
}

// KEY-06: full-path demonstration — the forged record DISPATCHES to
// the executor when the identity gate sees a live agent_id. This is
// the end of the kill chain, not a fold-level detail.
func TestAdvC2_KEY06_ForgedContinuationExecutes(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 50 * time.Millisecond
	orch.SetIdentityChecker(func(id string) bool { return id == "agt_live" })
	orch.Start()
	defer orch.Stop()

	forged := NewContinuation("dec_NONE", "shell", "shell:payload").WithAgentID("agt_live")
	forged.ContinuationID = c2ForgedID
	forged.MarkApproved("attacker")
	forged.MarkQueued()
	store.Create(forged)

	for i := 0; i < 40 && exec.Calls() == 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if exec.Calls() == 0 {
		t.Fatal("forged queued continuation never reached the executor — an unseen gate holds (report it)")
	}
}
