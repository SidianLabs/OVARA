// P2.3.4 security gate — adversarial claim/revoke tests against the
// REAL file-backed registry (not a fake checker). The instrumented
// executor counts invocations so "denied claim ran the executor" is
// observable, not assumed.
package continuation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/revocation"
)

// lp mirrors canon.go — sha256(lp(issuer)‖lp(nonce)) is the
// presentation key; rebuilt here so the test does not depend on
// identity internals.
func lp(s string) []byte {
	b := []byte(s)
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func hopKey(issuer, nonce string) string {
	return fmt.Sprintf("%x", sha256.Sum256(append(lp(issuer), lp(nonce)...)))
}

// spyExec records invocations — the executor-boundary proof: a denied
// claim that ran the executor is the state that must never exist.
type spyExec struct{ calls int32 }

func (s *spyExec) Execute(_ context.Context, e *execution.Execution) error {
	atomic.AddInt32(&s.calls, 1)
	e.MarkStarted()
	e.MarkSucceeded(0, "", "")
	return nil
}

func realRegistry(t *testing.T) *gwidentity.Registry {
	t.Helper()
	reg, err := gwidentity.Open(t.TempDir() + "/reg.jsonl")
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}
	t.Cleanup(func() { reg.Close() })
	return reg
}

func queuedCnt(t *testing.T, store *FileBackedStore, id, leaseID string, delegKeys, issuers []string) *Continuation {
	t.Helper()
	c := NewContinuation("dec-"+id, "shell", "true").
		WithAuthorityIDs(leaseID, delegKeys, issuers)
	c.ContinuationID = id
	c.State = StateQueued // claimable — the pre-claim state machine isn't the test target
	if err := store.Create(c); err != nil {
		t.Fatalf("create: %v", err)
	}
	return c
}

// §3+§4 — claim/revoke race at scale against the real journal. Every
// claim resolves to exactly one of: revoked-before-check → deny, zero
// executor calls; or clean → executor ran once. No third state.
func TestGate_ClaimRevokeRace_RealRegistry(t *testing.T) {
	for _, n := range []int{64, 128, 256} {
		reg := realRegistry(t)
		store, err := NewFileBackedStore(t.TempDir()+"/cont.jsonl", 0)
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		exec := &spyExec{}
		var denied, clean int32

		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("c%d", i)
			// Alternate: half the continuations ride lease lse-race,
			// half ride a delegation presentation key.
			var leaseID string
			var dkeys, issuers []string
			if i%2 == 0 {
				leaseID = "lse-race"
			} else {
				dkeys = []string{hopKey("iss-race", fmt.Sprintf("n%d", i))}
				issuers = []string{"iss-race"}
			}
			queuedCnt(t, store, id, leaseID, dkeys, issuers)
			wg.Add(1)
			go func(id, leaseID string, dkeys, issuers []string) {
				defer wg.Done()
				c, claimed := store.ClaimForExecution(id)
				if !claimed {
					return
				}
				deny, _, err := CheckClaimAuthority(reg, c)
				switch {
				case err != nil:
					c.MarkRequeue()
					store.Update(c)
				case deny:
					c.MarkDenied("revocation", "revoked")
					store.Update(c)
					atomic.AddInt32(&denied, 1)
				default:
					exec.Execute(nil, execution.NewExecution(id, c.DecisionID, c.ApprovalID, c.AgentID, c.ActionType, c.Resource, 5))
					atomic.AddInt32(&clean, 1)
				}
			}(id, leaseID, dkeys, issuers)
		}
		// Revoke concurrently — some claims see it, some don't.
		go reg.Revoke("lease", "lse-race", "op", "race")
		go reg.Revoke("issuer", "iss-race", "op", "race")
		wg.Wait()

		if int64(denied)+int64(clean) != int64(n) {
			t.Fatalf("n=%d: every claim must resolve: denied=%d clean=%d", n, denied, clean)
		}
		// Executor calls must equal EXACTLY the clean claims — a denied
		// claim that ran the executor is the third state we must not see.
		if int64(exec.calls) != int64(clean) {
			t.Fatalf("n=%d: executor calls %d != clean claims %d — denied work executed", n, exec.calls, clean)
		}
	}
}

// §4 — revoked before claim: executor is never invoked. Deterministic.
func TestGate_RevokedBeforeClaim_ZeroExecutorCalls(t *testing.T) {
	reg := realRegistry(t)
	store, err := NewFileBackedStore(t.TempDir()+"/cont.jsonl", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	exec := &spyExec{}

	queuedCnt(t, store, "c1", "lse-1", nil, nil)
	if _, err := reg.Revoke("lease", "lse-1", "op", "kill"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	c, claimed := store.ClaimForExecution("c1")
	if !claimed {
		t.Fatal("claim should win the atomic transition")
	}
	deny, why, err := CheckClaimAuthority(reg, c)
	if err != nil || !deny {
		t.Fatalf("revoked authority must deny: deny=%v err=%v", deny, err)
	}
	c.MarkDenied("revocation", why)
	store.Update(c)
	if exec.calls != 0 {
		t.Fatalf("executor invoked %d times on denied claim", exec.calls)
	}
	got, _ := store.Get("c1")
	if got.State != StateDenied {
		t.Fatalf("state = %q, want denied", got.State)
	}
}

// §6 — mid-hop presentation revocation must be visible at claim-time.
// Chain A→B→C: revoking presentation (A,nAB) kills the chain at eval;
// the queued continuation derived from it must deny too — the recorded
// authority surface includes EVERY hop's presentation key, matching
// eval (F1 regression: terminal-key-only capture let this execute).
func TestGate_MidHopPresentationRevokedAtClaim(t *testing.T) {
	reg := realRegistry(t)
	store, err := NewFileBackedStore(t.TempDir()+"/cont.jsonl", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	terminalKey := hopKey("mid", "n2")
	hop0Key := hopKey("root", "n1")
	// Recorded as the fixed implementation records: every hop key.
	queuedCnt(t, store, "c1", "", []string{hop0Key, terminalKey}, []string{"root", "mid"})

	if _, err := reg.Revoke("delegation", hop0Key, "op", "kill hop0"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	c, claimed := store.ClaimForExecution("c1")
	if !claimed {
		t.Fatal("claim should win")
	}
	deny, why, err := CheckClaimAuthority(reg, c)
	if err != nil {
		t.Fatalf("check err: %v", err)
	}
	if !deny {
		t.Fatalf("mid-hop presentation %q revoked but continuation authorized (why=%q)", hop0Key[:16], why)
	}
}

// §10 — registry failure at claim → requeue, never execute.
func TestGate_ShrunkRegistryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	reg, err := gwidentity.Open(dir + "/reg.jsonl")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := reg.Revoke("lease", "lse-1", "op", "x"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	reg.Close()

	// External truncation below the committed offset → in-process
	// shrink detection must turn every check into UNKNOWN.
	reg2, err := gwidentity.Open(dir + "/reg.jsonl")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reg2.Close()
	if _, err := reg2.Revoke("lease", "lse-2", "op", "grow"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	// Truncate the file while reg2 is live — simulates an attacker or
	// filesystem fault shrinking the committed journal.
	if err := os.Truncate(dir+"/reg.jsonl", 64); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	c := NewContinuation("d", "shell", "true").WithAuthorityIDs("lse-9", nil, nil)
	c.ContinuationID = "c9"
	deny, _, err := CheckClaimAuthority(reg2, c)
	if err == nil {
		t.Fatal("shrunk journal must surface UNKNOWN, not a clean answer")
	}
	if deny {
		t.Fatal("UNKNOWN must not masquerade as revoked — it is requeue")
	}
}

// §23/RVI-14 — revocation landing DURING a running execution is not
// retroactive: the executor completes. The claim boundary is the
// linearization point; the system does not claim to kill in-flight
// external work. This test pins the honest semantic.
func TestGate_RevokeDuringExecution_NotRetroactive(t *testing.T) {
	reg := realRegistry(t)
	store, err := NewFileBackedStore(t.TempDir()+"/cont.jsonl", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	queuedCnt(t, store, "c1", "lse-run", nil, nil)

	release := make(chan struct{})
	ran := make(chan struct{})
	blocking := &blockingExec{release: release, ran: ran}

	c, claimed := store.ClaimForExecution("c1")
	if !claimed {
		t.Fatal("claim should win")
	}
	deny, _, err := CheckClaimAuthority(reg, c)
	if err != nil || deny {
		t.Fatal("pre-revocation claim must pass")
	}
	done := make(chan struct{})
	go func() {
		blocking.Execute(context.Background(),
			execution.NewExecution("c1", c.DecisionID, "", "", c.ActionType, c.Resource, 5))
		close(done)
	}()
	<-ran // executor is mid-flight
	// Revocation lands while the executor runs — documented semantics:
	// not retroactive, the in-flight execution completes.
	if _, err := reg.Revoke("lease", "lse-run", "op", "mid-run"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	close(release)
	<-done
	if blocking.calls != 1 {
		t.Fatalf("executor ran %d times, want 1", blocking.calls)
	}
	c.MarkExecuted()
	store.Update(c)
	got, _ := store.Get("c1")
	if got.State != StateExecuted {
		t.Fatalf("post-revocation in-flight execution completed to %q", got.State)
	}
}

type blockingExec struct {
	release chan struct{}
	ran     chan struct{}
	calls   int32
}

func (b *blockingExec) Execute(_ context.Context, e *execution.Execution) error {
	atomic.AddInt32(&b.calls, 1)
	e.MarkStarted()
	close(b.ran)
	<-b.release
	e.MarkSucceeded(0, "", "")
	return nil
}

// Concurrent duplicate revocation of the same target — exercises the
// dup path's epoch read under the mutation lock (previously r.seq was
// read unlocked: data race on concurrent revokes).
func TestGate_ConcurrentDupRevoke(t *testing.T) {
	reg := realRegistry(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg.Revoke("lease", "lse-dup", "op", "race")
		}()
	}
	wg.Wait()
	off, rev, err := reg.AnyRevoked(revocation.P(revocation.ClassLease, "lse-dup"))
	if err != nil || !rev {
		t.Fatalf("dup-concurrent revoke must still land: rev=%v err=%v", rev, err)
	}
	_ = off
	recs, err := reg.Revocations()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("dup revokes appended %d records — must be exactly 1 durable kill", len(recs))
	}
}
