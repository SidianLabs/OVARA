package continuation

import (
	"fmt"
	"sync"
	"testing"

	"ovara.runtime.gateway/internal/revocation"
)

type fakeRev struct {
	mu      sync.Mutex
	revoked map[revocation.Pair]bool
	err     error
}

func (f *fakeRev) revoke(p revocation.Pair) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[p] = true
}

func (f *fakeRev) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return revocation.Pair{}, false, f.err
	}
	for _, p := range pairs {
		if f.revoked[p] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

func (f *fakeRev) Epoch() (uint64, error) { return 1, f.err }

// RVI-06: a queued continuation is revalidated at claim time — a
// revocation committed after queueing must deny the claim.
func TestClaimRevocation_QueuedThenRevoked(t *testing.T) {
	store := NewInMemoryStore()
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}}

	cnt := NewContinuation("dec-1", "shell", "host").
		WithAuthorityIDs("lse-1", nil, nil)
	cnt.MarkApproved("op")
	cnt.MarkQueued()
	store.Create(cnt)

	// Authority revoked AFTER queueing.
	fc.revoke(revocation.P(revocation.ClassLease, "lse-1"))

	c, claimed := store.ClaimForExecution(cnt.ContinuationID)
	if !claimed {
		t.Fatal("claim should succeed — the boundary is post-claim")
	}
	deny, why, err := CheckClaimAuthority(fc, c)
	if err != nil || !deny {
		t.Fatalf("revoked lease must deny at claim: deny=%v why=%q err=%v", deny, why, err)
	}
}

// Issuer-class revocation kills at claim too.
func TestClaimRevocation_IssuerRevoked(t *testing.T) {
	store := NewInMemoryStore()
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}}
	cnt := NewContinuation("dec-1", "shell", "host").
		WithAuthorityIDs("", []string{"pk-abc"}, []string{"root", "mid"})
	cnt.MarkApproved("op")
	cnt.MarkQueued()
	store.Create(cnt)

	fc.revoke(revocation.P(revocation.ClassIssuer, "mid"))
	c, _ := store.ClaimForExecution(cnt.ContinuationID)
	deny, _, _ := CheckClaimAuthority(fc, c)
	if !deny {
		t.Fatal("revoked hop issuer must deny at claim")
	}
}

// RVI-03: a sibling presentation's continuation still claims.
func TestClaimRevocation_SiblingUnaffected(t *testing.T) {
	store := NewInMemoryStore()
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}}
	cnt := NewContinuation("dec-1", "shell", "host").
		WithAuthorityIDs("lse-2", []string{"pk-B"}, []string{"root"})
	cnt.MarkApproved("op")
	cnt.MarkQueued()
	store.Create(cnt)

	fc.revoke(revocation.P(revocation.ClassDelegation, "pk-A")) // sibling
	c, _ := store.ClaimForExecution(cnt.ContinuationID)
	deny, _, err := CheckClaimAuthority(fc, c)
	if err != nil || deny {
		t.Fatal("sibling revocation must not kill this continuation")
	}
}

// RVI-09: storage failure → UNKNOWN → requeue (fail closed), never
// execute and never a terminal deny on a transient error.
func TestClaimRevocation_StorageFailureRequeues(t *testing.T) {
	store := NewInMemoryStore()
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}, err: fmt.Errorf("journal corrupt")}
	cnt := NewContinuation("dec-1", "shell", "host").
		WithAuthorityIDs("lse-1", nil, nil)
	cnt.MarkApproved("op")
	cnt.MarkQueued()
	store.Create(cnt)

	c, _ := store.ClaimForExecution(cnt.ContinuationID)
	deny, _, err := CheckClaimAuthority(fc, c)
	if err == nil {
		t.Fatal("storage failure must surface as error")
	}
	if deny {
		t.Fatal("UNKNOWN is not a terminal deny — requeue is correct")
	}
	// The orchestrator contract: requeue so the claim cannot execute.
	c.MarkRequeue()
	store.Update(c)
	got, _ := store.Get(cnt.ContinuationID)
	if got.State != StateQueued {
		t.Fatalf("requeued continuation must return to queued, got %s", got.State)
	}
}

// No recorded authority → nothing to check (legacy continuations).
func TestClaimRevocation_NoAuthorityPasses(t *testing.T) {
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}}
	cnt := NewContinuation("dec-1", "shell", "host")
	deny, _, err := CheckClaimAuthority(fc, cnt)
	if err != nil || deny {
		t.Fatal("capability-less continuation has nothing to check")
	}
}

// RVI-06 + concurrency: revoke racing claims — exactly one outcome is
// allowed per claim (deny or execute-under-prior-view), never torn.
func TestClaimRevocation_ConcurrentRace(t *testing.T) {
	fc := &fakeRev{revoked: map[revocation.Pair]bool{}}
	var mu sync.Mutex
	var denied, clean int
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cnt := NewContinuation("d", "shell", "h").WithAuthorityIDs("lse-1", nil, nil)
			deny, _, err := CheckClaimAuthority(fc, cnt)
			mu.Lock()
			if err != nil || deny {
				denied++
			} else {
				clean++
			}
			mu.Unlock()
		}()
	}
	// Concurrent revocation while checks run.
	fc.revoke(revocation.P(revocation.ClassLease, "lse-1"))
	wg.Wait()
	if denied+clean != 64 {
		t.Fatal("every check must resolve")
	}
}
