package gwidentity

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

func newPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// E2: grant → admit → ACTIVE binding; consume recorded atomically.
func TestAdmit_GrantConsumesAndBinds(t *testing.T) {
	r := NewInMemory()
	pub := newPub(t)
	g, err := r.Authorize("gw_a", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.Admit("gw_a", pub, false)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != KeyActive {
		t.Fatalf("want active, got %s", rec.State)
	}
	got, _ := r.GrantsFor("gw_a")
	if got[0].State != GrantConsumed {
		t.Fatalf("grant must be consumed, got %s", got[0].State)
	}
	_ = g
}

// E1/E2: possession alone is not admission — no grant, not allowed.
func TestAdmit_NoGrant_RefusedWhenRequired(t *testing.T) {
	r := NewInMemory()
	if _, err := r.Admit("gw_a", newPub(t), false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	if _, err := r.Admit("gw_a", newPub(t), true); err != nil {
		t.Fatalf("compat auto-admit should allow, got %v", err)
	}
}

// Idempotent adopt: a consumed grant does not block restarts.
func TestAdmit_RestartAdopts(t *testing.T) {
	r := NewInMemory()
	pub := newPub(t)
	r.Authorize("gw_a", nil, 0)
	rec1, _ := r.Admit("gw_a", pub, false)
	rec2, err := r.Admit("gw_a", pub, false)
	if err != nil || rec2.KeyID != rec1.KeyID {
		t.Fatalf("restart adopt failed: %v", err)
	}
}

// E8/replay: a consumed grant cannot admit a second key.
func TestAdmit_ConsumedGrant_NoSecondKey(t *testing.T) {
	r := NewInMemory()
	pubA, pubB := newPub(t), newPub(t)
	r.Authorize("gw_a", nil, 0)
	r.Admit("gw_a", pubA, false)
	if _, err := r.Admit("gw_a", pubB, false); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("second key on consumed grant must conflict, got %v", err)
	}
}

// Pinned grant: matching pub admits, other pub refused.
func TestAdmit_PinnedGrant(t *testing.T) {
	r := NewInMemory()
	pubA, pubB := newPub(t), newPub(t)
	if _, err := r.Authorize("gw_a", pubA, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Admit("gw_a", pubA, false); err != nil {
		t.Fatalf("pinned pub must admit, got %v", err)
	}
	r2 := NewInMemory()
	r2.Authorize("gw_a", pubA, 0)
	if _, err := r2.Admit("gw_a", pubB, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-pinned pub must refuse, got %v", err)
	}
}

// Denied grant: blocks admission even in open mode.
func TestAdmit_DeniedGrant(t *testing.T) {
	r := NewInMemory()
	pub := newPub(t)
	g, _ := r.Authorize("gw_a", nil, 0)
	if err := r.Deny(g.GrantID); err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		if _, err := r.Admit("gw_a", pub, allow); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("denied grant must refuse (allow=%v), got %v", allow, err)
		}
	}
}

// Expired grant: cannot authorize.
func TestAdmit_ExpiredGrant(t *testing.T) {
	r := NewInMemory()
	pub := newPub(t)
	r.Authorize("gw_a", nil, -1*time.Second) // already expired
	if _, err := r.Admit("gw_a", pub, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired grant must refuse, got %v", err)
	}
}

// Deny-after-consume is meaningless and refused; deny is idempotent.
func TestDeny_ConsumedAndIdempotent(t *testing.T) {
	r := NewInMemory()
	g, _ := r.Authorize("gw_a", nil, 0)
	r.Admit("gw_a", newPub(t), false)
	if err := r.Deny(g.GrantID); err == nil {
		t.Fatal("deny of consumed grant must fail")
	}
	g2, _ := r.Authorize("gw_b", nil, 0)
	if err := r.Deny(g2.GrantID); err != nil {
		t.Fatal(err)
	}
	if err := r.Deny(g2.GrantID); err != nil {
		t.Fatal("deny must be idempotent")
	}
	if err := r.Deny("gwg_nonexistent"); !errors.Is(err, ErrUnknownGrant) {
		t.Fatalf("unknown grant: %v", err)
	}
}

// E6: retired gateway cannot re-enroll — tombstone beats an
// outstanding authorized grant AND any new key.
func TestAdmit_RetiredGateway_StaysDead(t *testing.T) {
	r := NewInMemory()
	pubA, pubB := newPub(t), newPub(t)
	r.Admit("gw_a", pubA, true)
	r.Destroy("gw_a")
	r.Authorize("gw_a", nil, 0) // pending grant must not help
	for _, pub := range []ed25519.PublicKey{pubA, pubB} {
		if _, err := r.Admit("gw_a", pub, true); !errors.Is(err, ErrGatewayDestroyed) {
			t.Fatalf("retired gateway must refuse, got %v", err)
		}
	}
	if _, err := r.Rotate("gw_a", pubB, time.Hour); !errors.Is(err, ErrGatewayDestroyed) {
		t.Fatalf("rotation must not resurrect retired gateway, got %v", err)
	}
}

// E10: rotation cannot bypass admission (new identity via rotate).
func TestAdmit_RotationCannotBootstrap(t *testing.T) {
	r := NewInMemory()
	if _, err := r.Rotate("gw_new", newPub(t), time.Hour); !errors.Is(err, ErrUnknownGateway) {
		t.Fatalf("rotate on unenrolled gateway must fail, got %v", err)
	}
}

// E9: concurrent admits of different keys → exactly one winner.
func TestAdmit_ConcurrentConflict_OneWinner(t *testing.T) {
	r := NewInMemory()
	r.Authorize("gw_a", nil, 0)
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Admit("gw_a", newPub(t), false); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("want exactly 1 admission, got %d", wins)
	}
}

// Atomicity: grant-consume and key-bind are one journal append — the
// file must contain both records after a single Admit.
func TestAdmit_AtomicConsumeAndBind_Persisted(t *testing.T) {
	p := t.TempDir() + "/reg.jsonl"
	r, _ := Open(p)
	r.Authorize("gw_a", nil, 0)
	pub := newPub(t)
	if _, err := r.Admit("gw_a", pub, false); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	gs, _ := r2.GrantsFor("gw_a")
	if len(gs) != 1 || gs[0].State != GrantConsumed {
		t.Fatalf("consumed grant must persist, got %+v", gs)
	}
	if !r2.HasUsableKey("gw_a") {
		t.Fatal("bound key must persist")
	}
}

// Old-format file (pre-"kind" lines) still loads; grant lines parse.
func TestAbsorb_MixedKindRecords(t *testing.T) {
	p := t.TempDir() + "/reg.jsonl"
	r, _ := Open(p)
	pub := newPub(t)
	r.Register("gw_old", pub) // P2.3.1 path
	r.Authorize("gw_old", nil, 0)
	r.Close()
	r2, err := Open(p)
	if err != nil {
		t.Fatalf("mixed-kind file must load: %v", err)
	}
	if gs, _ := r2.GrantsFor("gw_old"); len(gs) != 1 {
		t.Fatal("grant must survive reload")
	}
}

// A grant for one gateway never admits another.
func TestAdmit_GrantScopedToGateway(t *testing.T) {
	r := NewInMemory()
	r.Authorize("gw_b", nil, 0)
	if _, err := r.Admit("gw_a", newPub(t), false); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("grant for gw_b must not admit gw_a, got %v", err)
	}
}
