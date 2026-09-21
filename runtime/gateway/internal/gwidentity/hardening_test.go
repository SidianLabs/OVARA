package gwidentity

// P2.3.2.1 hardening regressions — F1 perms, F4 grant uniqueness,
// F6 no-create opens, F3 documented boundary.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func hPub() ed25519.PublicKey {
	p, _, _ := ed25519.GenerateKey(nil)
	return p
}

// ---------- F1: registry file permissions are enforced ----------

func TestH1_FreshRegistry0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	r, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("fresh registry must be 0600, got %o", st.Mode().Perm())
	}
	r.Close()
}

func TestH1_ExistingPermMatrix(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{
		{0600, true}, {0644, false}, {0666, false},
		{0620, false}, {0640, false}, {0660, false},
	} {
		p := filepath.Join(t.TempDir(), "reg.jsonl")
		os.WriteFile(p, []byte{}, tc.mode)
		os.Chmod(p, tc.mode) // WriteFile honors umask — force exact mode
		r, err := Open(p)
		if tc.ok != (err == nil) {
			t.Fatalf("mode %o: want accept=%v, err=%v", tc.mode, tc.ok, err)
		}
		if r != nil {
			r.Close()
		}
	}
}

// The audit's confirmed exploit: loose registry + forged grant line →
// admission. With perms enforced, Open refuses before ever folding
// the forged record — the exploit is dead at the door.
func TestH1_ForgedGrantExploitDead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	r, _ := Open(p)
	r.Authorize("gw_a", nil, 0)
	r.Close()
	os.Chmod(p, 0666) // attacker/operator loosens perms
	// non-owner appends a forged authorized grant
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintf(f, `{"kind":"grant","grant_id":"gwg_forged","gateway_id":"gw_a","state":"authorized","created_at":"%s"}`+"\n",
		time.Now().UTC().Format(time.RFC3339Nano))
	f.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("loose-permission registry with forged grant must refuse")
	}
}

// ---------- F4: grant_id uniqueness ----------

// Conflicting definition: same grant_id, different gateway → the file
// fails closed at open/fold.
func TestH4_ConflictingGrantID_FailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	l := func(gw string) string {
		return fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_dup","gateway_id":"%s","state":"authorized","created_at":"%s"}`+"\n", gw, now)
	}
	os.WriteFile(p, []byte(l("gw_a")+l("gw_b")), 0600)
	if _, err := Open(p); err == nil {
		t.Fatal("conflicting grant_id definitions must fail closed")
	}
}

// Same id + same gw but different pinned key = conflicting definition.
func TestH4_ConflictingPin_FailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	l := func(pub string) string {
		return fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_dup","gateway_id":"gw_a","public_key":"%s","state":"authorized","created_at":"%s"}`+"\n", pub, now)
	}
	os.WriteFile(p, []byte(l("")+l("aa")), 0600)
	if _, err := Open(p); err == nil {
		t.Fatal("same-id pin redefinition must fail closed")
	}
}

// Legitimate idempotency: identical line replayed, and state
// transitions of one definition — both fold fine.
func TestH4_IdempotentAndTransitions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	auth := fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_x","gateway_id":"gw_a","state":"authorized","created_at":"%s"}`+"\n", now)
	cons := fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_x","gateway_id":"gw_a","state":"consumed","created_at":"%s","consumed_at":"%s"}`+"\n", now, now)
	os.WriteFile(p, []byte(auth+auth+cons), 0600)
	r, err := Open(p)
	if err != nil {
		t.Fatalf("idempotent + transition fold must load: %v", err)
	}
	gs, _ := r.GrantsFor("gw_a")
	if gs[0].State != GrantConsumed {
		t.Fatalf("want consumed, got %s", gs[0].State)
	}
}

// API-level uniqueness: Authorize never reuses an id.
func TestH4_AuthorizeUniqueIDs(t *testing.T) {
	r := NewInMemory()
	g1, _ := r.Authorize("gw_a", nil, 0)
	g2, _ := r.Authorize("gw_a", nil, 0)
	if g1.GrantID == g2.GrantID {
		t.Fatal("Authorize must mint unique ids")
	}
}

// ---------- F6: OpenExisting never creates ----------

func TestH6_OpenExistingMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope.jsonl")
	if _, err := OpenExisting(p); err == nil {
		t.Fatal("OpenExisting on missing path must fail")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("OpenExisting must not create the file")
	}
	r, err := Open(p) // create path still initializes
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := OpenExisting(p); err != nil {
		t.Fatalf("OpenExisting on real registry: %v", err)
	}
}

// ---------- F3 documented boundary ----------
// Identical duplicate lines fold idempotently (harmless); conflicting
// definitions now fail closed (F4). Record REORDERING that reverses
// state (consumed→authorized) still regresses — last-wins fold has no
// sequence integrity; only dangerous combined with key-state rollback
// (documented architectural limit, anchoring deferred).

func TestH3_ReorderStillRegresses_Documented(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reg.jsonl")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	auth := fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_x","gateway_id":"gw_a","state":"authorized","created_at":"%s"}`+"\n", now)
	cons := fmt.Sprintf(`{"kind":"grant","grant_id":"gwg_x","gateway_id":"gw_a","state":"consumed","created_at":"%s","consumed_at":"%s"}`+"\n", now, now)
	// consumed BEFORE authorized in the file → last-wins = authorized.
	os.WriteFile(p, []byte(cons+auth), 0600)
	r, err := Open(p)
	if err != nil {
		t.Fatalf("reordered file still parses (documented limit): %v", err)
	}
	gs, _ := r.GrantsFor("gw_a")
	if gs[0].State != GrantAuthorized {
		t.Fatalf("expected documented regression to authorized, got %s", gs[0].State)
	}
}

// ---------- post-fix invariants ----------

func TestH_PostFix_ConcurrentAdmissions(t *testing.T) {
	r := NewInMemory()
	r.Authorize("gw_a", nil, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Admit("gw_a", hPub(), false); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("want 1 admission, got %d", wins)
	}
}

func TestH_PostFix_RetiredStaysDead(t *testing.T) {
	r := NewInMemory()
	pub := hPub()
	r.Admit("gw_a", pub, true)
	r.Destroy("gw_a")
	if _, err := r.Admit("gw_a", pub, true); !errors.Is(err, ErrGatewayDestroyed) {
		t.Fatalf("retired must stay dead, got %v", err)
	}
}
