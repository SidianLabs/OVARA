package gwidentity

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"ovara.runtime.gateway/internal/revocation"
)

func openRevReg(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gwreg.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

func TestRevoke_BasicAndIndex(t *testing.T) {
	r, _ := openRevReg(t)

	off, rev, err := r.AnyRevoked(revocation.P(revocation.ClassIssuer, "iss-a"))
	if err != nil || rev {
		t.Fatalf("expected clean: rev=%v err=%v", rev, err)
	}

	rv, err := r.Revoke("issuer", "iss-a", "op-1", "compromised")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rv.Class != "issuer" || rv.Target != "iss-a" || rv.Actor != "op-1" || rv.Seq == 0 {
		t.Fatalf("bad record: %+v", rv)
	}

	off, rev, err = r.AnyRevoked(revocation.P(revocation.ClassIssuer, "iss-a"))
	if err != nil || !rev || off.Class != revocation.ClassIssuer {
		t.Fatalf("expected revoked issuer: off=%v rev=%v err=%v", off, rev, err)
	}

	// Sibling granularity: another issuer + class separation.
	off, rev, err = r.AnyRevoked(
		revocation.P(revocation.ClassIssuer, "iss-b"),
		revocation.P(revocation.ClassLease, "iss-a"), // same target string, different class
	)
	if err != nil || rev {
		t.Fatalf("sibling must be unaffected: off=%v rev=%v", off, rev)
	}
}

func TestRevoke_BadClassAndTarget(t *testing.T) {
	r, _ := openRevReg(t)
	if _, err := r.Revoke("nonsense", "x", "op", ""); err != ErrBadRevocationClass {
		t.Fatalf("expected ErrBadRevocationClass, got %v", err)
	}
	if _, err := r.Revoke("issuer", "", "op", ""); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestRevoke_Idempotent(t *testing.T) {
	r, _ := openRevReg(t)
	if _, err := r.Revoke("lease", "lse-1", "op", ""); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	ep1, _ := r.Epoch()
	// Second revoke of the same target must not append noise.
	if _, err := r.Revoke("lease", "lse-1", "op", "again"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	ep2, _ := r.Epoch()
	if ep1 != ep2 {
		t.Fatalf("idempotent revoke advanced epoch: %d → %d", ep1, ep2)
	}
	recs, _ := r.Revocations()
	if len(recs) != 1 {
		t.Fatalf("expected 1 revocation record, got %d", len(recs))
	}
}

func TestRevoke_DurableAcrossRestart(t *testing.T) {
	r, path := openRevReg(t)
	if _, err := r.Revoke("delegation", "pk-deadbeef", "op", "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	r.Close()

	// Reopen — the revocation must be durable.
	r2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer r2.Close()
	_, rev, err := r2.AnyRevoked(revocation.P(revocation.ClassDelegation, "pk-deadbeef"))
	if err != nil || !rev {
		t.Fatalf("revocation lost across restart: rev=%v err=%v", rev, err)
	}
}

// SIGKILL-recovery equivalent: mutate fsyncs before committing, so a
// kill at any point either lands the whole record or truncates it on
// the next absorb — a revoked target must never come back active.
func TestRevoke_TornTailTruncated(t *testing.T) {
	r, path := openRevReg(t)
	if _, err := r.Revoke("issuer", "iss-a", "op", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	r.Close()

	// Simulate a torn write: append a partial line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"kind":"revoke","class":"lease","target":"lse-9`)
	f.Close() // no fsync, partial JSON — crash mid-append

	r2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after torn tail: %v", err)
	}
	defer r2.Close()
	_, rev, _ := r2.AnyRevoked(revocation.P(revocation.ClassIssuer, "iss-a"))
	if !rev {
		t.Fatal("committed revocation lost after torn-tail recovery")
	}
}

func TestRevoke_CorruptRecordFailsLoad(t *testing.T) {
	r, path := openRevReg(t)
	if _, err := r.Revoke("issuer", "iss-a", "op", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	r.Close()

	// Corrupt a byte inside the committed record — chain mismatch must
	// refuse the whole load (fail closed, never "nothing revoked").
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	r2, err := Open(path)
	if err == nil {
		r2.Close()
		t.Fatal("corrupt journal must fail to open")
	}
}

// Rollback — two detectors. In-process: a registry that already folded
// epoch N refuses a shrunken file (absorb fails → UNKNOWN, never
// "not revoked"). Cross-boot: the same-substitution is caught by the
// hash chain (modified record → load refuses); the L<A case is the
// P2.3.3 anchor reconcile, exercised by its own suite.
func TestRevoke_RollbackDetected(t *testing.T) {
	r, path := openRevReg(t)
	r.Revoke("issuer", "iss-a", "op", "")
	r.Revoke("issuer", "iss-b", "op", "") // r.seq=2, r.off=size

	// Shrink the file behind the live registry — absorb must fail.
	lines := readLines(t, path)
	writeLines(t, path, lines[:len(lines)-1])
	_, _, err := r.AnyRevoked(revocation.P(revocation.ClassIssuer, "iss-a"))
	if err == nil {
		t.Fatal("shrunken journal must fail closed (UNKNOWN), not answer")
	}
	r.Close()

	// Rewrite the last record in place (same length class change) —
	// chain mismatch must refuse the whole load.
	lines = readLines(t, path)
	var tampered []byte
	for i, l := range lines {
		if i == len(lines)-1 {
			l = []byte(`{"kind":"revoke","class":"issuer","target":"iss-a","actor":"x","revoked_at":"2025-01-01T00:00:00Z","seq":1,"chain":"0000000000000000000000000000000000000000000000000000000000000000"}` + "\n")
		}
		tampered = append(tampered, l...)
	}
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	r2, err := Open(path)
	if err == nil {
		r2.Close()
		t.Fatal("chain-mismatched journal must fail to open")
	}
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, data[start:i+1])
			start = i + 1
		}
	}
	return out
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var data []byte
	for _, l := range lines {
		data = append(data, l...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestRevoke_EpochMonotonic(t *testing.T) {
	r, _ := openRevReg(t)
	ep0, _ := r.Epoch()
	r.Revoke("issuer", "a", "op", "")
	ep1, _ := r.Epoch()
	r.Revoke("lease", "l1", "op", "")
	ep2, _ := r.Epoch()
	if !(ep0 < ep1 && ep1 < ep2) {
		t.Fatalf("epoch not monotonic: %d %d %d", ep0, ep1, ep2)
	}
}

// The Checker contract — storage failure is UNKNOWN, not "active".
func TestRevoke_CheckerInterface(t *testing.T) {
	var _ revocation.Checker = (*Registry)(nil)
}

func TestRevoke_Concurrent(t *testing.T) {
	r, _ := openRevReg(t)
	var wg sync.WaitGroup
	// Concurrent revokes + checks across classes — no race, no lost kill.
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			cls := "issuer"
			if n%2 == 0 {
				cls = "lease"
			}
			tgt := string(rune('a'+n%26)) + string(rune('0'+n/26))
			if _, err := r.Revoke(cls, tgt, "op", ""); err != nil {
				t.Errorf("revoke %d: %v", n, err)
			}
		}(i)
		go func(n int) {
			defer wg.Done()
			_, _, err := r.AnyRevoked(revocation.P(revocation.ClassIssuer, "x"))
			if err != nil {
				t.Errorf("check %d: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
	recs, err := r.Revocations()
	if err != nil || len(recs) != 32 {
		t.Fatalf("expected 32 revocations, got %d (err=%v)", len(recs), err)
	}
	ep, _ := r.Epoch()
	if ep != 32 {
		t.Fatalf("epoch must equal record count: %d", ep)
	}
}

// Cross-process visibility: a revocation written by a second handle on
// the same file (the gwctl path) must be observed by the first.
func TestRevoke_CrossProcessVisible(t *testing.T) {
	r1, path := openRevReg(t)

	r2, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer r2.Close()

	if _, err := r2.Revoke("issuer", "iss-ext", "gwctl", "cross-process"); err != nil {
		t.Fatalf("cross-process revoke: %v", err)
	}
	// r1 must see r2's committed record after absorb.
	_, rev, err := r1.AnyRevoked(revocation.P(revocation.ClassIssuer, "iss-ext"))
	if err != nil || !rev {
		t.Fatalf("cross-process revocation not observed: rev=%v err=%v", rev, err)
	}
}
