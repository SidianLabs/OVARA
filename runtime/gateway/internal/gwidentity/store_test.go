package gwidentity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func genPub(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func mustOpen(t *testing.T, path string) *Registry {
	t.Helper()
	r, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestRegister_FirstBinding(t *testing.T) {
	r := NewInMemory()
	_, pub := genPub(t)
	rec, err := r.Register("gw_a", pub)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != KeyActive || rec.KeyID == "" || rec.Generation != 1 {
		t.Fatalf("bad record %+v", rec)
	}
}

func TestRegister_IdempotentRejoin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	_, pub := genPub(t)
	r1 := mustOpen(t, p)
	rec1, err := r1.Register("gw_a", pub)
	if err != nil {
		t.Fatal(err)
	}
	r1.Close()
	// Restart: same key → same record, no new generation.
	r2 := mustOpen(t, p)
	rec2, err := r2.Register("gw_a", pub)
	if err != nil {
		t.Fatalf("rejoin must be idempotent: %v", err)
	}
	if rec2.KeyID != rec1.KeyID {
		t.Fatalf("rejoin changed key %s → %s", rec1.KeyID, rec2.KeyID)
	}
}

func TestRegister_DuplicateIDDifferentKey_Conflict(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	if _, err := r.Register("gw_x", pubA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("gw_x", pubB); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	// Inverse order on a fresh registry: B first, then A → same result.
	r2 := NewInMemory()
	if _, err := r2.Register("gw_x", pubB); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Register("gw_x", pubA); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("reverse-order conflict expected, got %v", err)
	}
}

func TestRegister_ConflictEvenWhenOldKeyRevoked(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	rec, _ := r.Register("gw_x", pubA)
	if err := r.RevokeKey("gw_x", rec.KeyID); err != nil {
		t.Fatal(err)
	}
	// Dead-key resurrection attempt via plain register → still conflict.
	// The recovery path is Rotate, never re-register.
	if _, err := r.Register("gw_x", pubB); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("expected conflict over revoked key, got %v", err)
	}
}

func TestRegister_ConcurrentSameIDDifferentKeys_OneWinner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	r1 := mustOpen(t, p)
	r2 := mustOpen(t, p)
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	var wg sync.WaitGroup
	res := make([]error, 2)
	for i, pair := range []struct {
		r   *Registry
		pub ed25519.PublicKey
	}{{r1, pubA}, {r2, pubB}} {
		wg.Add(1)
		go func(i int, r *Registry, pub ed25519.PublicKey) {
			defer wg.Done()
			_, err := r.Register("gw_race", pub)
			res[i] = err
		}(i, pair.r, pair.pub)
	}
	wg.Wait()
	wins, conflicts := 0, 0
	for _, err := range res {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrGatewayConflict) {
			conflicts++
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("race must produce exactly one winner: %v", res)
	}
}

func TestRegister_ConcurrentSameKey_BothWin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	r1 := mustOpen(t, p)
	r2 := mustOpen(t, p)
	_, pub := genPub(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, r := range []*Registry{r1, r2} {
		wg.Add(1)
		go func(i int, r *Registry) {
			defer wg.Done()
			_, err := r.Register("gw_same", pub)
			errs[i] = err
		}(i, r)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("idempotent same-key registration must succeed: %v", err)
		}
	}
}

func TestOpen_CorruptMidFile_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	_, pub := genPub(t)
	r := mustOpen(t, p)
	if _, err := r.Register("gw_a", pub); err != nil {
		t.Fatal(err)
	}
	r.Close()
	// Corrupt a non-final line, then append a valid line.
	data, _ := os.ReadFile(p)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines < 1 {
		t.Fatal("expected at least one record")
	}
	bad := append([]byte("{not json}\n"), data...)
	if err := os.WriteFile(p, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("corrupt non-tail record must fail closed")
	}
}

func TestOpen_TornTail_Truncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	_, pub := genPub(t)
	r := mustOpen(t, p)
	rec, _ := r.Register("gw_a", pub)
	r.Close()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"gateway_id":"gw_a","key_id":"PARTIAL`)
	f.Close()
	r2 := mustOpen(t, p)
	recs, err := r2.Lookup("gw_a")
	if err != nil || len(recs) != 1 || recs[0].KeyID != rec.KeyID {
		t.Fatalf("torn tail must truncate, keep committed records: %v %v", recs, err)
	}
}

func TestOpen_UnwritablePath_Fails(t *testing.T) {
	if _, err := Open("/proc/definitely-not-writable/gwreg.jsonl"); err == nil {
		t.Fatal("unopenable registry must fail")
	}
}

func TestRotate_NewKeyID_OldEntersGrace(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	recA, _ := r.Register("gw_a", pubA)
	recB, err := r.Rotate("gw_a", pubB, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if recB.KeyID == recA.KeyID {
		t.Fatal("rotation must assign a new key_id")
	}
	recs, _ := r.Lookup("gw_a")
	var old, new_ *KeyRecord
	for _, k := range recs {
		if k.KeyID == recA.KeyID {
			old = k
		}
		if k.KeyID == recB.KeyID {
			new_ = k
		}
	}
	if old.State != KeyRotating || old.RotatingUntil.IsZero() {
		t.Fatalf("old key must be rotating-with-grace: %+v", old)
	}
	if new_.State != KeyActive || new_.Generation != old.Generation+1 {
		t.Fatalf("new key must be active, bumped generation: %+v", new_)
	}
}

func TestRotate_HardCut_ZeroGrace(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	recA, _ := r.Register("gw_a", pubA)
	if _, err := r.Rotate("gw_a", pubB, 0); err != nil {
		t.Fatal(err)
	}
	// Zero grace → rotating-until = now → effective superseded at read.
	recs, _ := r.Lookup("gw_a")
	for _, k := range recs {
		if k.KeyID == recA.KeyID && effective(k, time.Now()) != KeySuperseded {
			t.Fatalf("zero-grace rotation must supersede old key: %+v", k)
		}
	}
}

func TestRotate_UnknownAndDestroyedRefused(t *testing.T) {
	r := NewInMemory()
	_, pub := genPub(t)
	_, pub2 := genPub(t)
	if _, err := r.Rotate("gw_none", pub, time.Hour); !errors.Is(err, ErrUnknownGateway) {
		t.Fatalf("rotate unknown → %v", err)
	}
	r.Register("gw_d", pub)
	if err := r.Destroy("gw_d"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate("gw_d", pub2, time.Hour); !errors.Is(err, ErrGatewayDestroyed) {
		t.Fatalf("rotate destroyed → %v", err)
	}
}

func TestRevokeKey_AndDestroy(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	recA, _ := r.Register("gw_a", pubA)
	r.Rotate("gw_a", pubB, time.Hour)
	if err := r.RevokeKey("gw_a", recA.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeKey("gw_a", "gwk_nonexistent"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revoke unknown → %v", err)
	}
	if err := r.Destroy("gw_a"); err != nil {
		t.Fatal(err)
	}
	recs, _ := r.Lookup("gw_a")
	for _, k := range recs {
		if k.State != KeyDestroyed && k.State != KeyRevoked {
			t.Fatalf("destroy must tombstone every key: %+v", k)
		}
	}
	if r.HasUsableKey("gw_a") {
		t.Fatal("destroyed gateway must have no usable key")
	}
	if _, err := r.Register("gw_a", pubA); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("register on destroyed → %v", err)
	}
}

func TestHasUsableKey(t *testing.T) {
	r := NewInMemory()
	_, pub := genPub(t)
	if r.HasUsableKey("gw_a") {
		t.Fatal("unknown gateway has no usable key")
	}
	rec, _ := r.Register("gw_a", pub)
	if !r.HasUsableKey("gw_a") {
		t.Fatal("active key must be usable")
	}
	if err := r.RevokeKey("gw_a", rec.KeyID); err != nil {
		t.Fatal(err)
	}
	if r.HasUsableKey("gw_a") {
		t.Fatal("last-usable-key revocation must leave none usable")
	}
}

func TestPersistence_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	r := mustOpen(t, p)
	recA, _ := r.Register("gw_a", pubA)
	recB, err := r.Rotate("gw_a", pubB, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r.RevokeKey("gw_a", recA.KeyID)
	r.Close()
	r2 := mustOpen(t, p)
	recs, err := r2.Lookup("gw_a")
	if err != nil || len(recs) != 2 {
		t.Fatalf("reopen must see both key records: %v %v", recs, err)
	}
	states := map[string]KeyState{}
	for _, k := range recs {
		states[k.KeyID] = k.State
	}
	if states[recA.KeyID] != KeyRevoked || states[recB.KeyID] != KeyActive {
		t.Fatalf("persisted states wrong: %v", states)
	}
}

func TestHistory_PreservedAcrossRotation(t *testing.T) {
	r := NewInMemory()
	_, pubA := genPub(t)
	_, pubB := genPub(t)
	_, pubC := genPub(t)
	r.Register("gw_a", pubA)
	r.Rotate("gw_a", pubB, time.Hour)
	r.Rotate("gw_a", pubC, time.Hour)
	recs, _ := r.Lookup("gw_a")
	if len(recs) != 3 {
		t.Fatalf("key history must be preserved: %d records", len(recs))
	}
}

func TestConcurrentMixedOps_NoCorruption(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gwreg.jsonl")
	r1 := mustOpen(t, p)
	r2 := mustOpen(t, p)
	priv, pub := genPub(t)
	_ = priv
	if _, err := r1.Register("gw_m", pub); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := r1
			if i%2 == 0 {
				rr = r2
			}
			rr.Lookup("gw_m")
			_, npub := genPub(t)
			rr.Rotate("gw_m", npub, time.Hour)
		}(i)
	}
	wg.Wait()
	// Every committed line must parse — concurrent flock+append must
	// never interleave a partial record.
	f, _ := os.Open(p)
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec KeyRecord
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("corrupt journal after concurrent ops: %v", err)
		}
	}
	recs, err := r1.Lookup("gw_m")
	if err != nil || len(recs) < 2 {
		t.Fatalf("expected rotated key history: %v %v", recs, err)
	}
}

func TestRecordStateTransitions_Deterministic(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	cases := []struct {
		rec  KeyRecord
		want KeyState
	}{
		{KeyRecord{State: KeyActive}, KeyActive},
		{KeyRecord{State: KeyRotating, RotatingUntil: future}, KeyRotating},
		{KeyRecord{State: KeyRotating, RotatingUntil: past}, KeySuperseded},
		{KeyRecord{State: KeySuperseded}, KeySuperseded},
		{KeyRecord{State: KeyRevoked}, KeyRevoked},
		{KeyRecord{State: KeyDestroyed}, KeyDestroyed},
	}
	for i, c := range cases {
		if got := effective(&c.rec, now); got != c.want {
			t.Fatalf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestRegister_BadPubKeyLength(t *testing.T) {
	r := NewInMemory()
	if _, err := r.Register("gw_a", ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("short pubkey must fail")
	}
}

func TestPublicKeyRoundTrip_Hex(t *testing.T) {
	_, pub := genPub(t)
	h := hex.EncodeToString(pub)
	if len(h) != 64 {
		t.Fatalf("hex pubkey must be 64 chars: %d", len(h))
	}
}
