package anchor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anchor.jsonl")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, domain string, seq uint64, tipByte byte, keyID string) *Checkpoint {
	t.Helper()
	cp := Checkpoint{Version: "v1", DomainID: domain, Seq: seq,
		TipHash: hex.EncodeToString(bytes.Repeat([]byte{tipByte}, 32)), KeyID: keyID}
	s, err := Sign(priv, cp)
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func register(t *testing.T, s *Store, priv ed25519.PrivateKey, domain string, seq uint64, tipByte byte) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	if err := s.Register(domain, mustSign(t, priv, domain, seq, tipByte, "genesis"), pub, "genesis"); err != nil {
		t.Fatalf("register %s: %v", domain, err)
	}
}

func TestRegisterCommitLatest(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	if _, err := s.Latest("dom_x"); !errors.Is(err, ErrDomainUnregistered) {
		t.Fatalf("unregistered domain must fail: %v", err)
	}
	register(t, s, priv, "dom_x", 1, 0x11)
	cp, err := s.Latest("dom_x")
	if err != nil || cp.Seq != 1 {
		t.Fatalf("latest: %v %v", cp, err)
	}
	// seq=2 advances.
	if err := s.Commit("dom_x", mustSign(t, priv, "dom_x", 2, 0x22, "genesis")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	cp, _ = s.Latest("dom_x")
	if cp.Seq != 2 || cp.TipHash != hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatalf("latest after commit: %+v", cp)
	}
}

func TestCommitSemantics(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	register(t, s, priv, "d", 5, 0x50)

	// lower seq → regression
	if err := s.Commit("d", mustSign(t, priv, "d", 4, 0x40, "g")); !errors.Is(err, ErrRegression) {
		t.Fatalf("seq<stored: %v", err)
	}
	// same seq + same state → idempotent
	if err := s.Commit("d", mustSign(t, priv, "d", 5, 0x50, "genesis")); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	// same seq + different tip → equivocation
	if err := s.Commit("d", mustSign(t, priv, "d", 5, 0xFF, "genesis")); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation: %v", err)
	}
	// same seq + different key_id → also equivocation (different state)
	if err := s.Commit("d", mustSign(t, priv, "d", 5, 0x50, "other_key")); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation by key_id: %v", err)
	}
	// unregistered domain → never implicitly created
	if err := s.Commit("dom_ghost", mustSign(t, priv, "dom_ghost", 1, 0x01, "g")); !errors.Is(err, ErrDomainUnregistered) {
		t.Fatalf("implicit domain creation: %v", err)
	}
	// domain mismatch between path and checkpoint
	if err := s.Commit("d", mustSign(t, priv, "other", 9, 0x09, "g")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("domain mismatch: %v", err)
	}
}

func TestDomainIsolation(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	register(t, s, priv, "dom_a", 3, 0xAA)
	register(t, s, priv, "dom_b", 7, 0xBB)
	// A's checkpoint replayed to B: domain binding is in the preimage,
	// so the signature itself rejects it before seq is even compared.
	if err := s.Commit("dom_b", mustSign(t, priv, "dom_a", 8, 0x88, "g")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("cross-domain commit: %v", err)
	}
	a, _ := s.Latest("dom_a")
	b, _ := s.Latest("dom_b")
	if a.Seq != 3 || b.Seq != 7 {
		t.Fatalf("domain isolation broken: a=%v b=%v", a, b)
	}
}

func TestUnsignedAndForeignKeyRejected(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	register(t, s, priv, "d", 1, 0x01)
	// Foreign key signs a higher-seq checkpoint — not in lineage.
	rogue := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	if err := s.Commit("d", mustSign(t, rogue, "d", 2, 0x02, "rogue")); !errors.Is(err, ErrBadKey) {
		t.Fatalf("foreign-key commit: %v", err)
	}
	// Garbage signature.
	cp := mustSign(t, priv, "d", 2, 0x02, "g")
	cp.Sig = hex.EncodeToString(bytes.Repeat([]byte{0}, 64))
	if err := s.Commit("d", cp); !errors.Is(err, ErrBadKey) {
		t.Fatalf("bad-sig commit: %v", err)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	priv := testKey(t)
	s, path := openTemp(t)
	register(t, s, priv, "d", 4, 0x44)
	s.Commit("d", mustSign(t, priv, "d", 6, 0x66, "g"))
	s.Close()
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	cp, err := s2.Latest("d")
	if err != nil || cp.Seq != 6 {
		t.Fatalf("restart lost state: %v %v", cp, err)
	}
	// Regression must still fail after reload.
	if err := s2.Commit("d", mustSign(t, priv, "d", 5, 0x55, "g")); !errors.Is(err, ErrRegression) {
		t.Fatalf("post-restart regression: %v", err)
	}
}

func TestTornTailAbsorbed(t *testing.T) {
	priv := testKey(t)
	s, path := openTemp(t)
	register(t, s, priv, "d", 2, 0x22)
	s.Close()
	// Simulate crash mid-write: garbage at tail.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"kind":"commit","domain_id":"d","checkpoint":{"seq":`)
	f.Close()
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("torn tail must recover: %v", err)
	}
	defer s2.Close()
	cp, _ := s2.Latest("d")
	if cp.Seq != 2 {
		t.Fatalf("torn tail rolled back committed state: %v", cp)
	}
}

func TestCorruptMidFileFails(t *testing.T) {
	priv := testKey(t)
	s, path := openTemp(t)
	register(t, s, priv, "d", 2, 0x22)
	s.Commit("d", mustSign(t, priv, "d", 3, 0x33, "g"))
	s.Close()
	// Inject an unparseable record in the middle — deterministic
	// corruption: not at the tail, so it must fail the load.
	data, _ := os.ReadFile(path)
	mid := bytes.IndexByte(data[len(data)/2:], '\n') + len(data)/2
	corrupt := append(append([]byte{}, data[:mid+1]...), []byte("GARBAGE-LINE\n")...)
	corrupt = append(corrupt, data[mid+1:]...)
	os.WriteFile(path, corrupt, 0600)
	if _, err := OpenStore(path); err == nil {
		t.Fatal("corrupt mid-file record must fail closed")
	}
}

func TestDuplicateRegisterFails(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	register(t, s, priv, "d", 1, 0x01)
	pub := priv.Public().(ed25519.PublicKey)
	if err := s.Register("d", mustSign(t, priv, "d", 9, 0x99, "x"), pub, "x"); !errors.Is(err, ErrDomainRegistered) {
		t.Fatalf("re-registration must fail: %v", err)
	}
}

func TestResetRequiresReinit(t *testing.T) {
	priv := testKey(t)
	s, path := openTemp(t)
	register(t, s, priv, "d", 1, 0x01)
	if err := s.Reset("d"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Latest("d"); !errors.Is(err, ErrDomainUnregistered) {
		t.Fatal("reset must unregister")
	}
	s.Close()
	s2, _ := OpenStore(path)
	defer s2.Close()
	if _, err := s2.Latest("d"); !errors.Is(err, ErrDomainUnregistered) {
		t.Fatal("reset must persist across restart")
	}
}

func TestBackupRestoreIsAuthorityRecovery(t *testing.T) {
	priv := testKey(t)
	s, path := openTemp(t)
	register(t, s, priv, "d", 1, 0x01)
	// Snapshot "backup" then advance, then restore the old copy —
	// the store's durable content is whatever the file holds; restoring
	// an older file is an OPERATOR recovery event. The store must not
	// silently re-init, and the folded state is exactly the backup's.
	backup, _ := os.ReadFile(path)
	s.Commit("d", mustSign(t, priv, "d", 5, 0x55, "g"))
	s.Close()
	os.WriteFile(path, backup, 0600)
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	cp, _ := s2.Latest("d")
	if cp.Seq != 1 {
		t.Fatalf("restored backup should show seq 1, got %v", cp)
	}
	// seq 5 commits again — the oracle accepts (it never saw 5). This
	// IS the documented co-rollback residual: an old oracle backup
	// lowers the anchored ceiling. Detection requires the GATEWAY to
	// refuse (local seq > oracle seq → LocalAhead → operator recovery).
	if err := s2.Commit("d", mustSign(t, priv, "d", 5, 0x55, "g")); err != nil {
		t.Fatalf("re-commit after backup restore: %v", err)
	}
}

func TestAddKeyRotationLineage(t *testing.T) {
	priv := testKey(t)
	s, _ := openTemp(t)
	register(t, s, priv, "d", 1, 0x01)
	newPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	newPub := newPriv.Public().(ed25519.PublicKey)
	intro := ed25519.Sign(priv, KeyIntroMessage("d", "gwk_new", newPub))
	if err := s.AddKey("d", newPub, "gwk_new", intro); err != nil {
		t.Fatalf("addkey: %v", err)
	}
	// New key's checkpoint now accepted.
	if err := s.Commit("d", mustSign(t, newPriv, "d", 2, 0x02, "gwk_new")); err != nil {
		t.Fatalf("post-rotation commit: %v", err)
	}
	// Rogue introduction (wrong introducer) fails.
	rogue := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	badIntro := ed25519.Sign(rogue, KeyIntroMessage("d", "x", rogue.Public().(ed25519.PublicKey)))
	if err := s.AddKey("d", rogue.Public().(ed25519.PublicKey), "x", badIntro); !errors.Is(err, ErrBadKey) {
		t.Fatalf("unauthorized introduction: %v", err)
	}
}

// ── F-A1: fold-time signature re-verification ───────────────────────
// The oracle store file is the trust root, but a file-write attacker
// must not be able to inject served state the lineage can't verify.

func TestFoldRejectsForgedCommit(t *testing.T) {
	priv := testKey(t)
	_, path := openTemp(t)
	s, _ := OpenStore(path)
	register(t, s, priv, "d", 1, 0x01)
	s.Close()
	// Inject a forward commit with a VALID seq but forged signature —
	// monotonicity alone would accept it; fold must not.
	forged := Checkpoint{Version: "v1", DomainID: "d", Seq: 9,
		TipHash: hex.EncodeToString(bytes.Repeat([]byte{0xee}, 32)),
		KeyID:   "injected", Sig: hex.EncodeToString(bytes.Repeat([]byte{0}, 64))}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	json.NewEncoder(f).Encode(map[string]any{"kind": "commit", "domain_id": "d", "checkpoint": forged})
	f.Close()
	if _, err := OpenStore(path); err == nil {
		t.Fatal("forged commit record must fail fold — signature not lineage-verifiable")
	}
}

func TestFoldRejectsForgedRegister(t *testing.T) {
	_, path := openTemp(t)
	bad := Checkpoint{Version: "v1", DomainID: "d", Seq: 1,
		TipHash: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		KeyID:   "x", Sig: hex.EncodeToString(bytes.Repeat([]byte{0}, 64))}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	json.NewEncoder(f).Encode(map[string]any{"kind": "register", "domain_id": "d",
		"checkpoint": bad, "pubkey": hex.EncodeToString(bytes.Repeat([]byte{7}, 32)), "key_id": "x"})
	f.Close()
	if _, err := OpenStore(path); err == nil {
		t.Fatal("register record with unverifiable genesis sig must fail fold")
	}
}

func TestFoldRejectsForgedKeyRecord(t *testing.T) {
	priv := testKey(t)
	_, path := openTemp(t)
	s, _ := OpenStore(path)
	register(t, s, priv, "d", 1, 0x01)
	s.Close()
	// Key record claiming introduction but with garbage introducer_sig.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	json.NewEncoder(f).Encode(map[string]any{"kind": "key", "domain_id": "d",
		"pubkey": hex.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		"key_id": "injected", "introducer_sig": hex.EncodeToString(bytes.Repeat([]byte{0}, 64))})
	f.Close()
	if _, err := OpenStore(path); err == nil {
		t.Fatal("key record without valid lineage introduction must fail fold")
	}
}
