package anchor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// Deterministic test key — fixed seed so vectors are stable.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

func testCP() Checkpoint {
	return Checkpoint{
		Version:  "v1",
		DomainID: "dom_abc123",
		Seq:      42,
		TipHash:  hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)),
		KeyID:    "gwk_test1",
	}
}

// TestCanonicalPreimage pins the exact signing bytes — independent
// reconstruction via literal byte ops (not lp()), the cross-language
// contract: any implementation producing different bytes is wrong.
func TestCanonicalPreimage(t *testing.T) {
	cp := testCP()
	got, err := cp.Preimage()
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		want = append(want, l[:]...)
		want = append(want, b...)
	}
	put([]byte("OVARA-ANCHOR-CP-V1"))
	put([]byte("dom_abc123"))
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], 42)
	put(sb[:])
	put(bytes.Repeat([]byte{0xAB}, 32))
	put([]byte("gwk_test1"))
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical preimage mismatch:\n got %x\nwant %x", got, want)
	}
	// Fixed vector: the preimage must be byte-identical forever.
	goldenPreimage := "00000012" + hexStr("OVARA-ANCHOR-CP-V1") +
		"0000000a" + hexStr("dom_abc123") +
		"00000008" + "000000000000002a" +
		"00000020" + strings.Repeat("ab", 32) +
		"00000009" + hexStr("gwk_test1")
	if hex.EncodeToString(got) != goldenPreimage {
		t.Fatalf("golden preimage drifted:\n got %s\nwant %s", hex.EncodeToString(got), goldenPreimage)
	}
}

func hexStr(s string) string { return hex.EncodeToString([]byte(s)) }

// TestSignVerify round-trips and pins a golden signature — Ed25519 is
// deterministic, so the same preimage+key MUST always produce this sig.
func TestSignVerify(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	signed, err := Sign(priv, testCP())
	if err != nil {
		t.Fatal(err)
	}
	const goldenSig = "d3ea920bbe308d6e6d88bb3d2daeb030713f5a1f23a03901d0d0fb29053291e4be8b15d7203ecc53322c4feed8b697a12833fecb22edc34272427bb74f24e40b"
	if signed.Sig != goldenSig {
		// Ed25519 is deterministic over the canonical preimage — a
		// drift here means the canonicalization changed and every
		// deployed checkpoint invalidates. Hard fail.
		t.Fatalf("golden signature drifted: %s — canonicalization changed", signed.Sig)
	}
	if err := signed.Verify(pub); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
}

// Each mutation must invalidate the signature — field-binding tests.
func TestTamperedFields(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	base, err := Sign(priv, testCP())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Checkpoint){
		"domain":   func(c *Checkpoint) { c.DomainID = "dom_evil" },
		"seq+1":    func(c *Checkpoint) { c.Seq++ },
		"seq-1":    func(c *Checkpoint) { c.Seq-- },
		"tip_hash": func(c *Checkpoint) { c.TipHash = hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 32)) },
		"key_id":   func(c *Checkpoint) { c.KeyID = "gwk_other" },
		"version":  func(c *Checkpoint) { c.Version = "v2" },
		"sig":      func(c *Checkpoint) { c.Sig = hex.EncodeToString(bytes.Repeat([]byte{0}, 64)) },
	}
	for name, mut := range cases {
		cp := base
		mut(&cp)
		if err := cp.Verify(pub); err == nil {
			t.Fatalf("tampered %s checkpoint verified", name)
		}
	}
}

// Malformed encodings must not verify.
func TestMalformedCheckpoints(t *testing.T) {
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	bad := []Checkpoint{
		{Version: "v1", DomainID: "d", Seq: 1, TipHash: "zz", KeyID: "k", Sig: hex.EncodeToString(make([]byte, 64))},
		{Version: "v1", DomainID: "d", Seq: 1, TipHash: hex.EncodeToString(make([]byte, 31)), KeyID: "k", Sig: hex.EncodeToString(make([]byte, 64))},
		{Version: "", DomainID: "d", Seq: 1, TipHash: hex.EncodeToString(make([]byte, 32)), KeyID: "k", Sig: hex.EncodeToString(make([]byte, 64))},
		{Version: "v1", DomainID: "d", Seq: 1, TipHash: hex.EncodeToString(make([]byte, 32)), KeyID: "k", Sig: "abcd"},
	}
	for i, cp := range bad {
		if err := cp.Verify(pub); err == nil {
			t.Fatalf("malformed checkpoint %d verified", i)
		}
	}
}

// Wrong key must not verify (domain substitution across signers).
func TestWrongKey(t *testing.T) {
	priv := testKey(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signed, _ := Sign(priv, testCP())
	if err := signed.Verify(other.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("checkpoint verified under wrong key")
	}
}

// Same() — idempotent-commit equality is over authority state, not sig.
func TestSame(t *testing.T) {
	priv := testKey(t)
	a, _ := Sign(priv, testCP())
	b, _ := Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)), testCP())
	if !a.Same(&b) {
		t.Fatal("identical state, different sig must be Same()")
	}
	c := a
	c.Seq++
	if a.Same(&c) {
		t.Fatal("different seq must not be Same()")
	}
}
