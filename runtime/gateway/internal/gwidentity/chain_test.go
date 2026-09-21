package gwidentity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/anchor"
)

func openRegTemp(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gwreg.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestChainAdvancesPerRecord(t *testing.T) {
	r, _ := openRegTemp(t)
	pub, _ := key(t)
	if _, err := r.Authorize("gw_a", pub, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Admit("gw_a", pub, false); err != nil {
		t.Fatal(err)
	}
	dom, seq, tip := r.ChainTip()
	if seq != 3 { // grant + consumed-transition + key record
		t.Fatalf("seq = %d, want 3", seq)
	}
	if dom == "" || !strings.HasPrefix(dom, "dom_") {
		t.Fatalf("domain id missing: %q", dom)
	}
	if tip == [32]byte{} {
		t.Fatal("zero tip")
	}
}

func TestChainConsistentAcrossReload(t *testing.T) {
	r, path := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)
	dom, seq, tip := r.ChainTip()
	r.Close()

	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	dom2, seq2, tip2 := r2.ChainTip()
	if seq2 != seq || tip2 != tip || dom2 != dom {
		t.Fatalf("chain drift across reload: (%s,%d,%x) vs (%s,%d,%x)", dom, seq, tip, dom2, seq2, tip2)
	}
}

func TestModifiedRecordBreaksChain(t *testing.T) {
	r, path := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)
	r.Close()
	// Flip a byte inside the first line's payload (after the first
	// field) — the record still parses, the chain must not.
	data, _ := os.ReadFile(path)
	i := strings.Index(string(data), "gw_a")
	data[i+3] = 'X'
	os.WriteFile(path, data, 0600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("modified record must fail chain verification: %v", err)
	}
}

func TestReorderedRecordsBreakChain(t *testing.T) {
	r, path := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)
	r.Close()
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("need ≥3 lines, got %d", len(lines))
	}
	// Swap lines 1 and 2 — embedded seq pinning must catch it even if
	// the raw-byte chain were somehow consistent.
	lines[0], lines[1] = lines[1], lines[0]
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
	if _, err := Open(path); err == nil {
		t.Fatal("reordered records must fail")
	}
}

func TestPrefixTruncateDetected(t *testing.T) {
	r, path := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)
	r.Close()
	// Truncate the last record (simulating a rolled-back tail) —
	// reopening gives a SMALLER seq; reconciliation then catches it
	// against the oracle (tested in TestReconcile*). Locally, a
	// truncated journal is still chain-valid — that's the design:
	// the oracle, not the chain, detects rollback.
	data, _ := os.ReadFile(path)
	last := strings.LastIndex(strings.TrimRight(string(data), "\n"), "\n")
	os.WriteFile(path, data[:last+1], 0600)
	r2, err := Open(path)
	if err != nil {
		t.Fatalf("prefix-truncated journal should still parse: %v", err)
	}
	defer r2.Close()
	_, seq2, _ := r2.ChainTip()
	if seq2 != 2 {
		t.Fatalf("truncated journal seq = %d, want 2", seq2)
	}
}

// fakeOracle is an in-memory anchor.Querier/Pusher for reconcile tests.
type fakeOracle struct {
	cp  *anchor.Checkpoint
	err error
}

func (f *fakeOracle) Latest(ctx context.Context, d string) (*anchor.Checkpoint, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.cp == nil {
			return nil, anchor.ErrDomainUnregistered
	}
	return f.cp, nil
}

func (f *fakeOracle) Commit(ctx context.Context, d string, cp *anchor.Checkpoint) error {
	f.cp = cp
	return nil
}

func TestReconcileTable(t *testing.T) {
	r, _ := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)
	dom, seq, tip := r.ChainTip()

	mk := func(s uint64, h [32]byte) *anchor.Checkpoint {
		return &anchor.Checkpoint{Version: "v1", DomainID: dom, Seq: s,
			TipHash: strings.Repeat("00", 32), KeyID: "k"}
	}
	oracleTip := mk(0, [32]byte{})
	oracleTip.TipHash = hexOf(tip)
	oracleTip.Seq = seq

	ctx := context.Background()
	// L == A, tip matches → OK
	res, _, err := r.ReconcileAnchor(ctx, &fakeOracle{cp: oracleTip})
	if err != nil || res != ReconcileOK {
		t.Fatalf("equal state: %v %v", res, err)
	}
	// L < A → local behind
	behind := mk(0, [32]byte{})
	behind.Seq = seq + 1
	res, _, err = r.ReconcileAnchor(ctx, &fakeOracle{cp: behind})
	if res != ReconcileLocalBehind || err != nil {
		t.Fatalf("local behind: %v %v", res, err)
	}
	// L == A, tip differs → equivocation
	diff := mk(0, [32]byte{})
	diff.Seq = seq
	diff.TipHash = strings.Repeat("ff", 32)
	res, _, err = r.ReconcileAnchor(ctx, &fakeOracle{cp: diff})
	if res != ReconcileEquivocation || err != nil {
		t.Fatalf("equivocation: %v %v", res, err)
	}
	// L > A → local ahead (unanchored tail)
	ahead := mk(0, [32]byte{})
	ahead.Seq = seq - 1
	res, _, err = r.ReconcileAnchor(ctx, &fakeOracle{cp: ahead})
	if res != ReconcileLocalAhead || err != nil {
		t.Fatalf("local ahead: %v %v", res, err)
	}
	// oracle unreachable → error, fail-closed input
	_, _, err = r.ReconcileAnchor(ctx, &fakeOracle{err: anchor.ErrUnavailable})
	if err == nil {
		t.Fatal("oracle error must propagate")
	}
	// unregistered domain → error
	_, _, err = r.ReconcileAnchor(ctx, &fakeOracle{})
	if !errors.Is(err, anchor.ErrDomainUnregistered) {
		t.Fatalf("unregistered: %v", err)
	}
}

func TestAnchorPushOnMutation(t *testing.T) {
	r, _ := openRegTemp(t)
	pub, priv := key(t)
	r.Authorize("gw_a", pub, 0)
	r.Admit("gw_a", pub, false)

	fo := &fakeOracle{}
	signer := func(seq uint64, tip [32]byte) (*anchor.Checkpoint, error) {
		dom, _, _ := r.ChainTip()
		cp := anchor.Checkpoint{Version: "v1", DomainID: dom, Seq: seq,
			TipHash: hexOf(tip), KeyID: "gwk_test"}
		s, err := anchor.Sign(priv, cp)
		return &s, err
	}
	if err := r.SetAnchor(fo, signer); err != nil {
		t.Fatal(err)
	}
	pub2, _ := key(t)
	if _, err := r.Rotate("gw_a", pub2, 0); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if fo.cp == nil {
		t.Fatal("mutation did not push checkpoint")
	}
	dom, seq, tip := r.ChainTip()
	if fo.cp.Seq != seq || fo.cp.TipHash != hexOf(tip) || fo.cp.DomainID != dom {
		t.Fatalf("pushed checkpoint mismatch: %+v", fo.cp)
	}
	// Push failure → mutation durable but error returned.
	fo2 := &failOracle{}
	r.SetAnchor(fo2, signer)
	pub3, _ := key(t)
	if _, err := r.Rotate("gw_a", pub3, 0); err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("push failure must surface: %v", err)
	}
	if !r.HasUsableKey("gw_a") {
		t.Fatal("failed push must not discard the durable mutation")
	}
}

type failOracle struct{ fakeOracle }

func (f *failOracle) Commit(ctx context.Context, d string, cp *anchor.Checkpoint) error {
	return anchor.ErrUnavailable
}

func hexOf(b [32]byte) string {
	const hexdig = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(hexdig[c>>4])
		sb.WriteByte(hexdig[c&0xf])
	}
	return sb.String()
}

func TestAnchorOnInMemoryRefused(t *testing.T) {
	r := NewInMemory()
	err := r.SetAnchor(&fakeOracle{}, func(uint64, [32]byte) (*anchor.Checkpoint, error) { return nil, nil })
	if err == nil {
		t.Fatal("in-memory registry must refuse anchoring")
	}
}

func TestMigrateMarker(t *testing.T) {
	r, _ := openRegTemp(t)
	pub, _ := key(t)
	r.Authorize("gw_a", pub, 0)
	if r.Migrated() != 0 {
		t.Fatal("no markers yet")
	}
	if err := r.AppendMarker(); err != nil {
		t.Fatal(err)
	}
	if r.Migrated() != 1 {
		t.Fatal("marker not counted")
	}
	// Marker is a chained record — chain moved.
	_, seq, _ := r.ChainTip()
	if seq != 2 {
		t.Fatalf("seq after marker = %d, want 2", seq)
	}
}
