package idregistry

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/internal/record"
)

// bugState reproduces what builds before the mutate fix left on disk: the
// ledger floor holds the first seal of file_seq 1, the file holds a second,
// different seal of file_seq 1.
func bugState(t *testing.T, signer *record.Signer) (string, record.Floor) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id.json")
	first, err := record.SealFile("idregistry", signer, []byte(`{"identities":[],"credentials":[]}`), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	floor := record.Floor{Known: true, Seq: 1, Hash: record.TipHash(first)}
	second, err := record.SealFile("idregistry", signer, []byte(`{"identities":[{"id":"op:x","role":"operator","status":"active","generation":1}],"credentials":[]}`), first, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, second, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, floor
}

func TestOpenRepair_RepairsTheOldSameSeqState(t *testing.T) {
	signer, resolve := advSigner(t)
	p, floor := bugState(t, signer)
	b := &record.Binding{Signer: signer, Resolve: resolve, Floor: floor}

	if _, err := Open(p, b); !errors.Is(err, record.ErrSameSeqEquivocation) {
		t.Fatalf("plain Open must still refuse, got %v", err)
	}
	reg, err := OpenRepair(p, b)
	if err != nil {
		t.Fatalf("repair refused: %v", err)
	}
	if !reg.Repaired() {
		t.Fatal("Repaired() = false")
	}
	var got record.Floor
	reg.SetTipsSink(func(seq uint64, hash string) error {
		if seq <= floor.Seq {
			return errors.New("tip does not advance")
		}
		got = record.Floor{Known: true, Seq: seq, Hash: hash}
		return nil
	})
	if err := reg.Reseal(); err != nil {
		t.Fatal(err)
	}
	if got.Seq != 2 || reg.Repaired() {
		t.Fatalf("after Reseal: floor %+v repaired=%v", got, reg.Repaired())
	}
	reg2, err := Open(p, &record.Binding{Signer: signer, Resolve: resolve, Floor: got})
	if err != nil {
		t.Fatalf("normal open after repair: %v", err)
	}
	if _, ok := reg2.ids["op:x"]; !ok {
		t.Fatal("repair lost the file's contents")
	}
}

func TestOpenRepair_RefusesAnotherKey(t *testing.T) {
	signer, resolve := advSigner(t)
	p, floor := bugState(t, signer)
	// a second key the resolver also trusts, but not this gateway's own
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	other := record.NewSigner(priv2, "dom-test", "gw2", "k2")
	resolve2 := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw == "gw2" {
			return pub2, nil
		}
		return resolve(gw, kid)
	}
	b := &record.Binding{Signer: other, Resolve: resolve2, Floor: floor}
	if _, err := OpenRepair(p, b); err == nil {
		t.Fatal("repaired a file signed by a different key")
	}
}

func TestOpenRepair_StillRefusesRollbackAndLeavesHealthyFilesAlone(t *testing.T) {
	signer, resolve := advSigner(t)
	p, floor := bugState(t, signer)
	ahead := record.Floor{Known: true, Seq: floor.Seq + 1, Hash: "x"}
	if _, err := OpenRepair(p, &record.Binding{Signer: signer, Resolve: resolve, Floor: ahead}); err == nil {
		t.Fatal("repaired a file below the ledger floor (rollback)")
	}

	q := filepath.Join(t.TempDir(), "id.json")
	reg, err := Open(q, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	var f record.Floor
	reg.SetTipsSink(func(seq uint64, hash string) error { f = record.Floor{Known: true, Seq: seq, Hash: hash}; return nil })
	if err := reg.SeedConfig([]string{"tok-0123456789abcdef"}, "operator"); err != nil {
		t.Fatal(err)
	}
	r2, err := OpenRepair(q, &record.Binding{Signer: signer, Resolve: resolve, Floor: f})
	if err != nil || r2.Repaired() {
		t.Fatalf("healthy file: err=%v repaired=%v", err, r2 != nil && r2.Repaired())
	}
}
