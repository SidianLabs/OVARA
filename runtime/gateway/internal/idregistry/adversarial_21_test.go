package idregistry

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/internal/record"
)

func advSigner(t *testing.T) (*record.Signer, record.ResolveFunc) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := record.NewSigner(priv, "dom-test", "gw1", "k1")
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw == "gw1" && kid == "k1" {
			return pub, nil
		}
		return nil, errors.New("no key")
	}
	return signer, resolve
}

// Sealed identity registry: unsigned file refuses when bound; a sealed
// file opened in another domain refuses; truncate-below-floor refuses.
func TestAdv21_RegistrySealed(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "id.json")

	// unsigned whole-file JSON → refuse
	os.WriteFile(p, []byte(`{"agents":{}}`), 0o600)
	b := &record.Binding{Signer: signer, Resolve: resolve}
	if _, err := Open(p, b); err == nil {
		t.Fatal("unsigned identity registry opened in sealed mode")
	}
	os.Remove(p)

	reg, err := Open(p, b)
	if err != nil {
		t.Fatal(err)
	}
	// persist path → sealed write
	if err := reg.persist(); err != nil {
		t.Fatalf("sealed persist: %v", err)
	}
	seq, hash := reg.JournalTip()

	reg2, err := Open(p, b)
	if err != nil {
		t.Fatalf("sealed reopen: %v", err)
	}
	_ = reg2

	// foreign-domain sealed file refuses
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	_ = pub2
	evil := record.NewSigner(priv2, "dom-evil", "gw9", "k9")
	pE := filepath.Join(t.TempDir(), "id.json")
	regE, err := Open(pE, &record.Binding{Signer: evil, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	regE.persist()
	if _, err := Open(pE, b); err == nil {
		t.Fatal("foreign-domain sealed registry accepted")
	}

	// floor above file seq refuses
	bF := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq + 1, Hash: hash}}
	if _, err := Open(p, bF); err == nil {
		t.Fatal("registry below ledger floor accepted")
	}
}

// Every mutation must advance file_seq. If the parent registry keeps a
// stale seq, the next persist rewrites the same file_seq under a new
// hash; the tip ledger has already pinned the first commit, so the next
// Open fails closed on equivocation (observed: an ovara-init'd
// deployment refused to boot on its second start).
func TestAdv21_SeqAdvancesAcrossMutations(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "id.json")
	b := &record.Binding{Signer: signer, Resolve: resolve}

	reg, err := Open(p, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.SeedConfig([]string{"tok-op"}, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := reg.SeedConfig([]string{"tok-a"}, "agent"); err != nil {
		t.Fatal(err)
	}
	seq, _ := reg.JournalTip()
	if seq != 2 {
		t.Fatalf("two mutations committed file_seq=%d, want 2", seq)
	}
	// Reopen with the floor pinned at the committed tip — the second
	// boot path.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b2 := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq, Hash: record.TipHash(data)}}
	if _, err := Open(p, b2); err != nil {
		t.Fatalf("reopen at committed floor: %v", err)
	}
}
