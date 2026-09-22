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
