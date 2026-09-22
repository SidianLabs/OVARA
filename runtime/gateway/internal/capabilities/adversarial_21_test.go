package capabilities

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// Sealed capability grants: unsigned file refuses; sealed round-trip
// works; floor-ahead refuses.
func TestAdv21_CapabilitiesSealed(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "caps.json")

	os.WriteFile(p, []byte(`{"cap_1":{"capability_id":"cap_1"}}`), 0o600)
	b := &record.Binding{Signer: signer, Resolve: resolve}
	if _, err := NewFileBackedStore(p, 0, time.Hour, b); err == nil {
		t.Fatal("unsigned capabilities file opened in sealed mode")
	}
	os.Remove(p)

	fs, err := NewFileBackedStore(p, 0, time.Hour, b)
	if err != nil {
		t.Fatal(err)
	}
	seq, hash := fs.JournalTip()
	

	if _, err := NewFileBackedStore(p, 0, time.Hour, b); err != nil {
		t.Fatalf("sealed reopen: %v", err)
	}

	bF := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq + 1, Hash: hash}}
	if _, err := NewFileBackedStore(p, 0, time.Hour, bF); err == nil {
		t.Fatal("capabilities file below ledger floor accepted")
	}
}
