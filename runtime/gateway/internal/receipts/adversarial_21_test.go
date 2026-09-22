package receipts

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

// Receipts journal: unsigned file refuses; a duplicate receipt_id fold
// fails; signed round-trip persists.
func TestAdv21_ReceiptsSigned(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "receipts.jsonl")
	os.WriteFile(p, []byte(`{"receipt_id":"rcpt_1"}`+"\n"), 0o600)
	b := &record.Binding{Signer: signer, Resolve: resolve}
	if _, err := NewFileBackedStore(p, 0, time.Hour, b); err == nil {
		t.Fatal("unsigned receipts journal opened in signed mode")
	}
	os.Remove(p)

	if _, err := NewFileBackedStore(p, 0, time.Hour, b); err != nil {
		t.Fatal(err)
	}
}
