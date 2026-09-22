package events

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

// The events journal is evidence, not authority — but it still fails
// closed on unsigned legacy data and preserves appended events across
// reopen in signed mode.
func TestAdv21_EventsSigned(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "events.jsonl")
	os.WriteFile(p, []byte(`{"event_id":"evt_1","type":"decision"}`+"\n"), 0o600)
	if _, err := NewFileBackedStore(p, 0, &record.Binding{Signer: signer, Resolve: resolve}); err == nil {
		t.Fatal("unsigned events journal opened in signed mode")
	}
	os.Remove(p)

	fs, err := NewFileBackedStore(p, 0, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	fs.Append(NewEvent("decision").WithGatewayID("gw1"))
	if fs.LastError() != nil {
		t.Fatalf("signed append failed: %v", fs.LastError())
	}
	fs.Close()

	fs2, err := NewFileBackedStore(p, 0, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(fs2.List(0)); n != 1 {
		t.Fatalf("expected 1 event after reopen, got %d", n)
	}
	fs2.Close()
}
