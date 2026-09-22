package replay

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

// STORE: unsigned consume journal refuses when bound; signed consume
// claims once, blocks replay, and survives reopen.
func TestAdv21_ReplaySigned(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "replay.jsonl")

	// legacy unsigned file → refuse
	os.WriteFile(p, []byte(`{"k":"deleg","p":"pid-1","e":"2030-01-01T00:00:00Z"}`+"\n"), 0o600)
	if _, err := OpenFile(p, 0, &record.Binding{Signer: signer, Resolve: resolve}); err == nil {
		t.Fatal("unsigned replay journal opened in signed mode")
	}
	os.Remove(p)

	exp := time.Now().Add(time.Hour)
	fs, err := OpenFile(p, 0, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	if r := fs.Consume(KindDelegation, "pid-1", exp); r != FirstConsume {
		t.Fatalf("first signed consume = %v", r)
	}
	if r := fs.Consume(KindDelegation, "pid-1", exp); r != AlreadyConsumed {
		t.Fatalf("replay re-claimed: %v", r)
	}
	fs.Close()

	fs2, err := OpenFile(p, 0, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	if r := fs2.Consume(KindDelegation, "pid-1", exp); r != AlreadyConsumed {
		t.Fatalf("consumed key re-claimed after reopen: %v", r)
	}
	fs2.Close()
}

// A consume journal truncated below the ledger floor refuses to open.
func TestAdv21_ReplayTruncateBelowFloor(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "replay.jsonl")
	exp := time.Now().Add(time.Hour)
	fs, err := OpenFile(p, 0, &record.Binding{Signer: signer, Resolve: resolve})
	if err != nil {
		t.Fatal(err)
	}
	fs.Consume(KindDelegation, "pid-1", exp)
	fs.Consume(KindDelegation, "pid-2", exp)
	seq, tip := fs.JournalTip()
	fs.Close()

	data, _ := os.ReadFile(p)
	idx := 0
	for i := 0; i < 1 && idx < len(data); i++ {
		for idx < len(data) && data[idx] != '\n' {
			idx++
		}
		idx++
	}
	os.WriteFile(p, data[:idx], 0o600)

	b := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq, Hash: tip}}
	if _, err := OpenFile(p, 0, b); err == nil {
		t.Fatal("truncated replay journal below floor accepted")
	}
}
