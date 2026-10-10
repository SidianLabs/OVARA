package receipts

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// Receipts on disk may be damaged or edited: verifying any bytes must never
// panic, and bytes nobody signed never verify as a non-empty chain.
func FuzzVerifyNeverPanics(f *testing.F) {
	f.Add([]byte(`{"receipt_id":"rcpt_1","prev_hash":"","signature":"sig_v1:00"}` + "\n"))
	f.Add([]byte("not json\n\n{}\n"))
	f.Add([]byte{})
	pub, _, _ := ed25519.GenerateKey(nil)
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "receipts.jsonl")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		res := VerifyFile(p, pub)
		if res.Valid && res.Total > 0 {
			t.Fatalf("unsigned bytes verified as %d receipts", res.Total)
		}
	})
}
