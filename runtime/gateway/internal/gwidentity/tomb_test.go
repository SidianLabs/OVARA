package gwidentity

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"
)

// A destroyed gateway's tombstone is terminal: RevokeKey must not
// rewrite a destroyed record (destroyed→revoked would defeat Rotate's
// allDestroyed guard and resurrect the gateway).
func TestTombstone_RevokeThenRotate(t *testing.T) {
	r := NewInMemory()
	pubA, _, _ := ed25519.GenerateKey(nil)
	rec, _ := r.Register("gw_x", pubA)
	if err := r.Destroy("gw_x"); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeKey("gw_x", rec.KeyID); !errors.Is(err, ErrGatewayDestroyed) {
		t.Fatalf("revoking a destroyed key must refuse, got %v", err)
	}
	pubB, _, _ := ed25519.GenerateKey(nil)
	if _, err := r.Rotate("gw_x", pubB, time.Hour); !errors.Is(err, ErrGatewayDestroyed) {
		t.Fatalf("rotate on destroyed gateway must refuse, got %v", err)
	}
	if _, err := r.Register("gw_x", pubB); !errors.Is(err, ErrGatewayConflict) {
		t.Fatalf("register on destroyed gateway must conflict, got %v", err)
	}
}

// Live shrink = history rewrite: a file truncated below this process's
// committed offset must fail closed (rollback of revocations/tombstones
// must not silently re-authorize dead trust state).
func TestAbsorb_ExternalShrink_FailsClosed(t *testing.T) {
	p := t.TempDir() + "/reg.jsonl"
	r, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	pubA, _, _ := ed25519.GenerateKey(nil)
	if _, err := r.Register("gw_a", pubA); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, 4); err != nil { // external rewrite below committed offset
		t.Fatal(err)
	}
	if _, err := r.Register("gw_b", pubA); err == nil {
		t.Fatal("shrunk registry must not accept new registrations")
	}
	if _, err := r.Lookup("gw_a"); err == nil {
		t.Fatal("shrunk registry must fail lookup closed")
	}
}
