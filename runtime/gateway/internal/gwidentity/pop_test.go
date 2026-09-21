package gwidentity

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func setupPeer(t *testing.T) (*Registry, ed25519.PrivateKey, *KeyRecord) {
	t.Helper()
	r := NewInMemory()
	priv, pub := genPub(t)
	rec, err := r.Register("gw_a", pub)
	if err != nil {
		t.Fatal(err)
	}
	return r, priv, rec
}

func TestPop_ValidChallenge_Succeeds(t *testing.T) {
	r, priv, rec := setupPeer(t)
	ch, _ := Challenge()
	sig := Prove(priv, rec.GatewayID, rec.KeyID, ch)
	peer, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig)
	if err != nil {
		t.Fatal(err)
	}
	if peer.GatewayID != rec.GatewayID || peer.KeyID != rec.KeyID {
		t.Fatalf("wrong peer: %+v", peer)
	}
}

func TestPop_WrongSignature(t *testing.T) {
	r, priv, rec := setupPeer(t)
	ch, _ := Challenge()
	sig := Prove(priv, rec.GatewayID, rec.KeyID, ch)
	sig[0] ^= 0xff
	if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestPop_WrongKey(t *testing.T) {
	r, _, rec := setupPeer(t)
	priv2, _ := genPub(t)
	ch, _ := Challenge()
	sig := Prove(priv2, rec.GatewayID, rec.KeyID, ch)
	if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-key signature must fail: %v", err)
	}
}

func TestPop_WrongGatewayID(t *testing.T) {
	r, priv, rec := setupPeer(t)
	ch, _ := Challenge()
	// Signature binds gw_b — verification against gw_a's record fails.
	sig := Prove(priv, "gw_b", rec.KeyID, ch)
	if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("cross-gateway signature must fail: %v", err)
	}
}

func TestPop_ModifiedChallenge(t *testing.T) {
	r, priv, rec := setupPeer(t)
	ch, _ := Challenge()
	sig := Prove(priv, rec.GatewayID, rec.KeyID, ch)
	ch[0] ^= 0x01
	if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("modified challenge must fail: %v", err)
	}
}

func TestPop_ModifiedKeyID(t *testing.T) {
	r, priv, rec := setupPeer(t)
	ch, _ := Challenge()
	sig := Prove(priv, rec.GatewayID, rec.KeyID, ch)
	if _, err := r.AuthenticatePeer(rec.GatewayID, "gwk_other", ch, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key_id must fail: %v", err)
	}
}

func TestPop_ChallengeForA_FailsForB(t *testing.T) {
	r, priv, recA := setupPeer(t)
	_, pubB := genPub(t)
	recB, err := r.Register("gw_b", pubB)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := Challenge()
	// Response minted for gateway A must not authenticate gateway B —
	// even when presented under B's own key_id.
	sig := Prove(priv, recA.GatewayID, recA.KeyID, ch)
	if _, err := r.AuthenticatePeer(recB.GatewayID, recB.KeyID, ch, sig); err == nil {
		t.Fatal("A's PoP response must not authenticate B")
	}
}

func TestPop_UnknownGateway(t *testing.T) {
	r, priv, _ := setupPeer(t)
	ch, _ := Challenge()
	sig := Prove(priv, "gw_ghost", "gwk_x", ch)
	if _, err := r.AuthenticatePeer("gw_ghost", "gwk_x", ch, sig); !errors.Is(err, ErrUnknownGateway) {
		t.Fatalf("unknown gateway must fail: %v", err)
	}
}

func TestPop_MalformedInputs_NoPanic(t *testing.T) {
	r, _, rec := setupPeer(t)
	for _, ch := range [][]byte{nil, {}, {1}, make([]byte, 31), make([]byte, 33), make([]byte, 1<<20)} {
		if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, make([]byte, 64)); err == nil {
			t.Fatalf("challenge len %d must fail", len(ch))
		}
	}
	for _, sig := range [][]byte{nil, {}, {1}, make([]byte, 63), make([]byte, 65)} {
		ch, _ := Challenge()
		if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); err == nil {
			t.Fatalf("sig len %d must fail", len(sig))
		}
	}
}

func TestPop_RotatingKey_ProvesInGrace(t *testing.T) {
	r, privA, recA := setupPeer(t)
	_, pubB := genPub(t)
	if _, err := r.Rotate("gw_a", pubB, time.Hour); err != nil {
		t.Fatal(err)
	}
	ch, _ := Challenge()
	sig := Prove(privA, recA.GatewayID, recA.KeyID, ch)
	peer, err := r.AuthenticatePeer(recA.GatewayID, recA.KeyID, ch, sig)
	if err != nil || peer.State != KeyRotating {
		t.Fatalf("in-grace rotating key must prove: %v %+v", err, peer)
	}
}

func TestPop_SupersededKey_Fails(t *testing.T) {
	r, privA, recA := setupPeer(t)
	_, pubB := genPub(t)
	if _, err := r.Rotate("gw_a", pubB, 0); err != nil { // hard cut
		t.Fatal(err)
	}
	ch, _ := Challenge()
	sig := Prove(privA, recA.GatewayID, recA.KeyID, ch)
	if _, err := r.AuthenticatePeer(recA.GatewayID, recA.KeyID, ch, sig); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("superseded key must not authenticate: %v", err)
	}
}

func TestPop_RevokedKey_FailsEvenInGrace(t *testing.T) {
	r, privA, recA := setupPeer(t)
	_, pubB := genPub(t)
	if _, err := r.Rotate("gw_a", pubB, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeKey("gw_a", recA.KeyID); err != nil {
		t.Fatal(err)
	}
	ch, _ := Challenge()
	sig := Prove(privA, recA.GatewayID, recA.KeyID, ch)
	if _, err := r.AuthenticatePeer(recA.GatewayID, recA.KeyID, ch, sig); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("revoked key must never prove — revocation beats grace: %v", err)
	}
}

func TestPop_DestroyedKey_Fails(t *testing.T) {
	r, priv, rec := setupPeer(t)
	if err := r.Destroy("gw_a"); err != nil {
		t.Fatal(err)
	}
	ch, _ := Challenge()
	sig := Prove(priv, rec.GatewayID, rec.KeyID, ch)
	if _, err := r.AuthenticatePeer(rec.GatewayID, rec.KeyID, ch, sig); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("destroyed key must fail: %v", err)
	}
}

func TestPop_UnregisteredKey_Fails(t *testing.T) {
	r, _, rec := setupPeer(t)
	privB, _ := genPub(t)
	ch, _ := Challenge()
	// Valid signature, but under a key_id that isn't registered.
	sig := Prove(privB, rec.GatewayID, "gwk_unregistered", ch)
	if _, err := r.AuthenticatePeer(rec.GatewayID, "gwk_unregistered", ch, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unregistered key must fail: %v", err)
	}
}
