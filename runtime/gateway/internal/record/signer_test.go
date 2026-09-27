package record

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// The constructor panics are the custody guard: a half-configured
// signer must never silently exist — a missing key part or identity
// field means startup dies, not envelopes minted under a wrong ref.
func TestNewSigner_PanicsOnIncompleteInputs(t *testing.T) {
	priv, _ := newKey()
	cases := []struct {
		name string
		priv ed25519.PrivateKey
		dom  string
		gw   string
		kid  string
	}{
		{"short key", priv[:10], "domA", "gw1", "k1"},
		{"nil key", nil, "domA", "gw1", "k1"},
		{"empty domain", priv, "", "gw1", "k1"},
		{"empty gateway", priv, "domA", "", "k1"},
		{"empty key id", priv, "domA", "gw1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewSigner did not panic")
				}
			}()
			NewSigner(c.priv, c.dom, c.gw, c.kid)
		})
	}
	remoteCases := []struct{ dom, gw, kid string }{
		{"", "gw1", "k1"},
		{"domA", "", "k1"},
		{"domA", "gw1", ""},
	}
	for _, c := range remoteCases {
		t.Run("remote", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewRemoteSigner did not panic")
				}
			}()
			NewRemoteSigner(c.dom, c.gw, c.kid, func(b []byte) ([]byte, error) { return b, nil })
		})
	}
	t.Run("remote/nil sign func", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewRemoteSigner did not panic on nil sign func")
			}
		}()
		NewRemoteSigner("domA", "gw1", "k1", nil)
	})
}

// A remote signer delegates every payload verbatim to its callback —
// the gateway-side signature path never touches a private key.
func TestRemoteSigner_SignDelegatesAndPropagatesError(t *testing.T) {
	var saw []byte
	s := NewRemoteSigner("domA", "gw1", "k1", func(b []byte) ([]byte, error) {
		saw = append([]byte(nil), b...)
		return []byte("signed"), nil
	})
	if d := s.Domain(); d != "domA" {
		t.Fatalf("Domain() = %q", d)
	}
	if r := s.Ref(); r.GatewayID != "gw1" || r.KeyID != "k1" {
		t.Fatalf("Ref() = %+v", r)
	}
	sig, err := s.Sign([]byte("payload"))
	if err != nil || string(sig) != "signed" {
		t.Fatalf("Sign = %q, %v", sig, err)
	}
	if string(saw) != "payload" {
		t.Fatalf("remote signer saw %q", saw)
	}

	fail := errors.New("signing service down")
	s = NewRemoteSigner("domA", "gw1", "k1", func([]byte) ([]byte, error) { return nil, fail })
	if _, err := s.Sign([]byte("x")); !errors.Is(err, fail) {
		t.Fatalf("sign failure not propagated: %v", err)
	}
}

// A remote signing failure must abort the journal append — an
// unsigned envelope can never land in history.
func TestRemoteSigner_SignFailureAbortsAppend(t *testing.T) {
	fail := errors.New("signer unreachable")
	s := NewRemoteSigner("domA", "gw1", "k1", func([]byte) ([]byte, error) { return nil, fail })
	e := setup(t)
	j, err := Open("t", e.dir+"/j.jsonl", "domA", s, e.resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, _, err := j.Append("t", "r1", map[string]string{"x": "1"}, nil); !errors.Is(err, fail) {
		t.Fatalf("append with dead remote signer: %v", err)
	}
}
