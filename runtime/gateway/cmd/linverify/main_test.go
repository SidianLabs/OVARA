package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestKeys_Decode(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	m, err := keys(map[string]string{"gw|k1": hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if len(m["gw|k1"]) != ed25519.PublicKeySize {
		t.Fatalf("decoded %d bytes", len(m["gw|k1"]))
	}
	for _, bad := range map[string]string{
		"not-hex":   "zzzz",
		"wrong-len": hex.EncodeToString([]byte{1, 2, 3}),
	} {
		for name, h := range map[string]string{"x": bad} {
			if _, err := keys(map[string]string{name: h}); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	}
}
