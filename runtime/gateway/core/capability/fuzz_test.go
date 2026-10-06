package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

// Verify on arbitrary bytes must never panic; a decoded token that
// fails verification must not produce a scope.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := Issue(priv, "f", 0, holderPub, Scope{
		ActionTypes: []string{"fs.read"}, Resources: []string{"/a*"},
		Envs: []string{"dev"}}, nil, false)
	gj, _ := json.Marshal(good)
	f.Add(gj)
	f.Add([]byte(`{"id":"x","blocks":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	issuers := map[string]ed25519.PublicKey{PubID(pub): pub}
	f.Fuzz(func(t *testing.T, data []byte) {
		var tok Token
		if err := json.Unmarshal(data, &tok); err != nil {
			return
		}
		sc, err := Verify(&tok, issuers, 5)
		if err == nil && len(sc.ActionTypes) == 0 && len(sc.Resources) == 0 {
			t.Error("verify ok but empty scope — empty effective scope must not be granted")
		}
		// also: a fuzzed token must never verify as the real one
	})
	_ = time.Now
}
