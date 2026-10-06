package decide

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"ovara.runtime.gateway/core/policy"
)

// Evaluate on arbitrary request JSON must never panic and must never
// allow a request without a valid signature.
func FuzzEvaluateNoSigNoAllow(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = priv
	pol := &policy.Policy{Version: "f", Default: policy.Allow,
		Rules: []policy.Rule{{ID: "a", Effect: policy.Allow,
			Sel: policy.Selector{Types: []string{"*"}}}}}
	eng := NewEngine(pol, nil,
		map[string]ed25519.PublicKey{"agent1": pub}, func() uint64 { return 1 })
	f.Add([]byte(`{"action":{"type":"fs.read","resource":"/a","env":"dev"},"nonce":"n","issued_at":"2030-01-01T00:00:00Z","actor_id":"agent1","signature":"edsig_v2:00"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Request
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		res := eng.Evaluate(&r)
		if res.Outcome == OutcomeAllow {
			t.Fatalf("unsigned/unverifiable request allowed: %s", data)
		}
	})
	_ = time.Now
}
