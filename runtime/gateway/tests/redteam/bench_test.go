package redteam

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"ovara.runtime.gateway/core/decide"
)

// Decision latency is a safety property: the check sits on every
// consequential action, so it must be cheap relative to any action's
// real cost. This pins an order-of-magnitude bound in-tree.
func BenchmarkEvaluateSignedAllow(b *testing.B) {
	eng := engine()
	a := canon(&testing.T{}, "http.request", "GET https://api.github.com/x")
	r := &decide.Request{Action: a, IssuedAt: time.Now().UTC(), ActorID: "agent1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Nonce = hex.EncodeToString([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		r.Signature = "edsig_v2:" + hex.EncodeToString(
			ed25519.Sign(agentKey, []byte(r.RequestCanonical())))
		if res := eng.Evaluate(r); res.Outcome != decide.OutcomeAllow {
			b.Fatalf("bench request denied: %+v", res)
		}
	}
}
