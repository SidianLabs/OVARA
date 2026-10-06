package decide

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/policy"
)

// RT-R1: a signed request replayed AFTER a gateway restart must still
// be denied — the nonce set is durable, not in-memory.
func TestReplayAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	nonceFile := dir + "/replay.jsonl"

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pol := &policy.Policy{Version: "t", Default: policy.Allow,
		Rules: []policy.Rule{{ID: "a", Effect: policy.Allow,
			Sel: policy.Selector{Types: []string{"*"}}}}}

	newEngine := func(t *testing.T) *Engine {
		e := NewEngine(pol, nil,
			map[string]ed25519.PublicKey{"agent1": pub}, func() uint64 { return 1 })
		rs, err := OpenReplayStore(nonceFile, 60*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		e.Replay = rs
		return e
	}

	a, err := action.Canonicalize("fs.read", "/x")
	if err != nil {
		t.Fatal(err)
	}
	req := &Request{Action: a, Nonce: "restart-test-nonce",
		IssuedAt: time.Now().UTC(), ActorID: "agent1"}
	req.Signature = "edsig_v2:" + hex.EncodeToString(
		ed25519.Sign(priv, []byte(req.RequestCanonical())))

	e1 := newEngine(t)
	if r := e1.Evaluate(req); r.Outcome != OutcomeAllow {
		t.Fatalf("first use must allow: %+v", r)
	}
	// simulate restart: new engine + reopened store
	e2 := newEngine(t)
	if r := e2.Evaluate(req); r.Outcome != OutcomeDeny {
		t.Fatalf("replay after restart must deny: %+v", r)
	}
}

// Corrupt store content must fail closed (refuse to open) — a
// truncated tail can't silently drop recorded nonces.
func TestReplayStoreCorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/r.jsonl"
	if err := os.WriteFile(p, []byte("{\"nonce\":\"ok\",\"at\":1}\nNOT-JSON\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReplayStore(p, time.Minute); err == nil {
		t.Fatal("corrupt store must refuse to open")
	}
}
