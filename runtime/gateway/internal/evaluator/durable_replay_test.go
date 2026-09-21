// P2.1 durable replay at the evaluator boundary: a consumed delegation
// stays consumed across restart, storage failure fails closed, and
// request nonces are durable too.
package evaluator

import (
	"path/filepath"
	"testing"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/replay"
)

func durableEval(t *testing.T, journal string) (*Evaluator, *replay.FileStore) {
	t.Helper()
	ev := delegStore(t)
	rs, err := replay.OpenFile(journal, 0)
	if err != nil {
		t.Fatalf("open replay store: %v", err)
	}
	ev.SetReplayStore(rs)
	return ev, rs
}

// Allow → replay denied → restart (fresh evaluator + reopened store on
// the same journal) → replay still denied.
func TestDurableReplay_DelegationAcrossRestart(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "replay.jsonl")
	chain := mintDeleg([]string{"shell"}, "repo://org/*", "durable-n-1")

	ev, rs := durableEval(t, journal)
	resp, err := ev.Evaluate(delegReq("shell", "repo://org/x", chain))
	if err != nil || resp.Decision != models.DecisionAllow {
		t.Fatalf("first presentation = %v (err=%v)", resp.Decision, err)
	}
	// Replay with a FRESH request nonce — only the chain nonce repeats.
	resp, _ = ev.Evaluate(delegReq("shell", "repo://org/x", chain))
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("in-process replay = %v, want deny", resp.Decision)
	}
	rs.Close()

	// Simulated restart: new evaluator, new store, same journal.
	ev2, rs2 := durableEval(t, journal)
	defer rs2.Close()
	resp, _ = ev2.Evaluate(delegReq("shell", "repo://org/x", chain))
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("replay after restart = %v, want deny", resp.Decision)
	}
}

// A request that can no longer prove replay state must fail closed.
func TestDurableReplay_StorageFailureDenies(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "replay.jsonl")
	ev, rs := durableEval(t, journal)
	rs.Close()
	resp, _ := ev.Evaluate(delegReq("shell", "repo://org/x",
		mintDeleg([]string{"shell"}, "repo://org/*", "n-x")))
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("dead replay store = %v, want deny (fail closed)", resp.Decision)
	}
}

// The request nonce is durable too: same full request after restart → deny.
func TestDurableReplay_RequestNonceAcrossRestart(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "replay.jsonl")
	req := delegReq("shell", "repo://org/x",
		mintDeleg([]string{"shell"}, "repo://org/*", "n-req"))
	ev, rs := durableEval(t, journal)
	if resp, _ := ev.Evaluate(req); resp.Decision != models.DecisionAllow {
		t.Fatalf("first = %v", resp.Decision)
	}
	rs.Close()
	ev2, rs2 := durableEval(t, journal)
	defer rs2.Close()
	if resp, _ := ev2.Evaluate(req); resp.Decision != models.DecisionDeny {
		t.Fatalf("same request after restart = %v, want deny", resp.Decision)
	}
}

// Two different valid chains minted with the same nonce by the same
// issuer are one replay identity — second denied (matches RC1).
func TestDurableReplay_IssuerNonceIdentity(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "replay.jsonl")
	ev, rs := durableEval(t, journal)
	defer rs.Close()
	c1 := mintDeleg([]string{"shell"}, "repo://org/*", "shared-n")
	c2 := mintDeleg([]string{"deploy"}, "repo://org/*", "shared-n")
	if resp, _ := ev.Evaluate(delegReq("shell", "repo://org/x", c1)); resp.Decision != models.DecisionAllow {
		t.Fatalf("first = %v", resp.Decision)
	}
	if resp, _ := ev.Evaluate(delegReq("deploy", "repo://org/y", c2)); resp.Decision != models.DecisionDeny {
		t.Fatalf("issuer nonce reuse = %v, want deny", resp.Decision)
	}
}
