package continuation

// P2.4 adversarial suite — signed-journal fold totality (C5),
// positional parent binding (C6), unconditional identity gate (C3),
// and captured-authority expiry at claim (C4).

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/record"
)

func advSigner(t *testing.T) (*record.Signer, record.ResolveFunc) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	signer := record.NewSigner(priv, "dom-test", "gw1", "k1")
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw == "gw1" && kid == "k1" {
			return pub, nil
		}
		return nil, errTestNoKey("no key")
	}
	return signer, resolve
}

type errTestNoKey string

func (e errTestNoKey) Error() string { return string(e) }

// appendCont writes one signed "continuation" envelope whose payload is
// cnt verbatim.
func appendCont(t *testing.T, j *record.Journal, cnt *Continuation) {
	t.Helper()
	if _, _, err := j.Append("continuation", cnt.ContinuationID, cnt, nil); err != nil {
		t.Fatal(err)
	}
}

func openBoundStore(t *testing.T, path string, signer *record.Signer, resolve record.ResolveFunc) (*FileBackedStore, error) {
	t.Helper()
	b := &record.Binding{Signer: signer, Resolve: resolve}
	return NewFileBackedStoreWithRetention(path, 0, 0, 0, b)
}

// FOLD-01: terminal resurrection — denied tail followed by a queued
// restatement is an illegal transition; the store must refuse to open.
func TestAdv21_FOLD01_TerminalResurrection(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")

	j, err := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.MarkApproved("admin")
	c.MarkQueued()
	appendCont(t, j, c)
	d := *c
	d.MarkDenied("revocation", "lease killed")
	appendCont(t, j, &d)
	// resurrect: same id back to queued — illegal
	r := d
	r.State = StateQueued
	appendCont(t, j, &r)
	j.Close()

	st, err := openBoundStore(t, p, signer, resolve)
	if err == nil {
		st.journal.Close()
		t.Fatal("terminal resurrection accepted")
	}
}

// FOLD-02: executed→resumed is legal ONLY when the execution failed.
func TestAdv21_FOLD02_ResumedOnlyOnFailure(t *testing.T) {
	signer, resolve := advSigner(t)

	mk := func(succeeded bool) string {
		p := filepath.Join(t.TempDir(), "c.jsonl")
		j, err := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
		c.ContinuationID = "cont_1"
		c.MarkApproved("admin")
		c.MarkQueued()
		c.State = StateExecuting
		appendCont(t, j, c)
		e := *c
		e.State = StateExecuted
		e.LastExecutionSucceeded = succeeded
		appendCont(t, j, &e)
		r := e
		r.State = StateResumed
		appendCont(t, j, &r)
		j.Close()
		return p
	}

	// success=true → resumed must fail
	p := mk(true)
	if st, err := openBoundStore(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("executed(success)→resumed accepted")
	}
	// success=false → resumed is legal
	p = mk(false)
	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("executed(failed)→resumed rejected: %v", err)
	}
	st.journal.Close()
}

// FOLD-03: terminal same-state restatement is legal (the MarkRequeue+
// Update race on an unchanged record), but an executed outcome flip
// is not.
func TestAdv21_FOLD03_TerminalRestatementAndOutcomeFlip(t *testing.T) {
	signer, resolve := advSigner(t)

	// restatement OK
	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.MarkApproved("admin")
	c.MarkQueued()
	appendCont(t, j, c)
	d := *c
	d.MarkDenied("operator", "no")
	appendCont(t, j, &d)
	appendCont(t, j, &d) // identical restatement
	j.Close()
	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("terminal restatement rejected: %v", err)
	}
	st.journal.Close()

	// outcome flip fails
	p = filepath.Join(t.TempDir(), "c.jsonl")
	j, _ = record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendCont(t, j, c)
	c.State = StateExecuting
	appendCont(t, j, c)
	e := *c
	e.State = StateExecuted
	e.LastExecutionSucceeded = false
	appendCont(t, j, &e)
	e2 := e
	e2.LastExecutionSucceeded = true
	appendCont(t, j, &e2)
	j.Close()
	if st, err := openBoundStore(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("executed outcome flip accepted")
	}
}

// FOLD-04: genesis must be non-terminal — a record that first appears
// already executed/denied was never authorized (C5 totality).
func TestAdv21_FOLD04_TerminalGenesis(t *testing.T) {
	signer, resolve := advSigner(t)
	for _, st := range []State{StateExecuted, StateDenied, StateExpired, StateCancelled} {
		p := filepath.Join(t.TempDir(), "c.jsonl")
		j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
		c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
		c.ContinuationID = "cont_1"
		c.State = st
		appendCont(t, j, c)
		j.Close()
		if s, err := openBoundStore(t, p, signer, resolve); err == nil {
			s.journal.Close()
			t.Fatalf("terminal genesis %s accepted", st)
		}
	}
}

// FOLD-05: unknown state strings and unknown record types fail closed.
func TestAdv21_FOLD05_Unknowns(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.State = State("escalated-backwards") // unknown
	appendCont(t, j, c)
	// unknown record type rides a second line
	j.Append("wat", "x", map[string]string{"a": "b"}, nil)
	j.Close()
	if s, err := openBoundStore(t, p, signer, resolve); err == nil {
		s.journal.Close()
		t.Fatal("unknown record accepted")
	}
}

// FOLD-06: core-field mutation mid-chain — agent_id is part of the
// signed core; silently changing it between records is a fold error.
func TestAdv21_FOLD06_CoreMutation(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.MarkApproved("admin")
	appendCont(t, j, c)
	m := *c
	m.AgentID = "agt_attacker" // identity swap on the queued write
	m.MarkQueued()
	appendCont(t, j, &m)
	j.Close()
	if s, err := openBoundStore(t, p, signer, resolve); err == nil {
		s.journal.Close()
		t.Fatal("core-field mutation accepted")
	}
}

// STORE-01: an unsigned legacy file fails closed when a binding is
// configured — no silent upgrade, no skip.
func TestAdv21_STORE01_UnsignedFileFailsClosed(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	// legacy-format line: plain JSON, no envelope
	c := NewContinuation("dec_1", "shell", "shell:ls")
	b, _ := json.Marshal(c)
	os.WriteFile(p, append(b, '\n'), 0o600)
	if _, err := openBoundStore(t, p, signer, resolve); err == nil {
		t.Fatal("unsigned legacy journal opened in signed mode")
	}
}

// STORE-02: a journal signed in another domain is refused (transplant).
func TestAdv21_STORE02_ForeignDomain(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	// write with signer bound to a different domain
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	otherSigner := record.NewSigner(priv, "dom-evil", "gw9", "k9")
	j, _ := record.Open("continuation", p, otherSigner.Domain(), otherSigner, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.ContinuationID = "cont_1"
	c.MarkApproved("admin")
	appendCont(t, j, c)
	j.Close()
	if st, err := openBoundStore(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("foreign-domain journal accepted")
	}
}

// TAIL-01: truncating the denied tail of a journal under a ledger
// floor leaves a valid prefix that folds to queued — the floor check
// is what refuses it.
func TestAdv21_TAIL01_TruncateBelowFloor(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.ContinuationID = "cont_1"
	c.MarkApproved("admin")
	c.MarkQueued()
	appendCont(t, j, c)
	d := *c
	d.MarkDenied("revocation", "killed")
	appendCont(t, j, &d)
	seq, tip := j.Tip() // seq=2, tip=hash(denied line)
	j.Close()

	// attacker truncates the denied record → file folds to queued
	data, _ := os.ReadFile(p)
	lines := splitLines(data)
	os.WriteFile(p, joinLines(lines[:1]), 0o600)

	// without floor: prefix is a valid shorter journal (expected)
	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatalf("unfloored prefix should open: %v", err)
	}
	got, ok := st.Get("cont_1")
	if !ok || got.State != StateQueued {
		t.Fatalf("truncated state = %v, %v", got, ok)
	}
	st.journal.Close()

	// with floor at seq=2/tip: refuse
	b := &record.Binding{Signer: signer, Resolve: resolve,
		Floor: record.Floor{Known: true, Seq: seq, Hash: tip}}
	if _, err := NewFileBackedStoreWithRetention(p, 0, 0, 0, b); err == nil {
		t.Fatal("truncated journal below ledger floor accepted")
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return out
}

func joinLines(ls [][]byte) []byte {
	var buf []byte
	for _, l := range ls {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	return buf
}

// LEASE-01/02/03 (C4): captured authority expiry is checked at claim —
// expired → deny; live → proceed to normal checks; nil → legacy path.
func TestAdv21_LEASE_AuthorityExpiryGate(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	// LEASE-01: expired authority → deny, no revocation lookup needed
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c.AuthorityExpiresAt = &past
	deny, why, err := CheckClaimAuthority(nil, c)
	if !deny || err != nil {
		t.Fatalf("expired authority: deny=%v err=%v", deny, err)
	}
	if why == "" {
		t.Fatal("expected a deny reason")
	}

	// LEASE-02: live authority → no expiry deny (nil checker → no deny)
	c.AuthorityExpiresAt = &future
	deny, _, err = CheckClaimAuthority(nil, c)
	if deny || err != nil {
		t.Fatalf("live authority denied: %v %v", deny, err)
	}

	// LEASE-03: nil authority → legacy behavior
	c.AuthorityExpiresAt = nil
	deny, _, err = CheckClaimAuthority(nil, c)
	if deny || err != nil {
		t.Fatalf("nil authority denied: %v %v", deny, err)
	}
}

// IDENT-01/02 (C3): with a checker wired, empty agent_id fails the
// gate instead of bypassing it — both dispatch sites use the
// unconditional form `checker != nil && !checker(agentID)`.
func TestAdv21_IDENT_IdentityGateUnconditional(t *testing.T) {
	store := NewInMemoryStore()
	execStore := &mockExecStore{}
	exec := &mockExecutor{}
	reg := execution.NewExecutorRegistry()
	reg.Register("shell", exec)

	orch := NewOrchestrator(store, execStore, reg)
	orch.pollInterval = 50 * time.Millisecond
	// checker: only agt_live is active — "" and "agt_dead" fail
	orch.SetIdentityChecker(func(id string) bool { return id == "agt_live" })
	orch.Start()
	defer orch.Stop()

	dead := NewContinuation("dec_d", "shell", "shell:ls").WithAgentID("agt_dead")
	dead.MarkApproved("admin")
	dead.MarkQueued()
	store.Create(dead)
	empty := NewContinuation("dec_e", "shell", "shell:ls") // AgentID ""
	empty.MarkApproved("admin")
	empty.MarkQueued()
	store.Create(empty)
	live := NewContinuation("dec_l", "shell", "shell:ls").WithAgentID("agt_live")
	live.MarkApproved("admin")
	live.MarkQueued()
	store.Create(live)

	time.Sleep(400 * time.Millisecond)

	if exec.Calls() == 0 {
		t.Fatal("live continuation never executed — gate over-denies")
	}
	d, _ := store.Get(dead.ContinuationID)
	e, _ := store.Get(empty.ContinuationID)
	l, _ := store.Get(live.ContinuationID)
	if d.State == StateExecuting || d.State == StateExecuted {
		t.Fatalf("dead-identity continuation reached %s", d.State)
	}
	if e.State == StateExecuting || e.State == StateExecuted {
		t.Fatalf("empty-identity continuation reached %s", e.State)
	}
	if l.State != StateExecuted && l.State != StateExecuting {
		t.Fatalf("live continuation stuck at %s", l.State)
	}
}

// COMPACT-01/02: a signed compact event prunes live records outright
// and demotes terminal records to skeleton tombstones — and a
// post-compact genesis over a tombstoned id still refuses.
func TestAdv21_COMPACT_CompactSemantics(t *testing.T) {
	signer, resolve := advSigner(t)
	p := filepath.Join(t.TempDir(), "c.jsonl")
	j, _ := record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })

	live := NewContinuation("dec_l", "shell", "shell:ls").WithAgentID("agt_a")
	live.ContinuationID = "cont_live"
	live.MarkApproved("admin")
	live.MarkQueued()
	appendCont(t, j, live)

	term := NewContinuation("dec_t", "shell", "shell:ls").WithAgentID("agt_a")
	term.ContinuationID = "cont_term"
	term.MarkApproved("admin")
	term.MarkQueued()
	appendCont(t, j, term)
	td := *term
	td.MarkDenied("operator", "done")
	appendCont(t, j, &td)

	// compact removes both ids
	if _, _, err := j.Append(record.TypeCompact, "", map[string]any{
		"removed_ids": []string{"cont_live", "cont_term"}}, nil); err != nil {
		t.Fatal(err)
	}
	// post-compact resurrection attempt over the tombstoned id
	r := td
	r.State = StateQueued
	appendCont(t, j, &r)
	j.Close()

	if st, err := openBoundStore(t, p, signer, resolve); err == nil {
		st.journal.Close()
		t.Fatal("post-compact tombstone resurrection accepted")
	}

	// Without the resurrection line, compact semantics hold:
	p = filepath.Join(t.TempDir(), "c.jsonl")
	j, _ = record.Open("continuation", p, signer.Domain(), signer, resolve, record.Floor{}, func(*record.Envelope) error { return nil })
	appendCont(t, j, live)
	appendCont(t, j, term)
	appendCont(t, j, &td)
	j.Append(record.TypeCompact, "", map[string]any{"removed_ids": []string{"cont_live", "cont_term"}}, nil)
	j.Close()
	st, err := openBoundStore(t, p, signer, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get("cont_live"); ok {
		t.Fatal("live record survived compact")
	}
	got, ok := st.Get("cont_term")
	if !ok || got.State != StateDenied || !st.tombstones["cont_term"] {
		t.Fatalf("terminal compact remnant wrong: %+v tombstone=%v", got, st.tombstones["cont_term"])
	}
	st.journal.Close()
}
