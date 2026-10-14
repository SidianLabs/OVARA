package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/receipts"
	"ovara.proxy/internal/sandbox"
)

// a chain with three receipts before the run and five in it
func chainFor(t *testing.T) (dir, chain, key, pub string) {
	t.Helper()
	dir = t.TempDir()
	chain, key, pub = filepath.Join(dir, "var", "receipts.jsonl"), filepath.Join(dir, "var", "receipt.key"), filepath.Join(dir, "var", "receipt_pubkey.hex")
	c, err := receipts.LoadOrCreate(chain, key, pub)
	if err != nil {
		t.Fatal(err)
	}
	add := func(e receipts.Entry) {
		if _, err := c.Append(e, true); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		add(receipts.Entry{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: "allow", Status: 200, PolicyHash: "p0"})
	}
	add(receipts.Entry{Method: "GET", URL: "https://pypi.org:443/simple/", Decision: "allow", Status: 200, PolicyHash: "p1", Agent: "a1"})
	add(receipts.Entry{Method: "POST", URL: "https://pastebin.com:443/api", Decision: "deny", PolicyHash: "p1", Rule: "dump site", Agent: "a1"})
	add(receipts.Entry{Method: "POST", URL: "https://api.github.com:443/repos/o/r/pulls", Decision: "escalate", PolicyHash: "p1", Agent: "a1", ApprovalID: "apr_1"})
	add(receipts.Entry{Method: "POST", URL: "https://api.github.com:443/repos/o/r/pulls", Decision: "allow", Status: 201, PolicyHash: "p1", ApprovalID: "apr_1", Approver: "slack:U1", Agent: "a1"})
	add(receipts.Entry{Method: "GET", URL: "https://example.org:443/", Decision: "error", PolicyHash: "p1", Agent: "a1"})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, chain, key, pub
}

func runFor(manifest []byte) Run {
	return Run{ID: "20261014-050000", Runtime: RuntimeBox, Agent: "a1", Started: time.Now().Add(-time.Minute), Finished: time.Now(),
		Manifest: manifest, Branch: "ovara/box-20261014-050000", Commit: "0123456789abcdef0123456789abcdef01234567",
		Summary: sandbox.Summary{Outcome: sandbox.OutcomeClean, Requests: sandbox.Counts{Allowed: 2, Paused: 1, Denied: 1}, Hosts: 4, CommitBack: "landed", Branch: "ovara/box-20261014-050000", Commit: "0123456789ab"}}
}

func TestAttestation_BuildSignWriteVerify(t *testing.T) {
	dir, chain, key, pub := chainFor(t)
	manifest := []byte(`{"version":"0.1","workspace":{"source":"/p"},"agent":{"command":["x"]}}`)
	st, err := Build(runFor(manifest), chain, pub, 3)
	if err != nil {
		t.Fatal(err)
	}
	p := st.Predicate
	if p.Receipts.Count != 5 || p.Receipts.After != 3 || p.Receipts.PrevHash == "" || p.Receipts.Head == "" {
		t.Fatalf("receipts: %+v", p.Receipts)
	}
	if len(p.Policy.Hashes) != 1 || p.Policy.Hashes[0] != "p1" {
		t.Fatalf("policy: %+v", p.Policy)
	}
	if len(p.Approvals) != 1 || p.Approvals[0].Approver != "slack:U1" || p.Approvals[0].Resource != "POST https://api.github.com:443/repos/o/r/pulls" {
		t.Fatalf("approvals: %+v", p.Approvals)
	}
	// a held request that nobody approved names its approval too, but is not an approval given
	ring, _ := receipts.LoadKeyRing(pub)
	_, all := receipts.ReadVerified(chain, ring)
	if _, held, _ := derive(all[5:6]); len(held) != 0 {
		t.Fatalf("a held request counted as an approval: %+v", held)
	}
	if len(p.Hosts) != 4 || p.Hosts[0].Host != "api.github.com:443" || p.Hosts[0].Allowed != 1 || p.Hosts[0].Paused != 1 || p.Hosts[1].Host != "example.org:443" || p.Hosts[1].Errors != 1 {
		t.Fatalf("hosts: %+v", p.Hosts)
	}
	if len(st.Subject) != 2 || st.Subject[0].Digest["gitCommit"] != runFor(nil).Commit || st.Subject[1].Digest["sha256"] != p.Receipts.SHA256 {
		t.Fatalf("subjects: %+v", st.Subject)
	}
	env, err := Sign(st, key)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := Write(dir, "20261014-050000", env)
	if err != nil || rel != "var/attestations/20261014-050000.intoto.json" {
		t.Fatalf("write: %v %q", err, rel)
	}
	if st, err := os.Stat(filepath.Join(dir, rel)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", err, st)
	}
	// a second one for the same run id is not written over the first
	if rel2, err := Write(dir, "20261014-050000", env); err != nil || rel2 == rel {
		t.Fatalf("second write: %v %q", err, rel2)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, rel))
	rep := Verify(raw, chain, pub, receipts.Segment{}, manifest)
	if !rep.Valid || rep.Chain.Total != 8 || rep.KeyID == "" {
		t.Fatalf("verify: %+v", rep)
	}
	if d := Describe(rep.Statement); !strings.Contains(d, "approved by slack:U1") || !strings.Contains(d, "5 request(s): 2 allowed, 1 paused, 1 denied; 4 host(s)") || !strings.Contains(d, "commit 0123456789ab") {
		t.Fatalf("describe:\n%s", d)
	}
	// without the manifest: fine; with another one: not the run's
	if rep := Verify(raw, chain, pub, receipts.Segment{}, nil); !rep.Valid {
		t.Fatalf("no manifest given: %v", rep.Problems)
	}
	if rep := Verify(raw, chain, pub, receipts.Segment{}, []byte("{}")); rep.Valid || !strings.Contains(strings.Join(rep.Problems, ";"), "not the one the run was made from") {
		t.Fatalf("another manifest: %v", rep.Problems)
	}
}

func TestAttestation_TamperingFails(t *testing.T) {
	dir, chain, key, pub := chainFor(t)
	st, err := Build(runFor(nil), chain, pub, 3)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := Sign(st, key)
	raw, _ := json.Marshal(env)
	// a changed payload no longer matches its signature
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	changed := bytes.Replace(payload, []byte(`"count":5`), []byte(`"count":4`), 1)
	e2 := *env
	e2.Payload = base64.StdEncoding.EncodeToString(changed)
	raw2, _ := json.Marshal(e2)
	if rep := Verify(raw2, chain, pub, receipts.Segment{}, nil); rep.Valid || !strings.Contains(rep.Problems[0], "signature") {
		t.Fatalf("changed payload: %+v", rep.Problems)
	}
	// a changed receipt breaks the chain, so the statement no longer holds
	b, _ := os.ReadFile(chain)
	tampered := bytes.Replace(b, []byte("pastebin.com"), []byte("pastebin.org"), 1)
	other := filepath.Join(dir, "tampered.jsonl")
	if err := os.WriteFile(other, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := Verify(raw, other, pub, receipts.Segment{}, nil); rep.Valid || !strings.Contains(strings.Join(rep.Problems, ";"), "receipt chain") {
		t.Fatalf("tampered chain: %+v", rep.Problems)
	}
	// another deployment's key does not verify it
	_, _, _, pub2 := chainFor(t)
	if rep := Verify(raw, chain, pub2, receipts.Segment{}, nil); rep.Valid || !strings.Contains(rep.Problems[0], "unknown key") {
		t.Fatalf("another key: %+v", rep.Problems)
	}
	// a launcher's summary that disagrees with the receipts is caught: six
	// receipts with the five-receipt counts
	st2, _ := Build(runFor(nil), chain, pub, 2)
	env2, _ := Sign(st2, key)
	raw3, _ := json.Marshal(env2)
	if rep := Verify(raw3, chain, pub, receipts.Segment{}, nil); rep.Valid || !strings.Contains(strings.Join(rep.Problems, ";"), "summary") {
		t.Fatalf("summary off by one receipt: %v", rep.Problems)
	}
	run6 := runFor(nil)
	run6.Summary.Requests.Allowed = 3
	st2, _ = Build(run6, chain, pub, 2)
	env2, _ = Sign(st2, key)
	raw3, _ = json.Marshal(env2)
	if rep := Verify(raw3, chain, pub, receipts.Segment{}, nil); !rep.Valid {
		t.Fatalf("a statement about six receipts: %v", rep.Problems)
	}
	// a statement claiming more receipts than the chain holds fails
	st3 := *st
	st3.Predicate.Receipts.Count = 9
	env3, _ := Sign(&st3, key)
	raw4, _ := json.Marshal(env3)
	if rep := Verify(raw4, chain, pub, receipts.Segment{}, nil); rep.Valid || !strings.Contains(strings.Join(rep.Problems, ";"), "does not hold the run's receipts") {
		t.Fatalf("too many: %v", rep.Problems)
	}
	// a broken chain is never attested
	if _, err := Build(runFor(nil), other, pub, 3); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("build on a broken chain: %v", err)
	}
}

func TestAttestation_VerifiesFromABundleCut(t *testing.T) {
	dir, chain, key, pub := chainFor(t)
	st, _ := Build(runFor(nil), chain, pub, 3)
	env, _ := Sign(st, key)
	raw, _ := json.Marshal(env)
	ring, _ := receipts.LoadKeyRing(pub)
	_, recs := receipts.ReadVerified(chain, ring)
	cut := func(from int) (string, receipts.Segment) {
		var b []byte
		for _, v := range recs[from:] {
			b = append(append(b, v.Line...), '\n')
		}
		p := filepath.Join(dir, "cut.jsonl")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p, receipts.Segment{After: from, PrevHash: receipts.LineHash(recs[from-1].Line)}
	}
	// the bundle starts before the run: fine
	p, seg := cut(2)
	if rep := Verify(raw, p, pub, seg, nil); !rep.Valid {
		t.Fatalf("cut before the run: %v", rep.Problems)
	}
	// the bundle starts exactly at the run: fine (the link is the segment's)
	p, seg = cut(3)
	if rep := Verify(raw, p, pub, seg, nil); !rep.Valid {
		t.Fatalf("cut at the run: %v", rep.Problems)
	}
	// the bundle starts inside the run: it cannot be checked
	p, seg = cut(5)
	if rep := Verify(raw, p, pub, seg, nil); rep.Valid || !strings.Contains(strings.Join(rep.Problems, ";"), "does not hold the run's receipts") {
		t.Fatalf("cut inside the run: %v", rep.Problems)
	}
}

func TestPAEIsDSSEv1(t *testing.T) {
	if got := string(pae("application/vnd.in-toto+json", []byte("hi"))); got != "DSSEv1 28 application/vnd.in-toto+json 2 hi" {
		t.Fatal(got)
	}
	// the receipt key signs two kinds of message; their prefixes differ
	if strings.HasPrefix(string(pae(PayloadType, nil)), "ovara-proxy-receipt") {
		t.Fatal("prefix collision with receipt signatures")
	}
}

func TestAttestation_EmptyRun(t *testing.T) {
	_, chain, key, pub := chainFor(t)
	run := runFor(nil)
	run.Commit, run.Branch = "", ""
	run.Summary = sandbox.Summary{Outcome: sandbox.OutcomeClean}
	st, err := Build(run, chain, pub, 8)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Receipts.Count != 0 || st.Predicate.Receipts.Head != "" || st.Predicate.Receipts.PrevHash == "" || len(st.Subject) != 1 {
		t.Fatalf("empty run: %+v %+v", st.Predicate.Receipts, st.Subject)
	}
	env, _ := Sign(st, key)
	raw, _ := json.Marshal(env)
	if rep := Verify(raw, chain, pub, receipts.Segment{}, nil); !rep.Valid {
		t.Fatalf("empty run: %v", rep.Problems)
	}
}
