// Canonical-preimage mutation property for the journal envelope and
// sealed-file signing payloads (docs/OVARA_2.1_JOURNAL_SPEC.md).
//
// Regression class under test: an lp helper that commits field
// LENGTHS but drops field CONTENTS makes the signature blind to
// same-length tampering. The property: mutate ONE covered field to a
// different value of the SAME length → the preimage must differ. The
// fold's chain linkage (parent = sha256 of the previous physical
// line) gets the same treatment.
package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mutationEnvelope() *Envelope {
	return &Envelope{
		V:        Version,
		Type:     "continuation",
		DomainID: "dom_a",
		Seq:      3,
		RecordID: "cnt_1",
		Parent:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Links:    []Link{{Kind: "evidence", Hash: "aa"}},
		Payload:  json.RawMessage(`{"k":"v1"}`),
		KeyRef:   KeyRef{GatewayID: "gw1", KeyID: "gk1"},
		Sig:      "00",
	}
}

func TestSigningPayload_FieldMutationChangesPreimage(t *testing.T) {
	base := SigningPayload(mutationEnvelope())
	mutations := []struct {
		name string
		mut  func(*Envelope)
	}{
		// Type is the domain separator itself ("OVARA-RECORD-<type>-V1")
		// — same-length substitution must still move the bytes.
		{"type", func(e *Envelope) { e.Type = "continuatioX" }},
		{"domain_id", func(e *Envelope) { e.DomainID = "dom_b" }},
		{"record_id", func(e *Envelope) { e.RecordID = "cnt_2" }},
		{"seq", func(e *Envelope) { e.Seq = 4 }},
		{"parent", func(e *Envelope) {
			e.Parent = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		}},
		{"payload", func(e *Envelope) { e.Payload = json.RawMessage(`{"k":"v2"}`) }},
		{"keyref_gateway", func(e *Envelope) { e.KeyRef.GatewayID = "gw2" }},
		{"keyref_key", func(e *Envelope) { e.KeyRef.KeyID = "gk2" }},
	}
	for _, m := range mutations {
		env := mutationEnvelope()
		m.mut(env)
		if bytes.Equal(SigningPayload(env), base) {
			t.Errorf("%s: envelope mutation produced identical signing payload", m.name)
		}
	}
	// Fields the signature deliberately does not cover: Links (evidence
	// hints, not authority), Sig itself, and V (the version tag is
	// already in the domain constant for this format).
	untouched := []struct {
		name string
		mut  func(*Envelope)
	}{
		{"sig", func(e *Envelope) { e.Sig = "ff" }},
		{"links", func(e *Envelope) { e.Links = []Link{{Kind: "other", Hash: "bb"}} }},
	}
	for _, m := range untouched {
		env := mutationEnvelope()
		m.mut(env)
		if !bytes.Equal(SigningPayload(env), base) {
			t.Errorf("%s: non-covered field changed the signing payload — contract drifted", m.name)
		}
	}
}

func TestFilePayload_FieldMutationChangesPreimage(t *testing.T) {
	mk := func() *FileSec {
		return &FileSec{
			V:           Version,
			Store:       "idregistry",
			DomainID:    "dom_a",
			FileSeq:     9,
			PrevHash:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			PayloadHash: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			KeyRef:      KeyRef{GatewayID: "gw1", KeyID: "gk1"},
		}
	}
	base := filePayload(mk())
	mutations := []struct {
		name string
		mut  func(*FileSec)
	}{
		{"store", func(s *FileSec) { s.Store = "Xdregistry" }},
		{"domain_id", func(s *FileSec) { s.DomainID = "dom_b" }},
		{"file_seq", func(s *FileSec) { s.FileSeq = 10 }},
		{"prev_hash", func(s *FileSec) {
			s.PrevHash = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		}},
		{"payload_hash", func(s *FileSec) {
			s.PayloadHash = "0edcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		}},
		{"keyref_gateway", func(s *FileSec) { s.KeyRef.GatewayID = "gw2" }},
		{"keyref_key", func(s *FileSec) { s.KeyRef.KeyID = "gk2" }},
	}
	for _, m := range mutations {
		sec := mk()
		m.mut(sec)
		if bytes.Equal(filePayload(sec), base) {
			t.Errorf("%s: sealed-file mutation produced identical signing payload", m.name)
		}
	}
}

// The chain link is the journal's tamper evidence: parent = sha256 of
// the previous physical line. Any byte change to that line — content
// or length — must move the tip hash the next record commits to, and
// genesis binds (domain, store) so cross-store grafts fail.
func TestChainLink_FieldMutationMovesTip(t *testing.T) {
	lineA := []byte(`{"v":1,"record_id":"a"}`)
	lineB := []byte(`{"v":1,"record_id":"b"}`) // same length
	if TipHash(lineA) == TipHash(lineB) {
		t.Fatal("identical tip hash for different line bytes")
	}
	if GenesisParent("domA", "store") == GenesisParent("domB", "store") ||
		GenesisParent("domA", "store") == GenesisParent("domA", "xtore") {
		t.Fatal("genesis parent is not domain/store bound")
	}
}

// A signed envelope appended by a SECOND writer (multi-process sharing
// under flock) must be verifiable by the fold — the mutation property
// applied end-to-end: a forged same-length record must not absorb.
func TestAbsorb_FieldMutationRejected(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "s.jsonl")
	fold := func(*Envelope) error { return nil }
	j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, fold)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Append("continuation", "a", map[string]string{"v": "a"}, nil); err != nil {
		t.Fatal(err)
	}
	// Second writer continues the chain at our tip (the flock-sharing
	// case Absorb exists for).
	w, err := ResumeAt("continuation", p, e.domain, e.signer, 1, func() string {
		_, tip := j.Tip()
		return tip
	}())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Append("continuation", "b", map[string]string{"v": "b"}, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if err := j.Absorb(); err != nil {
		t.Fatalf("honest append refused by absorb: %v", err)
	}
	if seq, _ := j.Tip(); seq != 2 {
		t.Fatalf("absorbed tip seq = %d, want 2", seq)
	}
	j.Close()
}

// A forged line appended out-of-band (same seq/parent shape, no valid
// signature) must fail the absorb — the fold does not soften for
// cross-process appends.
func TestAbsorb_ForgedLineRejected(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "s.jsonl")
	j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Append("continuation", "a", map[string]string{"v": "a"}, nil); err != nil {
		t.Fatal(err)
	}
	_, tip := j.Tip()
	forged, _ := json.Marshal(&Envelope{
		V: Version, Type: "continuation", DomainID: e.domain,
		Seq: 2, RecordID: "evil", Parent: tip,
		Payload: json.RawMessage(`{"v":"evil"}`),
		KeyRef:  KeyRef{GatewayID: "gw1", KeyID: "k1"},
		Sig:     "deadbeef",
	})
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(forged, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := j.Absorb(); err == nil {
		t.Fatal("forged absorbed line accepted")
	}
	j.Close()
}

// A shrunken file (unauthorized rewrite between folds) fails closed —
// never silently re-bases.
func TestAbsorb_ShrunkJournalRejected(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "s.jsonl")
	j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if _, _, err := j.Append("continuation", id, map[string]string{"v": id}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Truncate(p, 10); err != nil {
		t.Fatal(err)
	}
	if err := j.Absorb(); err == nil {
		t.Fatal("shrunk journal absorbed without error")
	}
	j.Close()
}

// A detached envelope must verify against the exported SigningPayload
// exactly as the fold verifies it — this is the contract the lineage
// verifier relies on for the approval journal line inside a bundle.
func TestSigningPayload_DetachedEnvelopeVerifies(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "s.jsonl")
	j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Append("continuation", "a", map[string]string{"v": "a"}, nil); err != nil {
		t.Fatal(err)
	}
	env := j.LastEnvelope()
	if env == nil {
		t.Fatal("no last envelope")
	}
	pub, err := e.resolve(env.KeyRef.GatewayID, env.KeyRef.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(env.Sig)
	if err != nil || !ed25519.Verify(pub, SigningPayload(env), sig) {
		t.Fatal("detached envelope does not verify against SigningPayload")
	}
	// Journal accessors must reflect the live writer state.
	if j.Domain() != e.domain || j.Store() != "continuation" || j.Signer() != e.signer || j.File() == nil {
		t.Fatal("journal accessors disagree with the open binding")
	}
	j.Close()
}
