// Preimage-binding tests for the journal envelope and sealed-file
// builders: every authority-bearing field must contribute its BYTES to
// the signed preimage — a mutation the preimage cannot see leaves the
// signature valid over tampered content.
package record

import (
	"encoding/json"
	"strings"
	"testing"
)

func msb(s string) string { // mutate, same length
	if s == "" {
		return "x"
	}
	b := []byte(s)
	b[0] ^= 0x01
	if b[0] == 0 || b[0] == '|' {
		b[0] = 'z'
	}
	return string(b)
}

func baseEnv() *Envelope {
	return &Envelope{
		V:        Version,
		Type:     "continuation",
		DomainID: "domA",
		Seq:      3,
		RecordID: "rec_a",
		Parent:   strings.Repeat("ab", 32),
		Payload:  json.RawMessage(`{"v":"x"}`),
		KeyRef:   KeyRef{GatewayID: "gw1", KeyID: "k1"},
	}
}

// Every signed field mutates the preimage. Links and V are excluded
// deliberately: links are cross-record evidence (never authority —
// see Envelope), and the version is bound by the -V1 domain separator
// plus verifyEnvelope's V check — both pinned below.
func TestPreimage_SigningPayloadCommitsEveryField(t *testing.T) {
	base := signingPayload(baseEnv())
	cases := map[string]func(*Envelope){
		"type":      func(e *Envelope) { e.Type = msb(e.Type) },
		"domain":    func(e *Envelope) { e.DomainID = msb(e.DomainID) },
		"record_id": func(e *Envelope) { e.RecordID = msb(e.RecordID) },
		"seq":       func(e *Envelope) { e.Seq++ },
		"parent":    func(e *Envelope) { e.Parent = msb(e.Parent) },
		"payload":   func(e *Envelope) { e.Payload = json.RawMessage(`{"v":"y"}`) },
		"key_gw":    func(e *Envelope) { e.KeyRef.GatewayID = msb(e.KeyRef.GatewayID) },
		"key_id":    func(e *Envelope) { e.KeyRef.KeyID = msb(e.KeyRef.KeyID) },
	}
	for name, mut := range cases {
		env := baseEnv()
		mut(env)
		if string(signingPayload(env)) == string(base) {
			t.Fatalf("signingPayload blind to %s", name)
		}
	}
}

// The unsigned field set is a contract: Links are evidence (never
// authority) and V is enforced at verify time, not signed. If either
// enters the preimage the contract changed — do it deliberately.
func TestPreimage_SigningPayload_UnsignedFieldsPinned(t *testing.T) {
	base := signingPayload(baseEnv())
	env := baseEnv()
	env.Links = []Link{{Kind: "caused-by", Hash: strings.Repeat("ff", 32)}}
	if string(signingPayload(env)) != string(base) {
		t.Fatal("links entered the signed preimage — they are evidence, never authority")
	}
	env2 := baseEnv()
	env2.V = 99
	if string(signingPayload(env2)) != string(base) {
		t.Fatal("version in the signed preimage — the -V1 domain tag is the binding")
	}
	// ...but a wrong V must still fail closed at verify time.
	e := setup(t)
	bad := baseEnv()
	bad.V = 99
	if err := verifyEnvelope(bad, e.domain, bad.Seq, bad.Parent, e.resolve); err == nil {
		t.Fatal("verifyEnvelope accepted wrong version")
	}
}

// Boundary slide: two different field assignments must never produce
// the same preimage — the lp framing makes this impossible, but the
// test pins it. "dom"+"A" and "do"+"mA" concatenate identically.
func TestPreimage_SigningPayload_NoBoundarySlide(t *testing.T) {
	a := baseEnv()
	a.DomainID, a.RecordID = "do", "mA"
	b := baseEnv()
	b.DomainID, b.RecordID = "dom", "A"
	if string(signingPayload(a)) == string(signingPayload(b)) {
		t.Fatal("boundary slide produced identical preimage")
	}
}

// The sealed whole-file snapshot builder: every _sec field commits.
func TestPreimage_FilePayloadCommitsEveryField(t *testing.T) {
	sec := func() *FileSec {
		return &FileSec{
			V:           Version,
			Store:       "idregistry",
			DomainID:    "domA",
			FileSeq:     4,
			PrevHash:    strings.Repeat("aa", 32),
			PayloadHash: strings.Repeat("bb", 32),
			KeyRef:      KeyRef{GatewayID: "gw1", KeyID: "k1"},
		}
	}
	base := filePayload(sec())
	cases := map[string]func(*FileSec){
		"store":        func(s *FileSec) { s.Store = msb(s.Store) },
		"domain":       func(s *FileSec) { s.DomainID = msb(s.DomainID) },
		"file_seq":     func(s *FileSec) { s.FileSeq++ },
		"prev_hash":    func(s *FileSec) { s.PrevHash = msb(s.PrevHash) },
		"payload_hash": func(s *FileSec) { s.PayloadHash = msb(s.PayloadHash) },
		"key_gw":       func(s *FileSec) { s.KeyRef.GatewayID = msb(s.KeyRef.GatewayID) },
		"key_id":       func(s *FileSec) { s.KeyRef.KeyID = msb(s.KeyRef.KeyID) },
	}
	for name, mut := range cases {
		s := sec()
		mut(s)
		if string(filePayload(s)) == string(base) {
			t.Fatalf("filePayload blind to %s", name)
		}
	}
	// Store doubles as the domain tag: sealing under "idregistry" and
	// opening as "capabilities" must diverge even before the field
	// check — different prefixes.
	s2 := sec()
	s2.Store = "capabilities"
	if string(filePayload(s2)) == string(base) {
		t.Fatal("filePayload blind to store substitution")
	}
}
