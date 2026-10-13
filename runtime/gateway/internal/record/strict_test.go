package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openE(e *envT, path string, bound KeyBoundFunc) (*Journal, error) {
	return open("continuation", path, e.domain, e.signer, e.resolve, bound, Floor{}, func(*Envelope) error { return nil })
}

func rewrite(t *testing.T, path string, ls [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, append(bytes.Join(ls, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// G-11: the tail's links, an extra key, a duplicate key: nothing outside
// the signature may change without the journal failing to open.
func TestJournalBytesAreBound(t *testing.T) {
	e := setup(t)
	edits := map[string]func(string) string{
		"links": func(l string) string {
			return strings.Replace(l, `"payload"`, `"links":[{"kind":"x","hash":"y"}],"payload"`, 1)
		},
		"extra key":     func(l string) string { return strings.Replace(l, `{"v":2,`, `{"v":2,"note":"x",`, 1) },
		"duplicate key": func(l string) string { return strings.Replace(l, `{"v":2,`, `{"v":2,"record_id":"zzz",`, 1) },
		"version":       func(l string) string { return strings.Replace(l, `{"v":2,`, `{"v":1,`, 1) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "j.jsonl")
			write3(t, e, path)
			ls := lines(t, path)
			edited := edit(string(ls[2]))
			if edited == string(ls[2]) {
				t.Fatal("test setup: nothing edited")
			}
			ls[2] = []byte(edited)
			rewrite(t, path, ls)
			if _, err := openE(e, path, nil); err == nil {
				t.Fatalf("journal with edited tail (%s) opened", name)
			}
		})
	}
}

// Version 1 journals (written before v2) still open, and a v2 envelope
// continues them; a v1 envelope after v2 does not open.
func TestJournalV1ThenV2(t *testing.T) {
	e := setup(t)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	// A v1 envelope as earlier builds wrote it.
	env := &Envelope{V: 1, Type: "continuation", DomainID: e.domain, Seq: 1, RecordID: "a",
		Parent: GenesisParent(e.domain, "continuation"), Payload: json.RawMessage(`{"v":"a"}`), KeyRef: e.signer.Ref()}
	env.Sig = hex.EncodeToString(ed25519.Sign(e.signer.priv, signingPayload(env)))
	v1line, _ := json.Marshal(env)
	_ = os.WriteFile(path, append(v1line, '\n'), 0o600)
	j, err := openE(e, path, nil)
	if err != nil {
		t.Fatalf("v1 journal: %v", err)
	}
	if _, _, err := j.Append("continuation", "b", map[string]string{"v": "b"}, nil); err != nil {
		t.Fatal(err)
	}
	seq, tip := j.Tip()
	j.Close()
	if _, err := openE(e, path, nil); err != nil {
		t.Fatalf("v1 then v2: %v", err)
	}
	// Append a validly signed v1 envelope after the v2 one.
	env2 := &Envelope{V: 1, Type: "continuation", DomainID: e.domain, Seq: seq + 1, RecordID: "c",
		Parent: tip, Payload: json.RawMessage(`{"v":"c"}`), KeyRef: e.signer.Ref()}
	env2.Sig = hex.EncodeToString(ed25519.Sign(e.signer.priv, signingPayload(env2)))
	l, _ := json.Marshal(env2)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write(append(l, '\n'))
	f.Close()
	if _, err := openE(e, path, nil); err == nil || !strings.Contains(err.Error(), "v1 envelope after v2") {
		t.Fatalf("v1 after v2 opened: %v", err)
	}
}

// G-07: an envelope signed by a key after it was revoked does not open;
// envelopes it signed before still do.
func TestJournalRespectsKeyRevocation(t *testing.T) {
	e := setup(t)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	write3(t, e, path)
	revokedAt := time.Now()
	bound := func(gw, kid string) (time.Time, bool) { return revokedAt, gw == "gw1" && kid == "k1" }
	if _, err := openE(e, path, bound); err != nil {
		t.Fatalf("records before revocation must open: %v", err)
	}
	time.Sleep(time.Millisecond)
	j, err := openE(e, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = j.Append("continuation", "d", map[string]string{"v": "d"}, nil) // the stolen key keeps signing
	j.Close()
	if _, err := openE(e, path, bound); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("record signed after revocation opened: %v", err)
	}
}

// A complete line that fails the strict decode is corruption, never a torn
// write to be cut off.
func TestStrictFailureIsNotTornTail(t *testing.T) {
	e := setup(t)
	path := filepath.Join(t.TempDir(), "j.jsonl")
	write3(t, e, path)
	data, _ := os.ReadFile(path)
	_ = os.WriteFile(path, append(data, []byte(`{"v":2,"bogus":1}`)...), 0o600)
	if _, err := openE(e, path, nil); err == nil {
		t.Fatal("a complete but invalid final line was treated as torn")
	}
	after, _ := os.ReadFile(path)
	if len(after) <= len(data) {
		t.Fatal("the line was cut off")
	}
}
