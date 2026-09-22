package record

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type envT struct {
	signer  *Signer
	resolve ResolveFunc
	domain  string
	dir     string
}

func setup(t *testing.T) *envT {
	t.Helper()
	priv, pub := newKey()
	// domain derives from identity — different key, different domain
	sum := sha256.Sum256(pub)
	domain := hex.EncodeToString(sum[:])
	signer := NewSigner(priv, domain, "gw1", "k1")
	return &envT{
		signer: signer,
		domain: domain,
		dir:    t.TempDir(),
		resolve: func(gw, kid string) (ed25519.PublicKey, error) {
			if gw == "gw1" && kid == "k1" {
				return pub, nil
			}
			return nil, errNoKey
		},
	}
}

var errNoKey = errTest("no key")

type errTest string

func (e errTest) Error() string { return string(e) }

func newKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return priv, pub
}

func write3(t *testing.T, e *envT, path string) (uint64, string) {
	t.Helper()
	j, err := Open("continuation", path, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, _, err := j.Append("continuation", id, map[string]string{"v": id}, nil); err != nil {
			t.Fatal(err)
		}
	}
	seq, tip := j.Tip()
	j.Close()
	return seq, tip
}

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		out = append(out, []byte(l))
	}
	return out
}

func writeLines(t *testing.T, path string, ls [][]byte) {
	t.Helper()
	var buf []byte
	for _, l := range ls {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

func foldOK(t *testing.T, e *envT, path string, floor Floor) *Journal {
	t.Helper()
	j, _ := Open("continuation", path, e.domain, e.signer, e.resolve, floor, func(*Envelope) error { return nil })
	return j
}

func TestRoundTrip(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "c.journal")
	write3(t, e, p)
	var seen []string
	j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(env *Envelope) error {
		seen = append(seen, env.RecordID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0] != "a" || seen[2] != "c" {
		t.Fatalf("seen %v", seen)
	}
	if s, _ := j.Tip(); s != 3 {
		t.Fatalf("seq %d", s)
	}
}

func TestFoldRejections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(ls [][]byte) [][]byte
	}{
		{"FOLD-01 reorder", func(ls [][]byte) [][]byte { ls[0], ls[2] = ls[2], ls[0]; return ls }},
		{"FOLD-02 duplicate", func(ls [][]byte) [][]byte { return append(ls[:1], append([][]byte{ls[0]}, ls[1:]...)...) }},
		{"FOLD-03 delete-middle", func(ls [][]byte) [][]byte { return append(ls[:1], ls[2:]...) }},
		// NOTE: delete-tail passes the fold without a floor by design —
		// a truncated journal is a valid shorter journal. Truncation
		// detection is the tip-ledger's job: see TestFloorTruncation.
		{"FOLD-05 modified-parent", func(ls [][]byte) [][]byte {
			var env Envelope
			json.Unmarshal(ls[1], &env)
			env.Parent = strings.Repeat("0", 64)
			b, _ := json.Marshal(env)
			ls[1] = b
			return ls
		}},
		{"FOLD-06 modified-payload", func(ls [][]byte) [][]byte {
			var env Envelope
			json.Unmarshal(ls[0], &env)
			env.Payload = json.RawMessage(`{"v":"forged"}`)
			b, _ := json.Marshal(env)
			ls[0] = b
			return ls
		}},
		{"FOLD-07 modified-seq", func(ls [][]byte) [][]byte {
			var env Envelope
			json.Unmarshal(ls[1], &env)
			env.Seq = 99
			b, _ := json.Marshal(env)
			ls[1] = b
			return ls
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			p := filepath.Join(e.dir, "c.journal")
			write3(t, e, p)
			writeLines(t, p, tc.mut(lines(t, p)))
			j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil })
			if err == nil {
				j.Close()
				t.Fatalf("%s: fold accepted mutated journal", tc.name)
			}
		})
	}
}

func TestDomainTransplant(t *testing.T) {
	e := setup(t)
	other := setup(t) // different key → different domain
	if e.domain == other.domain {
		t.Fatal("domains must differ")
	}
	p := filepath.Join(e.dir, "c.journal")
	write3(t, e, p)
	// fold under a different domain — transplant attempt must fail
	// at genesis parent (and at domain_id check)
	if j, err := Open("continuation", p, other.domain, other.signer, e.resolve, Floor{}, func(*Envelope) error { return nil }); err == nil {
		j.Close()
		t.Fatal("cross-domain journal accepted")
	}
}

func TestFloorTruncation(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "c.journal")
	seq, tip := write3(t, e, p)
	if seq != 3 {
		t.Fatalf("seq %d", seq)
	}
	floor := Floor{Known: true, Seq: 3, Hash: tip}
	// consistent floor → ok
	j := foldOK(t, e, p, floor)
	if j == nil {
		t.Fatal("floor at tip rejected")
	}
	j.Close()
	// truncate below floor → refuse
	writeLines(t, p, lines(t, p)[:2])
	if j, err := Open("continuation", p, e.domain, e.signer, e.resolve, floor, func(*Envelope) error { return nil }); err == nil {
		j.Close()
		t.Fatal("truncated journal below ledger floor accepted")
	}
	// missing ledgered file → refuse
	os.Remove(p)
	if j, err := Open("continuation", p, e.domain, e.signer, e.resolve, floor, func(*Envelope) error { return nil }); err == nil {
		j.Close()
		t.Fatal("deleted ledgered journal accepted")
	}
}

func TestTornTail(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "c.journal")
	write3(t, e, p)
	// simulate torn partial write — no trailing newline
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"v":1,"type":"continuati`)
	f.Close()
	j := foldOK(t, e, p, Floor{})
	if j == nil {
		t.Fatal("torn tail not tolerated")
	}
	if s, _ := j.Tip(); s != 3 {
		t.Fatalf("tip %d after torn tail", s)
	}
	j.Close()
	// non-JSON garbage mid-file must fail (not a torn tail)
	ls := lines(t, p)
	mid := append(ls[:1], append([][]byte{[]byte(`{"not-json`)}, ls[1:]...)...)
	writeLines(t, p, mid)
	if j, err := Open("continuation", p, e.domain, e.signer, e.resolve, Floor{}, func(*Envelope) error { return nil }); err == nil {
		j.Close()
		t.Fatal("mid-file anomaly accepted")
	}
}

func TestSealedFile(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "state.json")
	payload := json.RawMessage(`{"x":1}`)
	sealed, err := SealFile("idregistry", e.signer, payload, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, sealed, 0o600)
	got, seq, _, err := OpenSealedFile("idregistry", p, e.domain, e.resolve, Floor{})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 || string(got) != `{"x":1}` {
		t.Fatalf("seq=%d data=%s", seq, got)
	}
	// tampered payload
	var sf SealedFile
	json.Unmarshal(sealed, &sf)
	sf.Data = json.RawMessage(`{"x":2}`)
	tampered, _ := json.Marshal(sf)
	os.WriteFile(p, tampered, 0o600)
	if _, _, _, err := OpenSealedFile("idregistry", p, e.domain, e.resolve, Floor{}); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// wrong store name (transplant)
	sealed2, _ := SealFile("other", e.signer, payload, nil, 0)
	os.WriteFile(p, sealed2, 0o600)
	if _, _, _, err := OpenSealedFile("idregistry", p, e.domain, e.resolve, Floor{}); err == nil {
		t.Fatal("cross-store sealed file accepted")
	}
	// seq regression below floor
	sealed3, _ := SealFile("idregistry", e.signer, payload, nil, 0)
	os.WriteFile(p, sealed3, 0o600)
	floor := Floor{Known: true, Seq: 5, Hash: "irrelevant"}
	if _, _, _, err := OpenSealedFile("idregistry", p, e.domain, e.resolve, floor); err == nil {
		t.Fatal("file_seq regression below floor accepted")
	}
}
