package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeV1 appends a receipt the way builds before v2 did: pipe-joined
// canonical form, "sig_v1:", no version field.
func writeV1(t *testing.T, path string, key ed25519.PrivateKey, prev, method, url string) string {
	t.Helper()
	r := &Receipt{ReceiptID: "rcpt_" + newID(), SessionID: "s1", Timestamp: time.Now().UTC(),
		Method: method, URL: url, Decision: "allow", Status: 200, PrevHash: prev}
	r.Signature = sigV1Prefix + hex.EncodeToString(ed25519.Sign(key, []byte(r.canonicalV1())))
	line, _ := json.Marshal(r)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
	return hashLine(line)
}

func keyPair(t *testing.T, dir string) (keyFile, pubFile string, key ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keyFile, pubFile = filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub")
	_ = os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0o600)
	_ = os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)), 0o600)
	return keyFile, pubFile, key
}

func mustRing(t *testing.T, pubFile string) *KeyRing {
	t.Helper()
	ring, err := LoadKeyRing(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// An existing v1 log keeps verifying, and a v2 chain continues it.
func TestV1ThenV2Verifies(t *testing.T) {
	dir := t.TempDir()
	keyFile, pubFile, key := keyPair(t, dir)
	path := filepath.Join(dir, "r.jsonl")
	h := writeV1(t, path, key, "", "GET", "https://a.example/1")
	writeV1(t, path, key, h, "GET", "https://a.example/2")
	c, err := LoadOrCreate(path, keyFile, pubFile)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(Entry{Method: "POST", URL: "https://a.example/3", Decision: "allow", Reasons: []string{"policy_allow"}, Rule: "allow posts"}, true); err != nil {
		t.Fatal(err)
	}
	res := VerifyFileKeys(path, mustRing(t, pubFile))
	if !res.Valid || res.Total != 3 || res.V1 != 2 {
		t.Fatalf("v1 then v2: %+v", res)
	}
	// v1 after v2 is refused.
	lines := readLines(t, path)
	_ = os.WriteFile(path, append(append(append([]byte{}, lines[0]...), '\n'), append(lines[2], '\n')...), 0o600)
	if res := VerifyFile(path, key.Public().(ed25519.PublicKey)); res.Valid {
		t.Fatalf("broken link must fail: %+v", res)
	}
}

// The v1 form is ambiguous: moving a "|" between method and url keeps the
// signature valid. v2 binds each field separately.
func TestV2CanonicalFormIsUnambiguous(t *testing.T) {
	a := &Receipt{V: 2, Method: "GET", URL: "x|y"}
	b := &Receipt{V: 2, Method: "GET|x", URL: "y"}
	if a.canonicalV1() != b.canonicalV1() {
		t.Fatal("expected the v1 form to collide (documents why v2 exists)")
	}
	if bytes.Equal(a.canonicalV2(), b.canonicalV2()) {
		t.Fatal("v2 canonical form collides")
	}
	if !bytes.HasPrefix(a.canonicalV2(), []byte("ovara-proxy-receipt-v2\n")) {
		t.Fatal("missing domain separator")
	}

	c, chainFile, pub := newChain(t)
	_, _ = c.Record("GET", "https://a.example/p|q", "allow", 200, "")
	tamper(t, chainFile, 0, func(r *Receipt) { r.Method, r.URL = "GET|https://a.example/p", "q" })
	if res := VerifyFile(chainFile, pub); res.Valid {
		t.Fatal("moving a pipe between fields must break the signature")
	}
}

// G-11: bytes outside the signature must not verify.
func TestExtraAndDuplicateKeysRejected(t *testing.T) {
	cases := map[string]func(line string) string{
		"extra key": func(l string) string {
			return strings.Replace(l, `{"v":2,`, `{"v":2,"note":"edited",`, 1)
		},
		"duplicate key": func(l string) string {
			return strings.Replace(l, `{"v":2,`, `{"v":2,"decision":"deny",`, 1)
		},
		"whitespace": func(l string) string { return strings.Replace(l, `{"v":2,`, `{"v": 2,`, 1) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c, chainFile, pub := newChain(t)
			_, _ = c.Record("GET", "https://a.example/", "allow", 200, "")
			_, _ = c.Record("GET", "https://a.example/", "allow", 200, "")
			orig := readLines(t, chainFile)
			// The tail is the interesting position: no later prev_hash
			// covers it, only its own signature and form.
			for _, i := range []int{0, 1} {
				lines := append([][]byte(nil), orig...)
				lines[i] = []byte(edit(string(lines[i])))
				_ = os.WriteFile(chainFile, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600)
				if res := VerifyFile(chainFile, pub); res.Valid || res.FailAt != i {
					t.Fatalf("%s at line %d: %+v", name, i, res)
				}
			}
		})
	}
	// v1 lines with v2-only fields carry unsigned data.
	dir := t.TempDir()
	_, pubFile, key := keyPair(t, dir)
	path := filepath.Join(dir, "r.jsonl")
	writeV1(t, path, key, "", "GET", "https://a.example/")
	line := readLines(t, path)[0]
	line = bytes.Replace(line, []byte(`"prev_hash"`), []byte(`"approver":"someone","prev_hash"`), 1)
	_ = os.WriteFile(path, append(line, '\n'), 0o600)
	if res := VerifyFileKeys(path, mustRing(t, pubFile)); res.Valid {
		t.Fatal("v1 receipt with unsigned v2 fields verified")
	}
}

// G-07: rotation closes the old key's window; revocation bounds a key.
func TestRotateAndRevoke(t *testing.T) {
	dir := t.TempDir()
	keyFile, pubFile, oldKey := keyPair(t, dir)
	path := filepath.Join(dir, "r.jsonl")
	c, err := LoadOrCreate(path, keyFile, pubFile)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Record("GET", "https://a.example/before", "allow", 200, "")
	c.Close()
	time.Sleep(2 * time.Millisecond)
	oldID, newID, err := RotateKey(keyFile, pubFile, time.Now())
	if err != nil || oldID == newID {
		t.Fatalf("rotate: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	c2, err := LoadOrCreate(path, keyFile, pubFile)
	if c2 != nil {
		t.Cleanup(func() { _ = c2.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c2.Record("GET", "https://a.example/after", "allow", 200, "")
	if res := VerifyFileKeys(path, mustRing(t, pubFile)); !res.Valid || res.Total != 2 {
		t.Fatalf("chain across a rotation: %+v", res)
	}
	// The retired key cannot be used to start the proxy again.
	_ = os.WriteFile(filepath.Join(dir, "old.key"), []byte(hex.EncodeToString(oldKey)), 0o600)
	if _, err := LoadOrCreate(path, filepath.Join(dir, "old.key"), pubFile); err == nil {
		t.Fatal("a rotated-out key must not start a chain")
	}
	// A receipt the old key signs after rotation fails verification.
	c3 := &Chain{key: oldKey, keyID: oldID, sessionID: "x", path: path, prevHash: c2.prevHash, seq: c2.seq}
	_, _ = c3.Record("GET", "https://a.example/forged", "allow", 200, "")
	res := VerifyFileKeys(path, mustRing(t, pubFile))
	if res.Valid || res.FailAt != 2 || !strings.Contains(res.Reason, "rotated out") {
		t.Fatalf("old key after rotation: %+v", res)
	}
	// Revoking the current key as of now: receipts it signed before stay
	// valid, later ones fail.
	lines := readLines(t, path)
	_ = os.WriteFile(path, append(bytes.Join(lines[:2], []byte("\n")), '\n'), 0o600)
	if _, err := RevokeKey(pubFile, newID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFileKeys(path, mustRing(t, pubFile)); !res.Valid {
		t.Fatalf("receipts before revocation must verify: %+v", res)
	}
	time.Sleep(2 * time.Millisecond)
	c4 := &Chain{key: mustLoadKey(t, keyFile), keyID: newID, sessionID: "y", path: path, prevHash: hashLine(lines[1]), seq: 2}
	_, _ = c4.Record("GET", "https://a.example/late", "allow", 200, "")
	if res := VerifyFileKeys(path, mustRing(t, pubFile)); res.Valid || !strings.Contains(res.Reason, "revoked") {
		t.Fatalf("receipt after revocation verified: %+v", res)
	}
	if _, err := LoadOrCreate(path, keyFile, pubFile); err == nil {
		t.Fatal("a revoked key must not start a chain")
	}
}

func mustLoadKey(t *testing.T, f string) ed25519.PrivateKey {
	k, err := loadKey(f)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// G-07: a missing key next to existing receipts is not silently replaced.
func TestMissingKeyWithReceiptsRefused(t *testing.T) {
	c, chainFile, _ := newChain(t)
	_, _ = c.Record("GET", "https://a.example/", "allow", 200, "")
	dir := filepath.Dir(chainFile)
	os.Remove(filepath.Join(dir, "receipts.key"))
	if _, err := LoadOrCreate(chainFile, filepath.Join(dir, "receipts.key"), filepath.Join(dir, "receipts.pub")); err == nil {
		t.Fatal("expected refusal to mint a new key over existing receipts")
	}
}

// Outcome receipts must close an attempt that is in the chain.
func TestOutcomeNeedsAttempt(t *testing.T) {
	c, chainFile, pub := newChain(t)
	a, err := c.Append(Entry{Method: "GET", URL: "https://a.example/", Decision: "allow", Phase: "attempt", Outcome: "sent"}, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Append(Entry{Method: "GET", URL: "https://a.example/", Decision: "allow", Status: 200, Phase: "outcome", AttemptID: a.ReceiptID}, false)
	if res := VerifyFile(chainFile, pub); !res.Valid {
		t.Fatalf("%+v", res)
	}
	_, _ = c.Append(Entry{Method: "GET", URL: "https://a.example/", Decision: "allow", Status: 200, Phase: "outcome", AttemptID: "rcpt_nope"}, false)
	if res := VerifyFile(chainFile, pub); res.Valid {
		t.Fatal("outcome without attempt verified")
	}
}

// A durable append is on disk when it returns; a failed write leaves no
// half line behind.
func TestDurableAppendAndTornWrite(t *testing.T) {
	c, chainFile, pub := newChain(t)
	if _, err := c.Append(Entry{Method: "GET", URL: "u", Decision: "allow", Phase: "attempt", Outcome: "sent"}, true); err != nil {
		t.Fatal(err)
	}
	if c.synced != 1 {
		t.Fatalf("durable append did not sync (synced=%d)", c.synced)
	}
	// Make the file handle unwritable: the append must fail cleanly.
	c.mu.Lock()
	c.f.Close()
	ro, _ := os.Open(chainFile)
	c.f = ro
	c.mu.Unlock()
	if _, err := c.Append(Entry{Method: "GET", URL: "u2", Decision: "allow"}, true); err == nil {
		t.Fatal("append on an unwritable file succeeded")
	}
	if res := VerifyFile(chainFile, pub); !res.Valid || res.Total != 1 {
		t.Fatalf("chain after failed append: %+v", res)
	}
}

func BenchmarkDurableAppend(b *testing.B) {
	dir := b.TempDir()
	c, err := LoadOrCreate(filepath.Join(dir, "r.jsonl"), filepath.Join(dir, "k"), filepath.Join(dir, "p"))
	if c != nil {
		b.Cleanup(func() { _ = c.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		b.Fatal(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.Append(Entry{Method: "GET", URL: "https://a.example/", Decision: "allow", Phase: "attempt", Outcome: "sent"}, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPlainAppend(b *testing.B) {
	dir := b.TempDir()
	c, err := LoadOrCreate(filepath.Join(dir, "r.jsonl"), filepath.Join(dir, "k"), filepath.Join(dir, "p"))
	if c != nil {
		b.Cleanup(func() { _ = c.Close() }) // Windows cannot remove an open file
	}
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, _ = c.Append(Entry{Method: "GET", URL: "https://a.example/", Decision: "allow"}, false)
	}
}
