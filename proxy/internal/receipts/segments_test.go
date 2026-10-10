package receipts

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func newSegChain(t *testing.T, dir string) (*Chain, ed25519.PublicKey) {
	t.Helper()
	c, err := LoadOrCreate(filepath.Join(dir, "receipts.jsonl"), filepath.Join(dir, "r.key"), filepath.Join(dir, "r.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return c, c.key.Public().(ed25519.PublicKey)
}

func recordN(t *testing.T, c *Chain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Record("GET", "https://example.org/a/fairly/long/path/to/make/receipts/bigger", "allow", 200, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSegments_RotateVerifyRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	c.SetRotation(4000)
	recordN(t, c, 200)
	segs := Segments(path)
	if len(segs) < 3 {
		t.Fatalf("expected several segments, got %v", segs)
	}
	if got := Count(path); got != 200 {
		t.Fatalf("count %d", got)
	}
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 200 || res.Partial {
		t.Fatalf("verify across segments: %+v", res)
	}
	total, n := Size(path)
	if total <= 0 || n != len(segs) {
		t.Fatalf("size %d %d", total, n)
	}
	// restart right after a rotation: the current file is empty, the head
	// comes from the newest segment
	c.mu.Lock()
	err := c.rotateLocked()
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Size() != 0 {
		t.Fatal("current file not emptied")
	}
	c2, _ := newSegChain(t, dir)
	c2.SetRotation(4000)
	if c2.seq != 200 {
		t.Fatalf("seq after restart %d", c2.seq)
	}
	recordN(t, c2, 50)
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 250 {
		t.Fatalf("verify after restart: %+v", res)
	}
}

func TestSegments_TamperAndGaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	c.SetRotation(4000)
	recordN(t, c, 120)
	segs := Segments(path)
	if len(segs) < 3 {
		t.Fatalf("segments %v", segs)
	}

	// edit a receipt inside a compressed segment
	orig, _ := os.ReadFile(segs[1])
	zr, _ := gzip.NewReader(bytes.NewReader(orig))
	plain, _ := io.ReadAll(zr)
	edited := bytes.Replace(plain, []byte("example.org"), []byte("evil.example"), 1)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(edited)
	_ = zw.Close()
	if err := os.WriteFile(segs[1], buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFile(path, pub); res.Valid {
		t.Fatal("tampered segment verified")
	}
	if err := os.WriteFile(segs[1], orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// a segment missing in the middle breaks the chain
	mid, _ := os.ReadFile(segs[1])
	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFile(path, pub); res.Valid {
		t.Fatal("a gap in the middle verified")
	}
	if err := os.WriteFile(segs[1], mid, 0o600); err != nil {
		t.Fatal(err)
	}

	// the oldest segment moved away: the rest verifies, marked partial
	if err := os.Remove(segs[0]); err != nil {
		t.Fatal(err)
	}
	res := VerifyFile(path, pub)
	if !res.Valid || !res.Partial || res.Total >= 120 {
		t.Fatalf("oldest removed: %+v", res)
	}
}
