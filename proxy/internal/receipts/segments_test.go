package receipts

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func recordN(t *testing.T, c *Chain, n int, durable bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Append(Entry{Method: "GET", URL: "https://example.org/a/fairly/long/path/to/make/receipts/bigger", Decision: "allow", Status: 200}, durable); err != nil {
			t.Fatal(err)
		}
	}
}

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestSegments_RotateVerifyRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	c.SetRotation(4000)
	recordN(t, c, 200, true) // durable appends must survive a rotation
	segs := SegmentFiles(path)
	if len(segs) < 3 {
		t.Fatalf("expected several segments, got %v", segs)
	}
	if got := Count(path); got != 200 {
		t.Fatalf("count %d", got)
	}
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 200 {
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
	recordN(t, c2, 50, false)
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 250 {
		t.Fatalf("verify after restart: %+v", res)
	}
}

func TestSegments_TamperAndGaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	c.SetRotation(4000)
	recordN(t, c, 120, false)
	segs := SegmentFiles(path)
	if len(segs) < 3 {
		t.Fatalf("segments %v", segs)
	}

	// edit a receipt inside a compressed segment
	orig, _ := os.ReadFile(segs[1])
	edited := bytes.Replace(gunzipFile(t, segs[1]), []byte("example.org"), []byte("evil.example"), 1)
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

	// a segment missing in the middle, or the oldest one moved away, is a
	// cut: the chain fails, it does not verify "from what is left"
	for _, gone := range []string{segs[1], segs[0]} {
		keep, _ := os.ReadFile(gone)
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		res := VerifyFile(path, pub)
		if res.Valid || !strings.Contains(res.Reason, "missing") {
			t.Fatalf("%s removed: %+v", filepath.Base(gone), res)
		}
		if err := os.WriteFile(gone, keep, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 120 {
		t.Fatalf("restored: %+v", res)
	}
}

// A crash between the segment being written and the current file being
// emptied leaves the current file a copy of the segment. The next open
// finishes the rotation instead of seeing every receipt of it twice.
func TestSegments_InterruptedRotationIsFinished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	c.SetRotation(4000)
	recordN(t, c, 60, false)
	segs := SegmentFiles(path)
	if len(segs) == 0 {
		t.Fatal("no segment")
	}
	if err := os.WriteFile(path, gunzipFile(t, segs[len(segs)-1]), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := VerifyFile(path, pub); res.Valid {
		t.Fatal("a chain holding its last segment twice verified")
	}
	c2, _ := newSegChain(t, dir)
	if st, _ := os.Stat(path); st.Size() != 0 {
		t.Fatal("the interrupted rotation was not finished")
	}
	if res := VerifyFile(path, pub); !res.Valid {
		t.Fatalf("after the repair: %+v", res)
	}
	if n := Count(path); c2.seq != n || n == 0 {
		t.Fatalf("seq %d, count %d", c2.seq, n)
	}
	recordN(t, c2, 5, true)
	if res := VerifyFile(path, pub); !res.Valid {
		t.Fatalf("appending after the repair: %+v", res)
	}
}

func TestSegments_NoRotationByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	c, pub := newSegChain(t, dir)
	recordN(t, c, 50, false)
	if segs := SegmentFiles(path); len(segs) != 0 {
		t.Fatalf("rotated without SetRotation: %v", segs)
	}
	if res := VerifyFile(path, pub); !res.Valid || res.Total != 50 {
		t.Fatalf("%+v", res)
	}
}
