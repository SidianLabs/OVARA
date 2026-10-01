package proxy

import (
	"io"
	"strings"
	"testing"
)

// slowReader feeds the body one byte at a time to force the worst-case
// boundary condition: every secret straddles multiple reads.
type slowReader struct{ s string }

func (r *slowReader) Read(p []byte) (int, error) {
	if len(r.s) == 0 {
		return 0, io.EOF
	}
	p[0] = r.s[0]
	r.s = r.s[1:]
	return 1, nil
}

func TestScrubReader_Boundary(t *testing.T) {
	body := `{"headers":{"Authorization":"Bearer ghp_secret123","X":"ok"},"tail":"Bearer ghp_secret123"}`
	r := newScrubReader(&slowReader{s: body}, [][]byte{[]byte("Bearer ghp_secret123")})
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ghp_secret123") {
		t.Fatalf("secret leaked in output: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED]") || !strings.Contains(string(out), `"X":"ok"`) {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestScrubReader_NoSecret(t *testing.T) {
	r := newScrubReader(strings.NewReader("plain body"), [][]byte{[]byte("x")})
	out, err := io.ReadAll(r)
	if err != nil || string(out) != "plain body" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}
