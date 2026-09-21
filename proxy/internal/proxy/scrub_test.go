package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ovara.proxy/internal/creds"
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

// Reflector via trailers: an upstream that echoes the injected secret in
// a response TRAILER must not hand it to the agent — trailers get the
// same scrub as headers and body (RC1 review finding).
func TestTrailerSecretScrubbed(t *testing.T) {
	secret := "Bearer trailer-secret-xyz"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Echo")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
	}))
	defer upstream.Close()

	f := newFixture(t, "allow", []creds.Binding{
		{Host: mustHost(t, upstream.URL), Headers: map[string]string{"Authorization": secret}},
	})
	req, _ := http.NewRequest("GET", upstream.URL+"/x", nil)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)

	trailer := rec.Result().Trailer.Get("X-Echo")
	if trailer == secret {
		t.Fatalf("injected secret leaked via trailer: %q", trailer)
	}
	if trailer != "[REDACTED]" && secret != "" {
		// empty trailer is also acceptable (no echo), but raw secret is not
		if trailer != "" {
			t.Fatalf("trailer not scrubbed: %q", trailer)
		}
	}
}
