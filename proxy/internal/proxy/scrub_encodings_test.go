package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CR-05: encoded and case-changed reflections, and a reflection in a
// header NAME, are scrubbed.
func TestEncodedReflectionsScrubbed(t *testing.T) {
	const tok = "sk-live-SECRET-123"
	enc := func(s string) []string {
		var out []string
		for _, pre := range []string{"", "a", "ab"} {
			out = append(out,
				base64.StdEncoding.EncodeToString([]byte(pre+s+"!")),
				base64.RawURLEncoding.EncodeToString([]byte(pre+s)),
			)
		}
		return append(out, hex.EncodeToString([]byte(s)), strings.ToUpper(hex.EncodeToString([]byte(s))),
			strings.ToUpper(s), strings.ToLower(s))
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("X-"+v, "1")
		w.Header().Set("X-B64", base64.StdEncoding.EncodeToString([]byte(r.Header.Get("Authorization"))))
		_, _ = io.WriteString(w, strings.Join(enc(v), "\n"))
	}))
	defer up.Close()
	f := credFixture(t, up)
	resp, b := tunnelReq(t, f.srv, up, f.ca, "GET", "/x", nil) //nolint:bodyclose // the helper reads and closes the body
	for _, e := range enc(tok) {
		if strings.Contains(string(b), e) {
			t.Errorf("encoded spelling %q reached the agent", e)
		}
	}
	for k, vv := range resp.Header {
		if strings.Contains(strings.ToLower(k), "secret") {
			t.Errorf("header name carrying the secret reached the agent: %q", k)
		}
		for _, v := range vv {
			if v == base64.StdEncoding.EncodeToString([]byte(testSecret)) {
				t.Errorf("base64 header value reached the agent: %s=%q", k, v)
			}
		}
	}
}

// CR-03: signed URLs minted from the credential (a redirect to a presigned
// download, a JSON link field) reach the agent with the signature redacted.
func TestDerivedSignedURLsRedacted(t *testing.T) {
	const loc = "https://bucket.s3.amazonaws.com/a.tgz?X-Amz-Credential=AKIAXXX%2F2026&X-Amz-Signature=deadbeefcafe&X-Amz-Expires=300"
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/archive" {
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"download_url":"https://codeload.example.com/x.zip?token=AABBCCDDEEFF","sas":"https://a.blob.core.windows.net/c/b?sv=2024&sp=r&sig=c2lnbmF0dXJl%3D","esc":"https://x.example/y?a=1&access_token=zzz111"}`)
	}))
	defer up.Close()
	f := credFixture(t, up)
	resp, _ := tunnelReq(t, f.srv, up, f.ca, "GET", "/archive", nil) //nolint:bodyclose // the helper reads and closes the body
	got := resp.Header.Get("Location")
	if strings.Contains(got, "deadbeefcafe") || strings.Contains(got, "AKIAXXX") {
		t.Fatalf("signed Location reached the agent: %q", got)
	}
	if !strings.Contains(got, "X-Amz-Expires=300") || !strings.Contains(got, "X-Amz-Signature=[REDACTED]") {
		t.Fatalf("Location rewritten badly: %q", got)
	}
	_, b := tunnelReq(t, f.srv, up, f.ca, "GET", "/json", nil) //nolint:bodyclose // the helper reads and closes the body
	for _, s := range []string{"AABBCCDDEEFF", "c2lnbmF0dXJl", "zzz111"} {
		if strings.Contains(string(b), s) {
			t.Errorf("signed value %s reached the agent: %s", s, b)
		}
	}
	if !strings.Contains(string(b), "sv=2024&sp=r&sig=[REDACTED]") {
		t.Errorf("unexpected body: %s", b)
	}
}

// The signed-parameter pass holds keys and values that straddle reads.
func TestSignedParamReader_Boundary(t *testing.T) {
	body := `{"a":"https://x/y?X-Amz-Security-Token=` + strings.Repeat("Q", 300) + `&n=1","b":"https://x/z?sig=abc"} tail ?token=end`
	out, err := io.ReadAll(newSignedParamReader(&slowReader{s: body}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"https://x/y?X-Amz-Security-Token=[REDACTED]&n=1","b":"https://x/z?sig=[REDACTED]"} tail ?token=[REDACTED]`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	plain := `{"q":"?tokens=1&designature=2&x=token"}`
	if out, _ := io.ReadAll(newSignedParamReader(&slowReader{s: plain})); string(out) != plain {
		t.Fatalf("unrelated parameters changed: %s", out)
	}
}

// CR-11: only exact, known non-secret header names skip scrubbing.
func TestVersionLikeHeaderStillScrubbed(t *testing.T) {
	if got := secretTargets("X-Api-Version-Key", "abcdefgh12345"); len(got) == 0 {
		t.Fatal("a secret in a header whose name contains \"version\" was not scrubbed")
	}
	if got := secretTargets("anthropic-version", "2023-06-01"); len(got) != 0 {
		t.Fatalf("anthropic-version must not be scrubbed: %q", got)
	}
}

func TestScrubReader_CaseInsensitiveStraddle(t *testing.T) {
	body := "x " + strings.ToUpper("bearer ghp_secret123") + " y"
	out, _ := io.ReadAll(newScrubReader(&slowReader{s: body}, [][]byte{[]byte("Bearer ghp_secret123")}))
	if string(out) != "x [REDACTED] y" {
		t.Fatalf("got %q", out)
	}
}
