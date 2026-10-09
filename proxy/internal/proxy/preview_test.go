package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func req(t *testing.T, method, url, ctype, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	return r
}

func TestRedactPreview_HidesCredentialShapes(t *testing.T) {
	for _, secret := range []string{
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"sk-proj-abcdefghijklmnopqrstuvwxyz012345",
		"AKIAIOSFODNN7EXAMPLE",
		"xoxb-1234567890-abcdefghij",
		"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
		"aGVsbG8gdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2Igd2l0aCBubyBzcGFjZXM",
	} {
		got := redactPreview("data=" + secret + " end")
		if strings.Contains(got, secret) {
			t.Errorf("secret survived redaction: %q -> %q", secret, got)
		}
	}
	got := redactPreview(`{"user":"ana","password":"hunter2hunter2","note":"hi"}`)
	if strings.Contains(got, "hunter2") || !strings.Contains(got, `"user":"ana"`) || !strings.Contains(got, "hi") {
		t.Errorf("named secret not redacted, or ordinary fields lost: %s", got)
	}
	if got := redactPreview("q=golang+generics&page=2"); got != "q=golang+generics&page=2" {
		t.Errorf("ordinary query was altered: %q", got)
	}
}

func TestRequestContext_QueryBodyAndLimits(t *testing.T) {
	r := req(t, "POST", "https://x.example/api?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789&q=hello", "application/json", `{"msg":"hello","password":"p4ssw0rdp4ss"}`)
	c := requestContext(r)
	if strings.Contains(c["query"], "ghp_") || !strings.Contains(c["query"], "q=hello") {
		t.Errorf("query not redacted properly: %q", c["query"])
	}
	if c["body_bytes"] == "" || c["content_type"] != "application/json" {
		t.Errorf("size/type missing: %v", c)
	}
	if !strings.Contains(c["body_preview"], `"msg":"hello"`) || strings.Contains(c["body_preview"], "p4ssw0rd") {
		t.Errorf("body preview wrong: %q", c["body_preview"])
	}

	// A big text body: previewed up to the cap and marked as cut.
	big := strings.Repeat("hello world ", 500)
	c = requestContext(req(t, "POST", "https://x.example/", "text/plain", big))
	if len(c["body_preview"]) > maxPreviewBody+16 || !strings.HasSuffix(c["body_preview"], "…") {
		t.Errorf("large preview not bounded/marked: %d %q", len(c["body_preview"]), c["body_preview"][len(c["body_preview"])-10:])
	}
	if c["body_bytes"] != "6000" {
		t.Errorf("body size = %q, want 6000", c["body_bytes"])
	}
}

func TestRequestContext_NeverPreviewsBinaryOrHugeBodies(t *testing.T) {
	bin := string([]byte{0x00, 0x01, 0xff, 0xfe, 0x80})
	if c := requestContext(req(t, "POST", "https://x/", "application/octet-stream", bin)); c["body_preview"] != "" {
		t.Errorf("binary body was previewed: %q", c["body_preview"])
	}
	if c := requestContext(req(t, "POST", "https://x/", "text/plain", bin)); c["body_preview"] != "" {
		t.Errorf("invalid UTF-8 was previewed: %q", c["body_preview"])
	}
	r := req(t, "POST", "https://x/", "text/plain", "x")
	r.ContentLength = maxPeekBodySize + 1
	if c := requestContext(r); c["body_preview"] != "" {
		t.Error("a body over the peek limit must not even be read")
	}
	if c := requestContext(req(t, "GET", "https://x.example/plain", "", "")); c != nil {
		t.Errorf("a request with nothing to show should produce no context, got %v", c)
	}
}

// Looking at the body must not consume it: the upstream has to receive every byte.
func TestRequestContext_LeavesTheBodyIntact(t *testing.T) {
	payload := strings.Repeat(`{"k":"value"},`, 200)
	r := req(t, "POST", "https://x.example/", "application/json", payload)
	_ = requestContext(r)
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != payload {
		t.Fatalf("body altered by the preview: err=%v len=%d want %d", err, len(got), len(payload))
	}
}

// End to end: the gateway receives the preview as metadata, and the upstream
// still gets the complete request.
func TestPreviewReachesTheGatewayAndTheUpstreamStillGetsTheBody(t *testing.T) {
	var gotMeta string
	var upstreamBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		io.WriteString(w, "ok")
	}))
	defer up.Close()

	srv, _, _ := newScripted(t, "allow")
	srv.gw = capturingGateway(t, &gotMeta)
	payload := `{"hello":"world","pad":"` + strings.Repeat("z", 800) + `"}`
	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("POST", up.URL+"/x?a=1", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, r)

	if upstreamBody != payload {
		t.Fatalf("upstream received %d bytes, want %d", len(upstreamBody), len(payload))
	}
	for _, want := range []string{"proxy_context", `"query":"a=1"`, "body_bytes", "hello"} {
		if !strings.Contains(gotMeta, want) {
			t.Errorf("gateway metadata is missing %q: %s", want, gotMeta)
		}
	}
}
