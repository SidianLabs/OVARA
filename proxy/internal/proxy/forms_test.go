package proxy

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

// A browser agent's form POST is shown field by field, with the page it
// was on; passwords and credential-shaped values are masked.

func heldFor(t *testing.T, r *http.Request) *heldBody {
	t.Helper()
	hb, err := holdBody(r, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hb.close)
	return hb
}

func TestRequestContext_FormFieldsAndPage(t *testing.T) {
	body := "username=alice&password=hunter2&remember=on&note=hello+world&api=ghp_" + strings.Repeat("b", 36)
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.com/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://app.example.com/login?next=/admin&token=abc")
	hb := heldFor(t, r)
	ctx := requestContext(r, hb)
	if ctx["form"] != "username=alice, password=[masked], remember=on, note=hello world, api=[REDACTED]" && !strings.HasPrefix(ctx["form"], "username=alice, password=[masked], remember=on, note=hello world, api=") {
		t.Fatalf("form: %q", ctx["form"])
	}
	if strings.Contains(ctx["form"], "hunter2") || strings.Contains(ctx["form"], "ghp_bbbb") {
		t.Fatalf("a secret is shown: %q", ctx["form"])
	}
	if ctx["from_page"] != "https://app.example.com/login" {
		t.Fatalf("from_page: %q (the query must go)", ctx["from_page"])
	}
	if !strings.Contains(ctx["warning"], "masked below") {
		t.Fatalf("warning: %q", ctx["warning"])
	}
	if ctx["body_sha256"] == "" || ctx["body_preview"] == "" {
		t.Fatalf("the raw evidence must stay: %v", ctx)
	}
}

func TestRequestContext_MultipartUploads(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("title", "Q3 report")
	_ = mw.WriteField("card_number", "4111111111111111")
	fw, _ := mw.CreateFormFile("attachment", "report.pdf")
	_, _ = fw.Write([]byte("%PDF-1.4 hello"))
	_ = mw.Close()
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.com/upload", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "https://app.example.com")
	hb := heldFor(t, r)
	ctx := requestContext(r, hb)
	if ctx["form"] != "title=Q3 report, card_number=[masked]" {
		t.Fatalf("form: %q", ctx["form"])
	}
	if !strings.HasPrefix(ctx["uploads"], "report.pdf (") || !strings.Contains(ctx["uploads"], "14 bytes)") {
		t.Fatalf("uploads: %q", ctx["uploads"])
	}
	if ctx["from_page"] != "https://app.example.com" {
		t.Fatalf("from_page: %q", ctx["from_page"])
	}
}

func TestRequestContext_FormTooLargeIsNamed(t *testing.T) {
	body := "a=" + strings.Repeat("x", maxFormParse+10)
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.com/big", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hb := heldFor(t, r)
	ctx := requestContext(r, hb)
	if !strings.HasPrefix(ctx["form"], "form too large to list") {
		t.Fatalf("form: %q", ctx["form"])
	}
	// A JSON body is not a form.
	r2, _ := http.NewRequest(http.MethodPost, "https://app.example.com/api", strings.NewReader(`{"a":1}`))
	r2.Header.Set("Content-Type", "application/json")
	if ctx := requestContext(r2, heldFor(t, r2)); ctx["form"] != "" || ctx["uploads"] != "" {
		t.Fatalf("json listed as a form: %v", ctx)
	}
}
