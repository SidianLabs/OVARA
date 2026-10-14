package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

func TestDoctor_Upstream(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, "")
	}
	// nothing configured, nothing in the environment: nothing to say
	if out := auditUpstream(dir, &config.Config{}); len(out) != 0 {
		t.Fatalf("%v", out)
	}
	// a proxy in the shell that proxy.json does not know about
	t.Setenv("HTTPS_PROXY", "http://corp.example:3128")
	if out := statuses(auditUpstream(dir, &config.Config{})); out["upstream proxy"] != "WARN" {
		t.Fatalf("%v", out)
	}
	// broken settings fail
	out := auditUpstream(dir, &config.Config{UpstreamProxy: "corp.example:3128", UpstreamCABundle: "missing.pem"})
	if st := statuses(out); st["upstream proxy"] != "FAIL" || st["upstream CA bundle"] != "FAIL" {
		t.Fatalf("%v", out)
	}
	// good settings pass, and the credentials in the URL are not printed
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(dir, "corp-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	out = auditUpstream(dir, &config.Config{UpstreamProxy: "http://me:secret@corp.example:3128", UpstreamCABundle: "corp-ca.pem"})
	if st := statuses(out); st["upstream proxy"] != "PASS" || st["upstream CA bundle"] != "PASS" {
		t.Fatalf("%v", out)
	}
	for _, c := range out {
		if strings.Contains(c.detail, "secret") {
			t.Fatalf("the proxy password is printed: %v", c)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "corp-ca.pem"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := statuses(auditUpstream(dir, &config.Config{UpstreamCABundle: "corp-ca.pem"})); st["upstream CA bundle"] != "FAIL" {
		t.Fatalf("%v", st)
	}
}
