package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"ovara.runtime.gateway/internal/anchor"
)

// G-08: the reset token comes from an owner-only file or the environment,
// never argv, and is compared in constant time.
func TestOperatorTokenSources(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	os.WriteFile(f, []byte("s3cret\n"), 0o600)
	if tok, err := loadOperatorToken(f); err != nil || tok != "s3cret" {
		t.Fatalf("file: %q %v", tok, err)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(f, 0o644)
		if _, err := loadOperatorToken(f); err == nil {
			t.Fatal("a token file other users can read was accepted")
		}
	}
	t.Setenv(operatorTokenEnv, "from-env")
	if tok, err := loadOperatorToken(""); err != nil || tok != "from-env" {
		t.Fatalf("env: %q %v", tok, err)
	}
	if operatorTokenOK("", "") || operatorTokenOK("abc", "ab") || !operatorTokenOK("abc", "abc") {
		t.Fatal("token comparison")
	}
}

func TestResetNeedsToken(t *testing.T) {
	st, err := anchor.OpenStore(filepath.Join(t.TempDir(), "o.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, c := range []struct {
		configured, sent string
		want             int
	}{
		{"", "", 498}, {"tok", "", 498}, {"tok", "tok2", 498}, {"tok", "to", 498},
	} {
		srv := httptest.NewServer(newHandler(st, c.configured))
		req, _ := http.NewRequest("POST", srv.URL+"/v1/anchor/d1/reset", nil)
		req.Header.Set("X-Operator-Token", c.sent)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != c.want {
			t.Errorf("configured %q sent %q: %d, want %d", c.configured, c.sent, resp.StatusCode, c.want)
		}
	}
	// The right token gets past the check (the store then answers for the
	// unregistered domain).
	srv := httptest.NewServer(newHandler(st, "tok"))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/anchor/d1/reset", nil)
	req.Header.Set("X-Operator-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 498 {
		t.Fatal("the right token was rejected")
	}
}
