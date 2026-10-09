package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/config"
)

func newUI(t *testing.T, pend ...pendingApproval) (*fakeGateway, http.Handler) {
	t.Helper()
	f, c := newFake(t, pend...)
	_, chainFile, pubFile := writeChain(t)
	return f, (&uiServer{admin: c, pageToken: "tok", receiptsFile: chainFile, pubFile: pubFile}).handler()
}

func call(h http.Handler, method, path, host, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUI_Guards(t *testing.T) {
	_, h := newUI(t)
	cases := []struct {
		name, method, path, host, auth string
		want                           int
	}{
		{"page needs no token", "GET", "/", "127.0.0.1:9090", "", 200},
		{"api without token", "GET", "/api/pending", "127.0.0.1:9090", "", 401},
		{"api with wrong token", "GET", "/api/pending", "127.0.0.1:9090", "Bearer nope", 401},
		{"dns-rebound host", "GET", "/api/pending", "evil.example:9090", "Bearer tok", 403},
		{"rebound host, page too", "GET", "/", "evil.example", "", 403},
		{"approve via GET", "GET", "/api/approve/x", "127.0.0.1:9090", "Bearer tok", 405},
		{"localhost name ok", "GET", "/api/pending", "localhost:9090", "Bearer tok", 200},
		{"ipv6 loopback ok", "GET", "/api/pending", "[::1]:9090", "Bearer tok", 200},
	}
	for _, c := range cases {
		if got := call(h, c.method, c.path, c.host, c.auth).Code; got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
}

func TestUI_PageIsNotFramable(t *testing.T) {
	_, h := newUI(t)
	rec := call(h, "GET", "/", "127.0.0.1", "")
	if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("page can be framed (clickjacking): %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), "Waiting for you") {
		t.Fatal("embedded page not served")
	}
}

func TestUI_PendingApproveDenyActivity(t *testing.T) {
	f, h := newUI(t,
		pendingApproval{ApprovalID: "a1", ActionType: "http.request", Resource: "POST https://github.com/o/r.git/git-receive-pack refs/heads/main", CreatedAt: time.Now()},
		pendingApproval{ApprovalID: "a2", ActionType: "http.request", Resource: "DELETE https://api.github.com/x", CreatedAt: time.Now()})

	rec := call(h, "GET", "/api/pending", "127.0.0.1", "Bearer tok")
	var list []map[string]string
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 || list[0]["what"] != "push to refs/heads/main on github.com/o/r" {
		t.Fatalf("pending = %s", rec.Body.String())
	}
	if call(h, "POST", "/api/approve/a1", "127.0.0.1", "Bearer tok").Code != 200 ||
		call(h, "POST", "/api/deny/a2", "127.0.0.1", "Bearer tok").Code != 200 {
		t.Fatal("approve/deny failed")
	}
	if f.resolved["a1"] != "approve" || f.resolved["a2"] != "deny" {
		t.Fatalf("resolved = %v", f.resolved)
	}

	rec = call(h, "GET", "/api/activity", "127.0.0.1", "Bearer tok")
	var act activity
	if err := json.Unmarshal(rec.Body.Bytes(), &act); err != nil {
		t.Fatal(err)
	}
	if act.Total != 4 || !act.Checked || !act.Valid || len(act.Entries) != 4 {
		t.Fatalf("activity = %+v", act)
	}
}

func TestStartUI_RefusesNonLoopback(t *testing.T) {
	if _, err := startUI("0.0.0.0:9090", nil); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("want loopback error, got %v", err)
	}
	if url, err := startUI("off", nil); err != nil || url != "" {
		t.Fatalf("off: %q %v", url, err)
	}
}

// The browser link must never carry the operator token: the page gets its
// own random token that opens only the page's endpoints.
func TestUI_PageTokenIsNotTheOperatorToken(t *testing.T) {
	_, c := newFake(t)
	_, chainFile, pubFile := writeChain(t)
	h := (&uiServer{admin: c, pageToken: "page", receiptsFile: chainFile, pubFile: pubFile}).handler()
	if got := call(h, "GET", "/api/pending", "127.0.0.1", "Bearer "+c.token).Code; got != 401 {
		t.Fatalf("operator token opened the page API: %d", got)
	}
	if got := call(h, "GET", "/api/pending", "127.0.0.1", "Bearer page").Code; got != 200 {
		t.Fatalf("page token refused: %d", got)
	}
	empty := (&uiServer{admin: c, receiptsFile: chainFile, pubFile: pubFile}).handler()
	for _, auth := range []string{"", "Bearer ", "Bearer " + c.token} {
		if got := call(empty, "GET", "/api/pending", "127.0.0.1", auth).Code; got != 401 {
			t.Fatalf("server without a page token accepted %q: %d", auth, got)
		}
	}
}

func TestStartUI_LinkCarriesAFreshPageToken(t *testing.T) {
	const operator = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	cfgJSON := `{"server_port":"1","listen_addr":"127.0.0.1","operator_tokens":["` + operator + `"]}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	links := map[string]bool{}
	for i := 0; i < 2; i++ {
		url, err := startUI("127.0.0.1:0", &config.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(url, operator) {
			t.Fatalf("link carries the operator token: %s", url)
		}
		i := strings.Index(url, "/#t=")
		if i < 0 {
			t.Fatalf("link has no page token: %s", url)
		}
		tok := url[i+4:]
		if len(tok) != 64 || strings.Trim(tok, "0123456789abcdef") != "" {
			t.Fatalf("page token %q is not 32 random bytes in hex", tok)
		}
		links[tok] = true
		base := url[:i]
		for _, c := range []struct {
			auth string
			want int
		}{{"Bearer " + operator, 401}, {"Bearer " + tok, 502}} { // 502: auth passed, no gateway behind it
			req, _ := http.NewRequest("GET", base+"/api/pending", nil)
			req.Header.Set("Authorization", c.auth)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Fatalf("%s...: status %d, want %d", c.auth[:12], resp.StatusCode, c.want)
			}
		}
	}
	if len(links) != 2 {
		t.Fatal("two runs got the same page token")
	}
}
