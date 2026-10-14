package proxy

import (
	"net/http"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

// The content rule: a secret-shaped value in an allowed request's body or
// query is a question of its own; the person sees the kinds, never the
// values.

func TestDLP_DetectorsAndLuhn(t *testing.T) {
	srv, _, _ := newActionServer(t, "allow")
	srv.SetDLP(true, []config.DLPPattern{{Name: "customer_id", Regex: `CUST-[0-9]{8}`}}, nil, false)
	pem := "-----BEGIN OPENSSH PRIVATE" + " KEY-----\nabc\n-----END OPENSSH PRIVATE" + " KEY-----"
	cases := map[string]string{
		pem:                                    "private_key",
		"key=AKIAABCDEFGHIJKLMNOP":             "cloud_key",
		"token ghp_" + strings.Repeat("x", 36): "api_token",
		"glpat-" + strings.Repeat("y", 20):     "api_token",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3NpZ25hdHVyZQ":     "jwt",
		"card 4111 1111 1111 1111 ok":                                             "card_number",
		"ref CUST-12345678":                                                       "customer_id",
		"id 1234567890123456 (fails luhn)":                                        "",
		"plain prose about keys and tokens":                                       "",
		"commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": "",
	}
	for body, want := range cases {
		r, _ := http.NewRequest(http.MethodPost, "https://api.example.com/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/plain")
		hb := heldFor(t, r)
		kinds, _ := srv.sensitiveContent(r, hb)
		if kinds != want {
			t.Errorf("%q: kinds %q, want %q", truncate(body, 40), kinds, want)
		}
	}
	if !luhn("4111111111111111") || luhn("4111111111111112") || luhn("411111111111") {
		t.Error("luhn")
	}
}

func TestDLP_AllowedWriteWithASecretIsAQuestion(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	srv.SetDLP(true, nil, nil, false)
	up := newRecorder(t)
	ag.setDecision(actionContent, "deny")
	body := `{"comment":"here is the key: AKIAABCDEFGHIJKLMNOP and a token ghp_` + strings.Repeat("a", 36) + `"}`
	rec := send(srv, http.MethodPost, up.URL+"/comments", "application/json", strings.NewReader(body), nil)
	if rec.Code != 403 || up.hits.Load() != 0 {
		t.Fatalf("a refused secret-carrying write went out: %d, hits %d", rec.Code, up.hits.Load())
	}
	c := ag.of(actionContent)
	host := mustHostPort(t, up.URL)
	if len(c) != 1 || c[0].Resource != "content:api_token,cloud_key POST http://"+host+"/comments" {
		t.Fatalf("asked %+v", c)
	}
	if ctx := c[0].Context; ctx["content"] != "api_token ×1, cloud_key ×1" || strings.Contains(ctx["content"], "AKIA") {
		t.Fatalf("context: %v", ctx)
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != gwDeny || !containsString(r.Reasons, "content:api_token,cloud_key") {
		t.Fatalf("receipt: %+v", r)
	}
	ag.setDecision(actionContent, "allow")
	if rec := send(srv, http.MethodPost, up.URL+"/comments", "application/json", strings.NewReader(body), nil); rec.Code != 200 || up.hits.Load() != 1 {
		t.Fatalf("an allowed one: %d", rec.Code)
	}
	// A body without a secret is not asked about; a query with one is.
	if rec := send(srv, http.MethodPost, up.URL+"/comments", "application/json", strings.NewReader(`{"comment":"all good"}`), nil); rec.Code != 200 || len(ag.of(actionContent)) != 2 {
		t.Fatalf("plain body: %d", rec.Code)
	}
	ag.setDecision(actionContent, "deny")
	if rec := send(srv, http.MethodGet, up.URL+"/search?q=AKIAABCDEFGHIJKLMNOP", "", nil, nil); rec.Code != 403 {
		t.Fatalf("a key in a query: %d", rec.Code)
	}
}

func TestDLP_ExemptionsAndModelCalls(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := newRecorder(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionContent, "deny")
	body := "-----BEGIN RSA PRIVATE" + " KEY-----\nxyz\n-----END RSA PRIVATE" + " KEY-----" // built here: no key material in the source

	srv.SetDLP(true, nil, []string{"http://" + host + "/vault/*"}, false)
	if rec := send(srv, http.MethodPost, up.URL+"/vault/store", "text/plain", strings.NewReader(body), nil); rec.Code != 200 {
		t.Fatalf("an exempt URL was asked about: %d", rec.Code)
	}
	if rec := send(srv, http.MethodPost, up.URL+"/elsewhere", "text/plain", strings.NewReader(body), nil); rec.Code != 403 {
		t.Fatalf("a non-exempt URL: %d", rec.Code)
	}
	// The model API is not scanned unless asked for.
	srv.SetModelGate(false, []string{host})
	if rec := send(srv, http.MethodPost, up.URL+"/v1/messages", "application/json", strings.NewReader(`{"prompt":"`+body+`"}`), nil); rec.Code != 200 {
		t.Fatalf("model call scanned by default: %d", rec.Code)
	}
	srv.SetDLP(true, nil, nil, true)
	if rec := send(srv, http.MethodPost, up.URL+"/v1/messages", "application/json", strings.NewReader(`{"prompt":"`+body+`"}`), nil); rec.Code != 403 {
		t.Fatalf("model call with include_model_calls: %d", rec.Code)
	}
	srv.SetDLP(false, nil, nil, false)
	if rec := send(srv, http.MethodPost, up.URL+"/elsewhere", "text/plain", strings.NewReader(body), nil); rec.Code != 200 {
		t.Fatalf("rule off: %d", rec.Code)
	}
}
