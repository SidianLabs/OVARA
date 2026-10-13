package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/creds"
)

// The read guard must run whatever the method's spelling: the gateway matches
// "get" as GET, so the proxy must check it as GET too.
func TestLowercaseMethodStillGuarded(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	for _, m := range []string{"get", "Get", "gEt", "head"} {
		f := newFixture(t, "allow", nil)
		rec := httptest.NewRecorder()
		req, err := http.NewRequest(m, up.URL+"/x?d="+strings.Repeat("A", maxReadQueryBytes+10), strings.NewReader("body"))
		if err != nil {
			t.Fatal(err)
		}
		f.srv.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("method %q: data-carrying read was forwarded", m)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream reached %d times", hits.Load())
	}
}

// Every Content-Encoding value counts, not just the first.
func TestDuplicateContentEncodingRefused(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Encoding"] = []string{"identity", "gzip"}
		io.WriteString(w, "opaque "+r.Header.Get("Authorization"))
	}))
	defer up.Close()
	f := credFixture(t, up)
	resp, b := tunnel(t, f.srv, f.ca, up, nil)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(b), "SECRET") {
		t.Fatalf("want 502 and no secret, got %d %q", resp.StatusCode, b)
	}
}

// On a host Ovara holds a key for, the agent's own credential headers are
// removed: it cannot add an account of its choosing next to ours.
func TestAgentCredentialHeadersStrippedOnBoundHost(t *testing.T) {
	var got http.Header
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		io.WriteString(w, "ok")
	}))
	defer up.Close()
	f := newFixture(t, "allow", []creds.Binding{
		{Host: mustHost(t, up.URL), Headers: map[string]string{"X-Api-Key": "real-key-123456"}},
	})
	resp, _ := tunnel(t, f.srv, f.ca, up, map[string]string{
		"Authorization":   "Bearer attacker-key",
		"X-Custom-Token":  "attacker",
		"Cookie":          "session=attacker",
		"X-Request-Thing": "kept",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got.Get("Authorization") != "" || got.Get("X-Custom-Token") != "" || got.Get("Cookie") != "" {
		t.Fatalf("agent credential reached upstream: %v", got)
	}
	if got.Get("X-Api-Key") != "real-key-123456" || got.Get("X-Request-Thing") != "kept" {
		t.Fatalf("injected or ordinary header missing: %v", got)
	}
}

func TestModelGate(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "{}")
	}))
	defer up.Close()

	refused := map[string]string{
		"anthropic mcp connector": `{"model":"m","mcp_servers":[{"type":"url","url":"https://x.example/sse","name":"x"}],"messages":[]}`,
		"anthropic url image":     `{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x.example/a.png"}}]}]}`,
		"anthropic web fetch":     `{"model":"m","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}],"messages":[]}`,
		"anthropic web search":    `{"model":"m","tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[]}`,
		"openai mcp tool":         `{"model":"m","tools":[{"type":"mcp","server_label":"x","server_url":"https://x.example"}],"input":"hi"}`,
		"openai image url":        `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x.example/a.png"}}]}]}`,
		"openai input_image url":  `{"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x.example/a.png"}]}]}`,
		"nested in tool_result":   `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://x.example/a.png"}}]}]}]}`,
	}
	// A finding is a question for a person (model.server_feature), not a
	// flat refusal: unanswered, the request times out and never runs.
	// (Before, these were refused outright with 403.)
	for name, body := range refused {
		t.Run("ask "+name, func(t *testing.T) {
			srv, ag, _ := newActionServer(t, "allow")
			srv.SetModelGate(true, []string{"127.0.0.1"})
			srv.SetEscalateWindow(60*time.Millisecond, 10*time.Millisecond)
			ag.setDecision(actionModelFeature, "escalate")
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusGatewayTimeout {
				t.Fatalf("want 504 (held for a person), got %d", rec.Code)
			}
			q := ag.of(actionModelFeature)
			if len(q) != 1 || !strings.HasPrefix(q[0].Resource, "model:127.0.0.1 model_request_") || q[0].Context["model_feature"] == "" {
				t.Fatalf("questions %+v", q)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("unanswered model requests reached upstream %d times", hits.Load())
	}
	mcp := refused["anthropic mcp connector"]
	t.Run("approved forwards", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		ag.setDecision(actionModelFeature, "escalate")
		ag.status.Store("approved")
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(mcp))
		req.Header.Set("Content-Type", "application/json")
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || ag.creates.Load() != 1 {
			t.Fatalf("approved: %d creates=%d", rec.Code, ag.creates.Load())
		}
	})
	t.Run("policy deny refuses without asking", func(t *testing.T) {
		before := hits.Load()
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		ag.setDecision(actionModelFeature, "deny")
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(mcp))
		req.Header.Set("Content-Type", "application/json")
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || ag.creates.Load() != 0 || hits.Load() != before {
			t.Fatalf("deny: %d creates=%d", rec.Code, ag.creates.Load())
		}
	})
	t.Run("asking off refuses outright", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		srv.SetModelGateAsk(false)
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(mcp))
		req.Header.Set("Content-Type", "application/json")
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || len(ag.of(actionModelFeature)) != 0 {
			t.Fatalf("ask off: %d", rec.Code)
		}
	})

	allowed := map[string]string{
		"plain message":             `{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"client tools with url arg": `{"model":"m","tools":[{"name":"fetch","input_schema":{"type":"object","properties":{"url":{"type":"string"}}}}],"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"fetch","input":{"url":"https://example.com","type":"url"}}]}]}`,
		"client computer/bash tool": `{"model":"m","tools":[{"type":"bash_20250124","name":"bash"},{"type":"text_editor_20250124","name":"str_replace_editor"}],"messages":[]}`,
		"base64 image":              `{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}`,
		"data url image":            `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`,
		"openai function arguments": `{"model":"m","input":[{"type":"function_call","name":"f","arguments":"{\"url\":\"https://x\"}","call_id":"c"}]}`,
	}
	for name, body := range allowed {
		t.Run("allow "+name, func(t *testing.T) {
			f := newFixture(t, "allow", nil)
			f.srv.SetModelGate(true, []string{"127.0.0.1"})
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			f.srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("multipart upload is asked about", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		ag.setDecision(actionModelFeature, "escalate")
		ag.status.Store("denied")
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/files", strings.NewReader("--b\r\n\r\nsecret\r\n--b--"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		srv.ServeHTTP(rec, req)
		q := ag.of(actionModelFeature)
		if rec.Code != http.StatusForbidden || len(q) != 1 || q[0].Resource != "model:127.0.0.1 model_request_not_json" {
			t.Fatalf("want 403 after a denied question, got %d %+v", rec.Code, q)
		}
	})
	t.Run("encoded body is refused outright", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader("xxxx"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "br")
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || len(ag.of(actionModelFeature)) != 0 {
			t.Fatalf("want 403 without a question, got %d", rec.Code)
		}
	})
	t.Run("gate off forwards", func(t *testing.T) {
		f := newFixture(t, "allow", nil)
		f.srv.SetModelGate(false, []string{"127.0.0.1"})
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(refused["anthropic mcp connector"]))
		req.Header.Set("Content-Type", "application/json")
		f.srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200 with the gate off, got %d", rec.Code)
		}
	})
}
