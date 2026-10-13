package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// modelUpstream answers every request with body and content type ct.
func modelUpstream(t *testing.T, ct string, body func(n int) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(hits.Add(1))
		w.Header().Set("Content-Type", ct)
		_, _ = io.WriteString(w, body(n))
	}))
	t.Cleanup(up.Close)
	return up, &hits
}

const modelCall = `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

func callModel(srv *Server, url string, hdr map[string]string) *httptest.ResponseRecorder {
	return send(srv, "POST", url+"/v1/messages", "application/json", strings.NewReader(modelCall), hdr)
}

// ASI08: model requests are counted per agent; past the allowance a person
// is asked once (model.budget, "model-budget:<host>"), a refusal stops the
// call, and an approval doubles the allowance for the run.
func TestModelBudget_RequestsAskOnceAndApprovalDoubles(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	srv.SetModelGate(true, []string{"127.0.0.1"})
	srv.SetModelBudget(true, 3, 0, 0)
	up, hits := modelUpstream(t, "text/plain", func(int) string { return "ok" })
	ag.setDecision("model.budget", "deny")
	for i := 0; i < 3; i++ {
		if rec := callModel(srv, up.URL, nil); rec.Code != 200 {
			t.Fatalf("call %d: %d", i, rec.Code)
		}
	}
	if n := len(ag.of("model.budget")); n != 0 {
		t.Fatalf("asked %d times within the budget", n)
	}
	rec := callModel(srv, up.URL, nil)
	q := ag.of("model.budget")
	if rec.Code != http.StatusForbidden || hits.Load() != 3 || len(q) != 1 || q[0].Resource != "model-budget:127.0.0.1" {
		t.Fatalf("over budget: %d hits=%d questions %+v", rec.Code, hits.Load(), q)
	}
	if !strings.Contains(q[0].Context["model_use"], "3 requests") {
		t.Fatalf("context %+v", q[0].Context)
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != "deny" {
		t.Fatalf("receipt %+v", r)
	}
	ag.setDecision("model.budget", "escalate")
	ag.status.Store("approved")
	for i := 0; i < 3; i++ { // 4, 5, 6 of a doubled 6
		if rec := callModel(srv, up.URL, nil); rec.Code != 200 {
			t.Fatalf("after approval, call %d: %d", i, rec.Code)
		}
	}
	if ag.creates.Load() != 1 {
		t.Fatalf("approvals %d", ag.creates.Load())
	}
	ag.status.Store("denied")
	if rec := callModel(srv, up.URL, nil); rec.Code != http.StatusForbidden || ag.creates.Load() != 2 {
		t.Fatalf("past the doubled allowance: %d creates=%d", rec.Code, ag.creates.Load())
	}
}

// ASI08: token counts come from the response's usage, JSON or a stream,
// and the agent gets the response unchanged.
func TestModelBudget_CountsTokens(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		srv.SetModelBudget(true, 0, 1000, 0)
		resp := `{"id":"x","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":400,"cache_read_input_tokens":200,"output_tokens":10}}`
		up, _ := modelUpstream(t, "application/json", func(int) string { return resp })
		ag.setDecision("model.budget", "deny")
		for i := 0; i < 2; i++ {
			rec := callModel(srv, up.URL, nil)
			if rec.Code != 200 || rec.Body.String() != resp {
				t.Fatalf("call %d: %d %q", i, rec.Code, rec.Body)
			}
		}
		// 1200 input tokens used of 1000
		if rec := callModel(srv, up.URL, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("over the input tokens: %d", rec.Code)
		}
		if q := ag.of("model.budget"); len(q) != 1 || !strings.Contains(q[0].Context["model_use"], "1200 input tokens") {
			t.Fatalf("questions %+v", q)
		}
	})
	t.Run("stream", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		srv.SetModelBudget(true, 0, 0, 900)
		stream := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":30,\"output_tokens\":1}}}\r\n\r\n" +
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"" + strings.Repeat("z", 5000) + "\"}}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":500}}\n\n" +
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
		up, _ := modelUpstream(t, "text/event-stream", func(int) string { return stream })
		ag.setDecision("model.budget", "deny")
		if rec := callModel(srv, up.URL, nil); rec.Code != 200 || rec.Body.String() != stream {
			t.Fatalf("first: %d", rec.Code)
		}
		if rec := callModel(srv, up.URL, nil); rec.Code != 200 {
			t.Fatalf("second (500 of 900 output tokens used): %d", rec.Code)
		}
		if rec := callModel(srv, up.URL, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("over the output tokens: %d", rec.Code)
		}
		if q := ag.of("model.budget"); len(q) != 1 || !strings.Contains(q[0].Context["model_use"], "60 input tokens, 1000 output tokens") {
			t.Fatalf("questions %+v", q)
		}
	})
	t.Run("unknown usage counts requests only", func(t *testing.T) {
		srv, ag, _ := newActionServer(t, "allow")
		srv.SetModelGate(true, []string{"127.0.0.1"})
		srv.SetModelBudget(true, 0, 10, 10)
		up, _ := modelUpstream(t, "application/json", func(int) string { return `{"usage":"lots"}` })
		ag.setDecision("model.budget", "deny")
		for i := 0; i < 5; i++ {
			if rec := callModel(srv, up.URL, nil); rec.Code != 200 {
				t.Fatalf("call %d: %d", i, rec.Code)
			}
		}
	})
}

// ASI08: the budget is per agent.
func TestModelBudget_PerAgent(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	srv.SetModelGate(true, []string{"127.0.0.1"})
	srv.SetModelBudget(true, 2, 0, 0)
	srv.SetAgents(map[string]string{"alpha": tokAlpha, "beta": tokBeta})
	up, _ := modelUpstream(t, "text/plain", func(int) string { return "ok" })
	ag.setDecision("model.budget", "deny")
	for i := 0; i < 2; i++ {
		callModel(srv, up.URL, asAgent(tokAlpha))
	}
	if rec := callModel(srv, up.URL, asAgent(tokAlpha)); rec.Code != http.StatusForbidden {
		t.Fatalf("alpha over budget: %d", rec.Code)
	}
	if rec := callModel(srv, up.URL, asAgent(tokBeta)); rec.Code != 200 {
		t.Fatalf("beta: %d", rec.Code)
	}
	if q := ag.of("model.budget"); len(q) != 1 || q[0].Context["agent"] != "alpha" {
		t.Fatalf("questions %+v", q)
	}
}

func TestFindUsage(t *testing.T) {
	cases := []struct {
		body    string
		in, out int64
	}{
		{`{"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`, 11, 7},
		{`{"type":"response.completed","response":{"usage":{"input_tokens":5,"output_tokens":3}}}`, 5, 3},
		{`{"usage":{"input_tokens":5,"cache_creation_input_tokens":2,"output_tokens":-4}}`, 7, 0},
		{`{"content":[{"usage":{"input_tokens":99}}]}`, 0, 0},
		{`{"a":{"b":{"c":{"d":{"e":{"usage":{"input_tokens":1}}}}}}}`, 0, 0},
	}
	for _, c := range cases {
		var v any
		dec := json.NewDecoder(strings.NewReader(c.body))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		in, out := findUsage(v, 0)
		if in != c.in || out != c.out {
			t.Errorf("%s: got %d/%d want %d/%d", c.body, in, out, c.in, c.out)
		}
	}
}

// The usage reader stays within its bounds: a line longer than the limit
// is skipped, not buffered.
func TestUsageReaderBounds(t *testing.T) {
	b := newModelBudget(0, 0, 0)
	long := "data: {\"usage\":{\"output_tokens\":5,\"pad\":\"" + strings.Repeat("p", maxUsageLine) + "\"}}\n"
	u := &usageReader{src: strings.NewReader(long + "data: {\"usage\":{\"output_tokens\":3}}\n"), b: b, key: "k", sse: true}
	if _, err := io.Copy(io.Discard, u); err != nil {
		t.Fatal(err)
	}
	if u.buf.Cap() > 2*maxUsageLine {
		t.Fatalf("buffered %d bytes", u.buf.Cap())
	}
	u.finish()
	if got := b.use["k"]; got == nil || got.out != 3 {
		t.Fatalf("use %+v", got)
	}
}
