package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// The model budget: a cap on how much one agent uses its model in one run.
// A runaway loop, or an agent talked into burning its operator's money,
// otherwise meets no limit at all: model calls are allowed without asking.
// Requests to model hosts are counted per agent and host; where the
// response says how many tokens it used (a JSON body with a "usage"
// object, or server-sent events carrying usage), those are counted too.
// Past the allowance a person is asked once (action_type "model.budget",
// resource "model-budget:<host>"); an approval doubles the allowance for
// the rest of the run. A response whose usage cannot be read counts as a
// request only.

const (
	actionModelBudget = "model.budget"

	defaultModelRequests     = 2000
	defaultModelInputTokens  = 50_000_000
	defaultModelOutputTokens = 10_000_000

	// maxUsageJSON bounds how much of a JSON response is kept to read its
	// usage; a larger one counts as a request only.
	maxUsageJSON = 8 << 20
	// maxUsageLine bounds one server-sent event line.
	maxUsageLine = 1 << 20
)

type modelUse struct {
	reqs, in, out int64
	mult          int64
	pending       *pkgResult
}

type modelBudget struct {
	mu                 sync.Mutex
	reqs, inTok, outTk int64
	use                map[string]*modelUse // agent + " " + host
}

func newModelBudget(reqs, in, out int64) *modelBudget {
	if reqs <= 0 {
		reqs = defaultModelRequests
	}
	if in <= 0 {
		in = defaultModelInputTokens
	}
	if out <= 0 {
		out = defaultModelOutputTokens
	}
	return &modelBudget{reqs: reqs, inTok: in, outTk: out, use: map[string]*modelUse{}}
}

// SetModelBudget turns the model budget on or off (default on) and sets
// the per-agent allowance for a run; zero keeps a default.
func (s *Server) SetModelBudget(on bool, requests, inputTokens, outputTokens int64) {
	if !on {
		s.modelBudget = nil
		return
	}
	s.modelBudget = newModelBudget(requests, inputTokens, outputTokens)
}

// entry returns key's counters. Called with mu held.
func (b *modelBudget) entry(key string) *modelUse {
	u := b.use[key]
	if u == nil {
		u = &modelUse{mult: 1}
		b.use[key] = u
	}
	return u
}

// over reports whether one more request would go past the allowance.
// Called with mu held.
func (b *modelBudget) over(u *modelUse) bool {
	return u.reqs+1 > b.reqs*u.mult || u.in >= b.inTok*u.mult || u.out >= b.outTk*u.mult
}

// isModelCall reports whether r is a call to a model host the budget counts.
func (s *Server) isModelCall(r *http.Request) bool {
	return s.modelBudget != nil && !isReadMethod(r.Method) && s.isModelHost(normalizeHost(r.URL.Hostname()))
}

// checkModelBudget counts one model request for the agent behind ctx,
// asking a person when it does not fit. Parallel requests over the budget
// share one question.
func (s *Server) checkModelBudget(ctx context.Context, r *http.Request, host string) (string, string) {
	b := s.modelBudget
	if b == nil || !s.isModelCall(r) {
		return pkgAllow, ""
	}
	key := agentKey(ctx) + " " + host
	b.mu.Lock()
	u := b.entry(key)
	if !b.over(u) {
		u.reqs++
		b.mu.Unlock()
		return pkgAllow, ""
	}
	if p := u.pending; p != nil {
		b.mu.Unlock()
		select {
		case <-p.done:
		case <-ctx.Done():
			return pkgAborted, ""
		}
		if p.outcome == pkgAllow || p.outcome == pkgApproved {
			b.mu.Lock()
			u.reqs++
			b.mu.Unlock()
			return pkgAllow, p.approvalID
		}
		return p.outcome, p.approvalID
	}
	p := &pkgResult{done: make(chan struct{})}
	u.pending = p
	preview := map[string]string{
		"host":      host,
		"model_use": fmt.Sprintf("%d requests, %d input tokens, %d output tokens so far this run", u.reqs, u.in, u.out),
		"allowance": fmt.Sprintf("%d requests, %d input tokens, %d output tokens", b.reqs*u.mult, b.inTok*u.mult, b.outTk*u.mult),
		"why":       "the agent has used its model more than its budget allows for one run (a loop, or an agent told to burn money); approving doubles the allowance for the rest of the run",
	}
	b.mu.Unlock()

	p.outcome, p.approvalID = s.askAction(ctx, actionModelBudget, "model-budget:"+host, preview, "is over its model budget")
	b.mu.Lock()
	ok := p.outcome == pkgAllow || p.outcome == pkgApproved
	if ok {
		u.mult *= 2
		u.reqs++
	}
	u.pending = nil
	b.mu.Unlock()
	close(p.done)
	if ok {
		return pkgAllow, p.approvalID
	}
	return p.outcome, p.approvalID
}

// addTokens counts tokens a response reported.
func (b *modelBudget) addTokens(key string, in, out int64) {
	if in <= 0 && out <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.entry(key)
	u.in += in
	u.out += out
}

// usageReader passes a model response through unchanged and reads the
// token usage it reports on the way, within fixed bounds.
type usageReader struct {
	src      io.Reader
	b        *modelBudget
	key      string
	sse      bool
	buf      bytes.Buffer // JSON: the body so far; SSE: the current line
	skipLine bool         // SSE: the current line is too long; drop it
	overflow bool         // JSON: too large to read the usage from
	in, out  int64        // the largest counts seen (SSE counts are cumulative)
	once     sync.Once
}

// watchModelUsage wraps *body so the tokens of a model response are
// counted when finish is called. It returns nil (finish is then a no-op)
// for anything that is not a model call with a JSON or event-stream body.
func (s *Server) watchModelUsage(r *http.Request, resp *http.Response, body *io.Reader) *usageReader {
	if !s.isModelCall(r) || resp == nil {
		return nil
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	u := &usageReader{src: *body, b: s.modelBudget, key: agentKey(r.Context()) + " " + normalizeHost(r.URL.Hostname())}
	switch {
	case strings.Contains(ct, "text/event-stream"):
		u.sse = true
	case strings.Contains(ct, "json"):
	default:
		return nil
	}
	if encodedValue(resp.Header.Values("Content-Encoding")) != "" {
		return nil // compressed bytes: the usage cannot be read; the request still counted
	}
	*body = u
	return u
}

func (u *usageReader) Read(p []byte) (int, error) {
	n, err := u.src.Read(p)
	if n > 0 {
		u.feed(p[:n])
	}
	return n, err
}

func (u *usageReader) feed(p []byte) {
	if !u.sse {
		if u.overflow {
			return
		}
		if u.buf.Len()+len(p) > maxUsageJSON {
			u.overflow = true
			u.buf = bytes.Buffer{}
			return
		}
		u.buf.Write(p)
		return
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		if !u.skipLine {
			if u.buf.Len()+len(chunk) > maxUsageLine {
				u.skipLine = true
				u.buf.Reset()
			} else {
				u.buf.Write(chunk)
			}
		}
		if i < 0 {
			return
		}
		if !u.skipLine {
			u.line(u.buf.Bytes())
		}
		u.buf.Reset()
		u.skipLine = false
		p = p[i+1:]
	}
}

// line reads one server-sent event line.
func (u *usageReader) line(l []byte) {
	l = bytes.TrimRight(l, "\r")
	data, ok := bytes.CutPrefix(l, []byte("data:"))
	if !ok {
		return
	}
	u.take(bytes.TrimSpace(data))
}

func (u *usageReader) take(data []byte) {
	if len(data) == 0 || data[0] != '{' {
		return
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return
	}
	in, out := findUsage(v, 0)
	u.in = max(u.in, in)
	u.out = max(u.out, out)
}

// finish counts what the response reported. Safe on nil and more than once.
func (u *usageReader) finish() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		if !u.sse && !u.overflow {
			u.take(bytes.TrimSpace(u.buf.Bytes()))
		} else if u.sse && !u.skipLine && u.buf.Len() > 0 {
			u.line(u.buf.Bytes())
		}
		u.buf = bytes.Buffer{}
		u.b.addTokens(u.key, u.in, u.out)
	})
}

// findUsage returns the largest input and output token counts in any
// "usage" object in v, looking a few levels deep ("usage" sits at the top
// of a response, under "message" in an Anthropic stream's first event and
// under "response" in an OpenAI Responses stream).
func findUsage(v any, depth int) (int64, int64) {
	m, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return 0, 0
	}
	var in, out int64
	if us, ok := m["usage"].(map[string]any); ok {
		num := func(k string) int64 {
			if n, ok := us[k].(json.Number); ok {
				if i, err := n.Int64(); err == nil && i > 0 {
					return i
				}
			}
			return 0
		}
		in = num("input_tokens") + num("cache_creation_input_tokens") + num("cache_read_input_tokens")
		if p := num("prompt_tokens"); p > in {
			in = p
		}
		out = max(num("output_tokens"), num("completion_tokens"))
	}
	for k, sub := range m {
		if k == "usage" {
			continue
		}
		if _, ok := sub.(map[string]any); ok {
			i, o := findUsage(sub, depth+1)
			in, out = max(in, i), max(out, o)
		}
	}
	return in, out
}
