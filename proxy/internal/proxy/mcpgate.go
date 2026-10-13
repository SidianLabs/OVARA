package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"ovara.proxy/internal/mcp"
)

// MCP-aware mode. A request whose body is MCP JSON-RPC (Streamable HTTP, or
// the POST half of the older HTTP+SSE transport) is read after the URL
// policy has let it through:
//
//   - every tools/call is a question of its own (action_type mcp.tool_call,
//     resource "mcp:<host><path>/<tool>"), asked with the arguments in view;
//     a tool whose definition was never approved is refused without asking;
//   - every tool list coming back (a JSON response, or an event of any
//     event stream from a non-model host) is compared with the definitions
//     pinned for that server; new or changed ones are a question
//     (action_type mcp.tools) and, unless approved, never reach the agent.
//
// Servers are keyed by host and path ("mcp.example.com/mcp"). For the older
// transport, whose responses arrive on a separate event stream, the
// stream's "endpoint" event ties the POST path to the stream's key.

type mcpState struct {
	gate *mcp.Gate
	mu   sync.Mutex
	// endpoints maps the POST endpoint of an HTTP+SSE server to the key of
	// the event stream that announced it.
	endpoints map[string]string
	// known are server keys seen carrying MCP.
	known map[string]bool
}

// maxMCPEndpoints bounds the two maps above; past it they start again.
const maxMCPEndpoints = 4096

func (s *Server) newMCPState(store *mcp.Store) *mcpState {
	g := mcp.NewGate(store, mcp.AskFunc(func(ctx context.Context, actionType, resource string, preview map[string]string) (string, string) {
		return s.askAction(ctx, actionType, resource, preview, "is an MCP question")
	}), redactPreviewCount)
	g.Logf = log.Printf
	return &mcpState{gate: g, endpoints: map[string]string{}, known: map[string]bool{}}
}

// SetMCPGate turns MCP-aware mode on or off (default on, pins in memory)
// and names the file the pinned tool definitions are kept in ("" keeps them
// in memory only).
func (s *Server) SetMCPGate(on bool, pinsFile string) error {
	if !on {
		s.mcp = nil
		return nil
	}
	store, err := mcp.OpenStore(pinsFile)
	if err != nil {
		return err
	}
	s.mcp = s.newMCPState(store)
	return nil
}

// mcpServerKey names the server a URL belongs to: host (with a port other
// than the scheme's default) and path, without the query.
func mcpServerKey(u *url.URL) string {
	host := normalizeHost(u.Hostname())
	if p := u.Port(); p != "" && !(p == "443" && u.Scheme == schemeHTTPS) && !(p == "80" && u.Scheme == "http") {
		host = net.JoinHostPort(host, p)
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return host + p
}

func (m *mcpState) server(u *url.URL) string {
	k := mcpServerKey(u)
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.endpoints[k]; ok {
		return s
	}
	return k
}

func (m *mcpState) markKnown(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.known) >= maxMCPEndpoints {
		m.known = map[string]bool{}
	}
	m.known[k] = true
}

func (m *mcpState) isKnown(k string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.known[k]
}

func (m *mcpState) mapEndpoint(endpoint, stream string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.endpoints) >= maxMCPEndpoints {
		m.endpoints = map[string]string{}
	}
	m.endpoints[endpoint] = stream
}

// mcpExchange is what the gate learned from one MCP request.
type mcpExchange struct {
	server string
	body   *mcp.Body
	// toolListIDs are the ids of the tools/list requests in the body.
	toolListIDs map[string]bool
}

// mcpRefusal is the answer sent instead of a request or a response.
type mcpRefusal struct {
	status     int
	body       []byte
	decision   string
	approvalID string
	reasons    []string
	aborted    bool // the client went away: nothing to write
}

// write sends the refusal and returns the decision and status to receipt.
func (f *mcpRefusal) write(w http.ResponseWriter) (string, int) {
	if f.aborted {
		return f.decision, 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = w.Write(append(f.body, '\n'))
	return f.decision, f.status
}

func acceptsEventStream(r *http.Request) bool {
	return strings.Contains(strings.ToLower(strings.Join(r.Header.Values("Accept"), ",")), "text/event-stream")
}

// isMCPSession reports the headers Streamable HTTP clients send on every
// request after initialization.
func isMCPSession(r *http.Request) bool {
	return r.Header.Get("Mcp-Session-Id") != "" || r.Header.Get("Mcp-Protocol-Version") != ""
}

// mcpRequest reads an allowed request's held body. It returns what it
// learned if the body is MCP, and a refusal if a tool call in it may not go
// out.
func (s *Server) mcpRequest(ctx context.Context, r *http.Request, hb *heldBody) (*mcpExchange, *mcpRefusal) {
	m := s.mcp
	if m == nil || s.isModelHost(r.URL.Hostname()) {
		return nil, nil
	}
	if acceptsEventStream(r) || isMCPSession(r) {
		// The response is read to be checked: it must arrive in a form
		// that can be read (the transport still negotiates gzip and
		// decodes it).
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Range")
		r.Header.Del("If-Range")
	}
	if hb == nil {
		return nil, nil
	}
	server := m.server(r.URL)
	if hb.size > mcp.MaxMessageBytes {
		// Too large to read whole. If it looks like JSON-RPC it is refused:
		// a tool call must not go out unchecked for being big.
		if bytes.Contains(bytes.ToLower(hb.head), []byte("jsonrpc")) || m.isKnown(server) {
			v := mcp.Refused("the MCP message is too large to check", "mcp_message_too_large")
			return nil, &mcpRefusal{status: http.StatusRequestEntityTooLarge, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
		}
		return nil, nil
	}
	data, err := io.ReadAll(hb.reader())
	if err != nil {
		return nil, nil
	}
	switch enc := encodedValue(r.Header.Values("Content-Encoding")); {
	case enc == "gzip" || enc == "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(zr, mcp.MaxMessageBytes+1))
		}
		if err != nil || len(data) > mcp.MaxMessageBytes {
			return nil, s.mcpUnreadable(server)
		}
	case enc != "":
		if m.isKnown(server) || isMCPSession(r) {
			return nil, s.mcpUnreadable(server)
		}
		return nil, nil
	}
	body, err := mcp.Parse(data)
	if err != nil || !body.IsMCP() {
		return nil, nil
	}
	m.markKnown(server)
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Range")
	r.Header.Del("If-Range")
	x := &mcpExchange{server: server, body: body, toolListIDs: map[string]bool{}}
	for _, msg := range body.Messages {
		if msg.Method == "tools/list" && msg.ID != nil {
			x.toolListIDs[idKey(msg.ID)] = true
		}
	}
	checks := m.gate.ClientBody(ctx, server, body)
	refused := map[int]mcp.Verdict{}
	var first *mcp.Verdict
	for i := range checks {
		c := &checks[i]
		if c.Verdict.Outcome == mcp.OutcomeAborted {
			return nil, &mcpRefusal{aborted: true, decision: "escalate", approvalID: c.Verdict.ApprovalID}
		}
		if !c.Verdict.Allowed() {
			refused[c.Index] = c.Verdict
			if first == nil {
				first = &c.Verdict
			}
		}
	}
	if first == nil {
		return x, nil
	}
	// One refused call stops the whole request: an HTTP request goes out
	// whole or not at all. Every request in it gets an error.
	notSent := mcp.Verdict{Outcome: mcp.OutcomeDeny, Reasons: []string{"mcp_batch_refused"}, Detail: "not sent: another call in the same batch was refused"}
	parts := make([][]byte, 0, len(body.Messages))
	for i, msg := range body.Messages {
		if msg.ID == nil || msg.Method == "" {
			continue
		}
		v, ok := refused[i]
		if !ok {
			v = notSent
		}
		parts = append(parts, mcp.ErrorResponse(msg.ID, v.Detail, v.ErrorData(server)))
	}
	ref := &mcpRefusal{status: http.StatusForbidden, decision: "deny", approvalID: first.ApprovalID, reasons: first.Reasons}
	switch first.Outcome {
	case mcp.OutcomeTimeout:
		ref.status, ref.decision = http.StatusGatewayTimeout, gwEscalate
	case mcp.OutcomeError:
		ref.status = http.StatusBadGateway
	}
	ref.body = joinMessages(parts, body.Batch)
	return nil, ref
}

func (s *Server) mcpUnreadable(server string) *mcpRefusal {
	v := mcp.Refused("the MCP message is encoded in a form Ovara cannot read", "mcp_message_unreadable")
	return &mcpRefusal{status: http.StatusBadRequest, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
}

func joinMessages(parts [][]byte, batch bool) []byte {
	if len(parts) == 0 {
		return mcp.ErrorResponse(nil, "", nil)
	}
	if len(parts) == 1 && !batch {
		return parts[0]
	}
	return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
}

// idKey is a JSON-RPC id in a comparable form.
func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return string(id)
	}
	return b.String()
}

func mediaType(h http.Header) string {
	mt, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return strings.ToLower(mt)
}

// mcpResponse checks a response before its headers reach the agent. A JSON
// response to an MCP request is read whole (up to mcp.MaxMessageBytes) and
// checked; an event stream is checked event by event as it is relayed
// (resp.Body is replaced). When the request listed tools and the answer is
// an event stream, the stream is held until those answers have been
// checked, so a refusal can still be a plain HTTP error. cut is called
// when an event is refused after the headers went out.
func (s *Server) mcpResponse(ctx context.Context, r *http.Request, x *mcpExchange, resp *http.Response, cut func(v mcp.Verdict)) *mcpRefusal {
	m := s.mcp
	if m == nil || s.isModelHost(r.URL.Hostname()) {
		return nil
	}
	mt := mediaType(resp.Header)
	isSSE := mt == "text/event-stream"
	isJSON := strings.HasSuffix(mt, "json")
	if x == nil && !isSSE {
		return nil
	}
	server := m.server(r.URL)
	if x != nil {
		server = x.server
	}
	if enc := encodedValue(resp.Header.Values("Content-Encoding")); enc != "" {
		if x != nil || (isSSE && (acceptsEventStream(r) || isMCPSession(r) || m.isKnown(server))) {
			v := mcp.Refused("the response is encoded in a form Ovara cannot read", "mcp_message_unreadable")
			return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
		}
		return nil
	}
	if isSSE {
		f := &sseFilter{
			ctx: ctx, s: s, m: m, req: r, server: server, cut: cut,
			ev:        mcp.NewEventReader(resp.Body, mcp.MaxMessageBytes),
			mcpStream: x != nil || isMCPSession(r) || m.isKnown(server),
		}
		if x != nil && len(x.toolListIDs) > 0 {
			if ref := f.hold(x.toolListIDs); ref != nil {
				return ref
			}
		}
		resp.Body = io.NopCloser(f)
		resp.Header.Del("Content-Length") // a refused event is replaced
		return nil
	}
	if !isJSON {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, mcp.MaxMessageBytes+1))
	if err != nil || len(data) > mcp.MaxMessageBytes {
		if len(x.toolListIDs) > 0 || err != nil {
			v := mcp.Refused("the response is too large to check, or could not be read", "mcp_response_unchecked")
			return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
		}
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), resp.Body))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	res := m.gate.ServerBody(ctx, server, data)
	if res.Verdict.Allowed() {
		return nil
	}
	return refusalFor(res, server)
}

// refusalFor turns a refused server body into the HTTP answer sent instead.
func refusalFor(res mcp.ServerResult, server string) *mcpRefusal {
	v := res.Verdict
	if v.Outcome == mcp.OutcomeAborted {
		return &mcpRefusal{aborted: true, decision: "escalate", approvalID: v.ApprovalID}
	}
	ref := &mcpRefusal{status: http.StatusBadGateway, decision: "deny", approvalID: v.ApprovalID, reasons: v.Reasons,
		body: mcp.Refusal(res.IDs, res.Batch, v, server)}
	if v.Outcome == mcp.OutcomeTimeout {
		ref.decision = "escalate"
	}
	return ref
}

var errMCPStreamCut = errors.New("MCP event stream cut: an event could not be checked")

// sseFilter relays an event stream one whole event at a time, checking every
// tool list in it. A refused event is replaced by a JSON-RPC error for the
// same ids. An event too large to check ends an MCP stream; in any other
// stream the rest is passed through as it is.
type sseFilter struct {
	ctx       context.Context
	s         *Server
	m         *mcpState
	req       *http.Request
	server    string
	ev        *mcp.EventReader
	mcpStream bool
	cut       func(mcp.Verdict)

	out     []byte
	err     error
	rest    io.Reader // passthrough after an oversized event in a non-MCP stream
	refused *mcp.ServerResult
	// answered collects the response ids seen (for hold)
	answered map[string]bool
}

func (f *sseFilter) Read(p []byte) (int, error) {
	for len(f.out) == 0 {
		if f.rest != nil {
			return f.rest.Read(p)
		}
		if f.err != nil {
			return 0, f.err
		}
		f.step()
	}
	n := copy(p, f.out)
	f.out = f.out[n:]
	return n, nil
}

// step reads and checks one event, appending what may be relayed to out.
func (f *sseFilter) step() {
	raw, err := f.ev.Next()
	if errors.Is(err, mcp.ErrEventTooLarge) {
		if f.mcpStream {
			log.Printf("mcp: %s: event over %d bytes; the stream is cut", f.server, mcp.MaxMessageBytes)
			if f.cut != nil {
				f.cut(mcp.Refused("event too large to check", "mcp_response_unchecked"))
			}
			f.err = errMCPStreamCut
			return
		}
		f.out = append(f.out, raw...)
		f.rest = f.ev.Rest()
		return
	}
	if len(raw) > 0 {
		// An event the stream ended in the middle of is checked too: not
		// every client drops it.
		f.out = append(f.out, f.check(raw)...)
	}
	if err != nil {
		f.err = err
	}
}

func (f *sseFilter) check(raw []byte) []byte {
	ev := mcp.ParseEvent(raw)
	if ev.Name == "endpoint" {
		f.mcpStream = true
		f.m.markKnown(f.server)
		if u, err := f.req.URL.Parse(strings.TrimSpace(ev.Data)); err == nil && strings.EqualFold(u.Host, f.req.URL.Host) {
			if k := mcpServerKey(u); k != f.server {
				f.m.mapEndpoint(k, f.server)
			}
		}
		return raw
	}
	data := strings.TrimSpace(ev.Data)
	if !ev.HasData || data == "" || (data[0] != '{' && data[0] != '[') {
		return raw
	}
	if !f.mcpStream && !strings.Contains(strings.ToLower(data), "jsonrpc") {
		// a stream not known to carry MCP: only JSON-RPC is looked at
		return raw
	}
	res := f.m.gate.ServerBody(f.ctx, f.server, []byte(ev.Data))
	if res.IsMCP {
		if !f.mcpStream {
			f.m.markKnown(f.server)
		}
		f.mcpStream = true
	}
	if f.answered != nil {
		for _, id := range res.IDs {
			f.answered[idKey(id)] = true
		}
	}
	if res.Verdict.Allowed() {
		return raw
	}
	if res.Verdict.Outcome == mcp.OutcomeAborted {
		f.err = context.Canceled
		return nil
	}
	if f.refused == nil {
		f.refused = &res
	}
	if f.cut != nil {
		f.cut(res.Verdict)
	}
	return mcp.MessageEvent(mcp.Refusal(res.IDs, res.Batch, res.Verdict, f.server))
}

// hold reads events (without relaying them) until every id in ids has been
// answered, the stream ends, or more than mcp.MaxMessageBytes are held. If
// a tool list among them is refused, the refusal is returned and nothing is
// relayed; otherwise what was read is relayed first, then the rest.
func (f *sseFilter) hold(ids map[string]bool) *mcpRefusal {
	f.answered = map[string]bool{}
	cut := f.cut
	f.cut = nil // nothing has been relayed yet: a refusal is an HTTP error
	defer func() { f.cut = cut }()
	for f.err == nil && f.rest == nil && len(f.out) <= mcp.MaxMessageBytes {
		done := true
		for id := range ids {
			if !f.answered[id] {
				done = false
				break
			}
		}
		if done {
			break
		}
		f.step()
		if f.refused != nil {
			return refusalFor(*f.refused, f.server)
		}
	}
	if errors.Is(f.err, errMCPStreamCut) {
		v := mcp.Refused("an event was too large to check", "mcp_response_unchecked")
		return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(f.server))}
	}
	if errors.Is(f.err, context.Canceled) {
		return &mcpRefusal{aborted: true, decision: "escalate"}
	}
	f.answered = nil
	return nil
}

const schemeHTTPS = "https"
