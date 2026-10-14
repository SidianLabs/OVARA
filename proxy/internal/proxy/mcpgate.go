package proxy

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"ovara.proxy/internal/canonjson"
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
	endpoints *lru[string]
	// known are server keys seen carrying MCP. Servers with pinned tools
	// are known whatever this holds (isKnown asks the pin store), so
	// filling it can only push out servers nothing was pinned for.
	known *lru[bool]
}

// maxMCPEndpoints bounds the two maps above; past it the entry used least
// recently goes.
const maxMCPEndpoints = 4096

func (s *Server) newMCPState(store *mcp.Store) *mcpState {
	g := mcp.NewGate(store, mcp.AskFunc(func(ctx context.Context, actionType, resource string, preview map[string]string) (string, string) {
		return s.askAction(ctx, actionType, resource, preview, "is an MCP question")
	}), redactPreviewCount)
	g.Logf = log.Printf
	return &mcpState{gate: g, endpoints: newLRU[string](maxMCPEndpoints), known: newLRU[bool](maxMCPEndpoints)}
}

// lru is a map bounded by evicting the entry used least recently. Not safe
// for concurrent use (mcpState.mu guards it).
type lru[V any] struct {
	max int
	ll  *list.List
	m   map[string]*list.Element
}

type lruEntry[V any] struct {
	k string
	v V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, ll: list.New(), m: map[string]*list.Element{}}
}

func (c *lru[V]) get(k string) (V, bool) {
	e, ok := c.m[k]
	if !ok {
		var zero V
		return zero, false
	}
	c.ll.MoveToFront(e)
	return e.Value.(*lruEntry[V]).v, true
}

func (c *lru[V]) put(k string, v V) {
	if e, ok := c.m[k]; ok {
		e.Value.(*lruEntry[V]).v = v
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&lruEntry[V]{k: k, v: v})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*lruEntry[V]).k)
	}
}

func (c *lru[V]) len() int { return c.ll.Len() }

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
	if s, ok := m.endpoints.get(k); ok {
		return s
	}
	return k
}

func (m *mcpState) markKnown(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known.put(k, true)
}

func (m *mcpState) knownLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.known.len()
}

// isKnown reports a server seen carrying MCP: recently, or ever if any of
// its tools are pinned.
func (m *mcpState) isKnown(k string) bool {
	m.mu.Lock()
	_, ok := m.known.get(k)
	m.mu.Unlock()
	return ok || m.gate.Store.HasServer(k)
}

func (m *mcpState) mapEndpoint(endpoint, stream string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints.put(endpoint, stream)
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
	retryAfter int  // seconds, for a hold answered with 503 (see Server.heldAnswer)
}

// write sends the refusal and returns the decision and status to receipt.
func (f *mcpRefusal) write(w http.ResponseWriter) (string, int) {
	if f.aborted {
		return f.decision, 0
	}
	w.Header().Set("Content-Type", mediaJSON)
	if f.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(f.retryAfter))
	}
	w.WriteHeader(f.status)
	_, _ = w.Write(append(f.body, '\n'))
	return f.decision, f.status
}

// retryHold turns a tool call's unanswered hold into the retry answer when
// that is configured: 503 with Retry-After, the approval staying open, so
// the same call sent again runs once it is approved.
func (s *Server) retryHold(ref *mcpRefusal) *mcpRefusal {
	if ref != nil && ref.status == http.StatusGatewayTimeout && s.escalateRetry {
		ref.status = http.StatusServiceUnavailable
		if ref.retryAfter = int(s.escalatePoll / time.Second); ref.retryAfter < 1 {
			ref.retryAfter = 1
		}
	}
	return ref
}

func acceptsEventStream(r *http.Request) bool {
	return strings.Contains(strings.ToLower(strings.Join(r.Header.Values("Accept"), ",")), "text/event-stream")
}

// isMCPSession reports the headers Streamable HTTP clients send on every
// request after initialization.
func isMCPSession(r *http.Request) bool {
	return r.Header.Get("Mcp-Session-Id") != "" || r.Header.Get("Mcp-Protocol-Version") != ""
}

// mcpPrep is what was read of a request body before the request was
// decided: the MCP body in it, or the refusal it gets once allowed.
type mcpPrep struct {
	server  string
	body    *mcp.Body   // set when the body is MCP (forwarded canonical)
	refusal *mcpRefusal // set when it may not go out, whatever policy says
}

// mcpPrepare reads a held request body as MCP before anyone is asked
// about the request. An MCP body is replaced by its canonical encoding
// (mcp.Canonical), so the hash in the approval context, the tool-call
// questions and the receipt, and the bytes the server receives, are all
// of the message as it was checked. A body that cannot be read strictly
// gets a refusal, returned by mcpRequest once the URL policy has let the
// request through. It returns nil for a body that is not MCP.
func (s *Server) mcpPrepare(r *http.Request, hb *heldBody) *mcpPrep {
	m := s.mcp
	if m == nil || hb == nil || s.isModelHost(r.URL.Hostname()) {
		return nil
	}
	server := m.server(r.URL)
	p := &mcpPrep{server: server}
	// An MCP context: the client says it is in an MCP session, or the
	// server is known to speak MCP. There, anything that cannot be read
	// strictly is refused.
	mcpCtx := isMCPSession(r) || m.isKnown(server)
	if hb.size > mcp.MaxMessageBytes {
		// Too large to read whole. If it could be JSON-RPC it is refused:
		// a tool call must not go out unchecked for being big.
		if mcpCtx || heldLooksLikeJSONRPC(hb) {
			v := mcp.Refused("the MCP message is too large to check", "mcp_message_too_large")
			p.refusal = &mcpRefusal{status: http.StatusRequestEntityTooLarge, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
			return p
		}
		return nil
	}
	data, err := io.ReadAll(hb.reader())
	if err != nil {
		return nil
	}
	switch encs := contentEncodings(r.Header.Values("Content-Encoding")); {
	case len(encs) == 1 && (encs[0] == "gzip" || encs[0] == "x-gzip"):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(zr, mcp.MaxMessageBytes+1))
		}
		if err != nil || len(data) > mcp.MaxMessageBytes {
			p.refusal = s.mcpUnreadable(server)
			return p
		}
	case len(encs) > 0:
		// An encoding Ovara does not decode. Whatever could be JSON-RPC is
		// refused: a server that decodes it would act on a call nobody
		// decided.
		if mcpCtx || jsonContentType(r.Header) || mcp.LooksLikeJSONRPC(data) {
			p.refusal = s.mcpUnreadable(server)
			return p
		}
		return nil
	}
	canon, cerr := mcp.Canonical(data)
	if cerr == nil {
		body, err := mcp.Parse(canon)
		if err != nil || !body.IsMCP() {
			// Valid JSON that is not MCP: not read any further, and sent
			// as it came.
			return nil
		}
		// What goes out is what is checked below: the canonical bytes,
		// plain (a gzip body was decoded above).
		hb.replace(r, canon)
		body.SHA256 = hb.sha256Hex()
		p.body = body
		return p
	}
	body, err := mcp.Parse(data)
	// Not valid JSON, yet a lenient reader (NaN, UTF-16/32, a second
	// value) could take it for JSON-RPC.
	if errors.Is(err, mcp.ErrUnparseable) {
		p.refusal = s.mcpUnparseable(server)
		return p
	}
	if canonjson.Ambiguous(cerr) {
		// JSON to a lenient reader, but readers disagree on it (which of
		// two members named alike wins, what invalid UTF-8 reads as). If
		// it could be JSON-RPC at all, it is refused whole.
		if !(mcpCtx || (err == nil && body.IsMCP()) || mcp.LooksLikeJSONRPC(data)) {
			return nil
		}
		v := mcp.RefusedAmbiguous()
		if err != nil {
			p.refusal = &mcpRefusal{status: http.StatusBadRequest, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
			return p
		}
		p.refusal = refuseMessages(body, nil, v, server)
		return p
	}
	// Anything at all that is not valid JSON sent in an MCP context.
	if mcpCtx && !strictJSONOrEmpty(data) {
		p.refusal = s.mcpUnparseable(server)
		return p
	}
	return nil
}

// mcpRequest decides an allowed request whose body mcpPrepare read. It
// returns what it learned if the body is MCP, and a refusal if a tool call
// in it may not go out.
func (s *Server) mcpRequest(ctx context.Context, r *http.Request, p *mcpPrep) (*mcpExchange, *mcpRefusal) {
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
	if p == nil {
		return nil, nil
	}
	if p.refusal != nil {
		return nil, p.refusal
	}
	body, server := p.body, p.server
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
	return nil, s.retryHold(refuseMessages(body, refused, *first, server))
}

// refuseMessages answers a refused request body: every request in it gets
// an error, the refused calls with their own reason (all of them with
// first's when refused is nil), the rest because they came in the same
// batch. One refused call stops the whole request: an HTTP request goes
// out whole or not at all.
func refuseMessages(body *mcp.Body, refused map[int]mcp.Verdict, first mcp.Verdict, server string) *mcpRefusal {
	notSent := mcp.Verdict{Outcome: mcp.OutcomeDeny, Reasons: []string{"mcp_batch_refused"}, Detail: "not sent: another call in the same batch was refused"}
	parts := make([][]byte, 0, len(body.Messages))
	for i, msg := range body.Messages {
		if msg.ID == nil || msg.Method == "" {
			continue
		}
		v, ok := refused[i]
		if !ok {
			v = notSent
			if refused == nil {
				v = first
			}
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
	return ref
}

func (s *Server) mcpUnreadable(server string) *mcpRefusal {
	v := mcp.Refused("the MCP message is encoded in a form Ovara cannot read", "mcp_message_unreadable")
	return &mcpRefusal{status: http.StatusBadRequest, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
}

// mcpUnparseable refuses a request that cannot be read strictly.
func (s *Server) mcpUnparseable(server string) *mcpRefusal {
	return &mcpRefusal{status: http.StatusBadRequest, decision: "deny", reasons: []string{mcp.ReasonUnparseable}, body: mcp.ParseErrorResponse(server)}
}

// mcpUnparseableResponse refuses a response that cannot be read strictly.
func mcpUnparseableResponse(server string) *mcpRefusal {
	v := mcp.RefusedUnparseable()
	return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
}

// strictJSONOrEmpty reports a body that is empty or valid JSON (UTF-8, a
// leading byte order mark aside).
func strictJSONOrEmpty(data []byte) bool {
	t := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf")))
	return len(t) == 0 || (json.Valid(t) && utf8.Valid(t))
}

// heldLooksLikeJSONRPC runs mcp.LooksLikeJSONRPC over a whole held body,
// a piece at a time.
func heldLooksLikeJSONRPC(hb *heldBody) bool {
	var sn mcp.Sniffer
	buf := make([]byte, 64<<10)
	r := hb.reader()
	for {
		n, err := r.Read(buf)
		_, _ = sn.Write(buf[:n])
		if sn.Found() {
			return true
		}
		if err != nil {
			return false
		}
	}
}

// contentEncodings lists the codings of a Content-Encoding header, in
// lower case, leaving out "identity".
func contentEncodings(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if t := strings.ToLower(strings.TrimSpace(tok)); t != "" && t != "identity" {
				out = append(out, t)
			}
		}
	}
	return out
}

// jsonContentType reports a request whose Content-Type says JSON, or that
// has none (a server may then read it as JSON anyway).
func jsonContentType(h http.Header) bool {
	v := h.Values("Content-Type")
	return len(v) == 0 || strings.Contains(strings.ToLower(strings.Join(v, ",")), "json")
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
	server := m.server(r.URL)
	if x != nil {
		server = x.server
	}
	// An MCP exchange: the request was MCP, the client says it is in an MCP
	// session, or the server is known to speak MCP. Its answer must name
	// one plain type, JSON or an event stream; every client reads those,
	// while what a client still reads under a looser name (SDKs match
	// prefixes or substrings, and join repeated headers) would otherwise
	// pass unchecked.
	mcpCtx := x != nil || isMCPSession(r) || m.isKnown(server)
	cts := resp.Header.Values("Content-Type")
	mt := ""
	if len(cts) == 1 {
		mt = mediaType(resp.Header)
	}
	isSSE := mt == "text/event-stream"
	isJSON := mt == mediaJSON
	if !mcpCtx {
		// Any other event stream is still read for JSON-RPC events.
		if !strings.Contains(strings.ToLower(strings.Join(cts, ",")), "text/event-stream") {
			return nil
		}
		isSSE, isJSON = true, false
	}
	if mcpCtx && !isSSE && !isJSON {
		// An error status is not read as a message by MCP clients, and an
		// empty answer (202 Accepted) carries none.
		if resp.StatusCode/100 != 2 || emptyBody(resp) {
			return nil
		}
		v := mcp.Refused("the MCP response's content type is not exactly one of application/json or text/event-stream", "mcp_unexpected_content_type")
		return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
	}
	if len(contentEncodings(resp.Header.Values("Content-Encoding"))) > 0 {
		if mcpCtx || acceptsEventStream(r) {
			v := mcp.Refused("the response is encoded in a form Ovara cannot read", "mcp_message_unreadable")
			return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
		}
		return nil
	}
	if isSSE {
		f := &sseFilter{
			ctx: ctx, s: s, m: m, req: r, server: server, cut: cut,
			ev:        mcp.NewEventReader(resp.Body, mcp.MaxMessageBytes),
			mcpStream: mcpCtx,
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, mcp.MaxMessageBytes+1))
	if err != nil || len(data) > mcp.MaxMessageBytes {
		if (x != nil && len(x.toolListIDs) > 0) || err != nil {
			v := mcp.Refused("the response is too large to check, or could not be read", "mcp_response_unchecked")
			return &mcpRefusal{status: http.StatusBadGateway, decision: "deny", reasons: v.Reasons, body: mcp.ErrorResponse(nil, v.Detail, v.ErrorData(server))}
		}
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), resp.Body))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if resp.StatusCode/100 == 2 && !strictJSONOrEmpty(data) {
		// What cannot be read strictly cannot be checked; a lenient client
		// might still read a tool list in it.
		return mcpUnparseableResponse(server)
	}
	// The client gets the canonical encoding of what was checked, not the
	// server's bytes (see canonical.go). A 2xx answer readers disagree on
	// (duplicate or case-variant keys, invalid UTF-8) is refused.
	res, canonical := m.gate.CheckServerBody(ctx, server, data, resp.StatusCode/100 == 2)
	if !res.Verdict.Allowed() {
		return refusalFor(res, server)
	}
	if canonical != nil {
		resp.Body = io.NopCloser(bytes.NewReader(canonical))
		resp.ContentLength = int64(len(canonical))
		resp.Header.Set("Content-Length", strconv.Itoa(len(canonical)))
	}
	return nil
}

// emptyBody reports a response with no body bytes at all, reading at most
// one byte (put back).
func emptyBody(resp *http.Response) bool {
	if resp.Body == nil || resp.Body == http.NoBody {
		return true
	}
	var one [1]byte
	n, err := io.ReadFull(resp.Body, one[:])
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		return true
	}
	resp.Body = readCloser{io.MultiReader(bytes.NewReader(one[:n]), resp.Body), resp.Body}
	return false
}

type readCloser struct {
	io.Reader
	io.Closer
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
	if !ev.HasData || data == "" {
		return raw
	}
	if f.mcpStream && (ev.Name == "" || ev.Name == "message") && !strictJSONOrEmpty([]byte(data)) {
		// A message event of an MCP stream that cannot be read strictly
		// cannot be checked.
		return f.refuse(mcp.ServerResult{IsMCP: true, HasTools: true, Verdict: mcp.RefusedUnparseable()})
	}
	jsonish := data[0] == '{' || data[0] == '['
	if !(jsonish && (f.mcpStream || strings.Contains(strings.ToLower(data), "jsonrpc"))) && !mcp.LooksLikeJSONRPC([]byte(data)) {
		// a stream not known to carry MCP: only what could be JSON-RPC is
		// looked at
		return raw
	}
	res, canonical := f.m.gate.CheckServerBody(f.ctx, f.server, []byte(ev.Data), f.mcpStream)
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
	if !res.Verdict.Allowed() {
		return f.refuse(res)
	}
	if canonical == nil {
		// not JSON at all: no JSON reader takes it for a message
		return raw
	}
	// What was checked is what the client reads: the event rebuilt around
	// the canonical encoding (one data line; see canonical.go).
	return ev.Rebuild(canonical)
}

// refuse records a refused event and returns what is relayed in its place.
func (f *sseFilter) refuse(res mcp.ServerResult) []byte {
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

// mediaJSON is the JSON media type.
const mediaJSON = "application/json"
