package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// normalizeHost returns the canonical form of a host name for every policy,
// sensitive-host and credential comparison: lower case, no trailing dot, no
// port. Without this "Internal.Example.com." would not
// match the glob "internal.example.com" and would skip forced approval.
func normalizeHost(host string) string {
	// Normalize to a fixed point. One pass peels one layer (port, dots,
	// brackets); hostile inputs like "[:]:0" have several, and two code
	// paths that normalize a different number of times would disagree about
	// whether the same host is "sensitive". Each pass never lengthens the
	// string, so this terminates quickly.
	for i := 0; i < 8; i++ {
		n := normalizeHostOnce(host)
		if n == host {
			return n
		}
		host = n
	}
	return host
}

func normalizeHostOnce(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Every trailing dot and space, not just one: "a.com.." must reach the
	// same canonical form as "a.com", and the result must be stable under
	// repeated normalization (the fuzz test enforces both).
	host = strings.TrimFunc(host, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
	host = strings.ToLower(host)
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return strings.Trim(host, "[]")
	}
	return host
}

// methodOverrideHeaders let a client turn an approved POST into another
// verb on upstreams that honour them, so the verb the human approved is not
// the verb that executes. They are never forwarded.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
}

func stripMethodOverride(h http.Header) {
	for _, k := range methodOverrideHeaders {
		h.Del(k)
	}
}

// Limits for request shapes that policy cannot see into. A GET that carries
// a body or a very long query is a data-carrying request wearing a read's
// clothes, so it is escalated even when a rule allows reads.
const (
	maxReadQueryBytes     = 512
	defaultMaxReadRequest = 2048
	// A standard header (User-Agent, Accept...) is free up to this size; past
	// it, all of it counts, so it cannot become the place the data goes.
	freeStandardHeaderBytes = 256
)

// standardHeaders are the request headers every client sends. They are left
// out of the approver's header list and, up to a size, out of the read budget.
var standardHeaders = map[string]bool{
	"Accept": true, "Accept-Encoding": true, "User-Agent": true, "Content-Length": true,
	"Content-Type": true, "Connection": true, "Host": true,
}

// notForwarded are request headers the proxy never sends upstream, so they
// carry nothing out.
func notForwarded(name string) bool {
	if strings.EqualFold(name, "Proxy-Authorization") {
		return true
	}
	for _, h := range hopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	for _, h := range methodOverrideHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// readRequestBytes is what a read carries out besides its body: the path, the
// query and the headers that will be forwarded.
func readRequestBytes(r *http.Request) int {
	n := len(r.URL.EscapedPath()) + len(r.URL.RawQuery)
	for k, vv := range r.Header {
		if notForwarded(k) {
			continue
		}
		for _, v := range vv {
			size := len(k) + len(v)
			if standardHeaders[http.CanonicalHeaderKey(k)] && size <= freeStandardHeaderBytes {
				continue
			}
			n += size
		}
	}
	return n
}

// readCarriesData reports why a read-class request should be refused, or "".
// A read's path, query and headers carry data just as well as a POST body,
// so they share one budget; the query also keeps its own, smaller cap.
func (s *Server) readCarriesData(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		return "read_with_body"
	}
	if len(r.URL.RawQuery) > maxReadQueryBytes {
		return "read_with_large_query"
	}
	if readRequestBytes(r) > s.limits.maxReadRequest {
		return "read_request_too_large"
	}
	return ""
}

// secretTargets expands one injected header into the strings that must be
// scrubbed from responses: the whole value, the bare token after an auth
// scheme ("Bearer abc" -> "abc"), and URL- and JSON-escaped spellings.
// Non-secret protocol headers (versions, content types) are not scrubbed:
// redacting "2023-06-01" everywhere helps nobody and corrupts responses.
func secretTargets(name, value string) [][]byte {
	if value == "" || isNonSecretHeader(name) {
		return nil
	}
	seen := map[string]bool{}
	var out [][]byte
	add := func(s string) {
		if len(s) >= 8 && !seen[s] {
			seen[s] = true
			out = append(out, []byte(s))
		}
	}
	add(value)
	if _, tok, ok := strings.Cut(value, " "); ok {
		add(tok)
	}
	for _, s := range append([]string(nil), keys(seen)...) {
		add(url.QueryEscape(s))
		if b, err := json.Marshal(s); err == nil && len(b) > 2 {
			add(string(b[1 : len(b)-1]))
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func isNonSecretHeader(name string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "version") {
		return true
	}
	switch n {
	case "accept", "content-type", "user-agent", "accept-language", "x-github-api-version":
		return true
	}
	return false
}

// copyFlush streams src to w and flushes after every chunk, so event
// streams (SSE, chunked LLM output) reach the agent as they arrive instead
// of being held back until a buffer fills.
func copyFlush(w http.ResponseWriter, src io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 16*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

// NewHTTPServer returns the listener-facing server with the limits a
// network-exposed proxy needs. There is deliberately no WriteTimeout:
// approvals hold requests for a long time and responses may stream.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// rateLimiter is a small token bucket used to cap receipts written for
// unauthenticated requests: probes must leave evidence, but anyone who can
// reach the port must not be able to grow the receipt log without bound.
type rateLimiter struct {
	mu      sync.Mutex
	tokens  float64
	max     float64
	perSec  float64
	last    time.Time
	dropped uint64
}

func newRateLimiter(burst, perSec float64) *rateLimiter {
	return &rateLimiter{tokens: burst, max: burst, perSec: perSec, last: time.Now()}
}

// allow reports whether an event may be recorded; dropped counts the rest.
func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.perSec
	if l.tokens > l.max {
		l.tokens = l.max
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	l.dropped++
	return false
}
