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
)

// normalizeHost returns the canonical form of a host name for every policy,
// sensitive-host and credential comparison: lower case, no trailing dot, no
// port. Without this "Internal.Example.com." would not
// match the glob "internal.example.com" and would skip forced approval.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
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
	maxReadQueryBytes = 512
)

// readCarriesData reports why a read-class request should be escalated, or "".
func readCarriesData(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		return "read_with_body"
	}
	if len(r.URL.RawQuery) > maxReadQueryBytes {
		return "read_with_large_query"
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
