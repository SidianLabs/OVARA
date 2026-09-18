// Package proxy is the executor chokepoint: an HTTP forward proxy with
// CONNECT + MITM support. Every request is evaluated against the gateway,
// allowed requests have real credentials injected and are executed by the
// proxy itself, and every transit is receipted.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

type Server struct {
	ca              *ca.CA
	gw              *gateway.Client
	bindings        []creds.Binding
	chain           *receipts.Chain
	failOpen        bool
	transport       *http.Transport
	dialer          *net.Dialer
	publicEgress    bool // SSRF guard: only public destinations may be dialed
	connectPort443  bool // CONNECT targets restricted to :443
	escalateTimeout time.Duration
	escalatePoll    time.Duration
	gitGate         bool
	sensitiveHosts  []string
}

func New(c *ca.CA, gw *gateway.Client, bindings []creds.Binding, chain *receipts.Chain, failOpen bool) *Server {
	s := &Server{
		ca: c, gw: gw, bindings: bindings, chain: chain, failOpen: failOpen,
		escalateTimeout: 60 * time.Second,
		// Git push gating is on by default: it only appends ref names to the
		// policy resource string and changes nothing for non-push requests.
		gitGate:        true,
		publicEgress:   true,
		connectPort443: true,
		escalatePoll:   2 * time.Second,
		dialer:         &net.Dialer{Timeout: 10 * time.Second},
		transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
	// Upstream dials go through the SSRF guard: the transport uses our
	// resolution, so a DNS rebind between check and dial cannot slip a
	// private address through (the classic TOCTOU hole in check-then-dial).
	s.transport.DialContext = s.dialChecked
	return s
}

// SetEscalateWindow configures the hold-and-resume bounds for escalate
// decisions: how long to hold the client request and how often to poll the
// gateway approval status.
func (s *Server) SetEscalateWindow(timeout, poll time.Duration) {
	if timeout > 0 {
		s.escalateTimeout = timeout
	}
	if poll > 0 {
		s.escalatePoll = poll
	}
}

// SetGitGate enables/disables git push (git-receive-pack) ref extraction for
// policy evaluation. Enabled by default in New.
func (s *Server) SetGitGate(on bool) { s.gitGate = on }

// SetSensitiveHosts marks host globs whose requests are always escalated to
// human approval, even when policy allows them. Use it for reachable internal
// services an agent could exploit as an egress pivot (package proxies,
// artifact registries, internal dashboards).
func (s *Server) SetSensitiveHosts(globs []string) { s.sensitiveHosts = globs }

// SetPublicEgressOnly toggles the SSRF destination guard. It defaults ON;
// disable only in tests/demos where upstreams are legitimately loopback.
func (s *Server) SetPublicEgressOnly(on bool) { s.publicEgress = on }

// SetConnectPort443Only toggles the CONNECT :443 restriction. Defaults ON;
// disable only in tests against non-443 upstreams.
func (s *Server) SetConnectPort443Only(on bool) { s.connectPort443 = on }

func matchHostGlob(globs []string, host string) bool {
	for _, g := range globs {
		if g == host {
			return true
		}
		if ok, err := path.Match(g, host); err == nil && ok {
			return true
		}
	}
	return false
}

// nonPublicNets is the destination denylist for the SSRF guard: loopback,
// private, link-local, CGNAT, reserved, and multicast space. The guard is
// strict — ANY non-public answer refuses the request, so a hostname that
// returns mixed public/private answers cannot smuggle an internal target.
var nonPublicNets []*net.IPNet

func init() {
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"192.88.99.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nonPublicNets = append(nonPublicNets, n)
	}
}

func isPublicIP(ip net.IP) bool {
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// resolvePublic resolves host (bounded) and returns the validated public
// IPs to dial, in resolver order. Errors on resolution failure or if ANY
// resolved address is non-public.
func resolvePublic(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("non-public address %s", ip)
		}
		return []net.IP{ip}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("%s resolves to non-public address %s", host, ip)
		}
	}
	return ips, nil
}

// checkDestination refuses requests to non-public destinations (SSRF).
func (s *Server) checkDestination(ctx context.Context, host string) error {
	if !s.publicEgress {
		return nil
	}
	_, err := resolvePublic(ctx, host)
	return err
}

// dialChecked is the transport's dial path: resolve ourselves, reject
// non-public answers, and dial the checked IP. Residual risk: an attacker
// who controls DNS *and* rotates records faster than our resolve→dial
// within this single call still cannot inject a private address, because
// we dial the exact IP we validated.
func (s *Server) dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	if !s.publicEgress {
		return s.dialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolvePublic(ctx, host)
	if err != nil {
		return nil, err
	}
	// Try every validated address in resolver order: a stale first answer
	// must not kill the request when other addrs work. Only IPs that
	// passed the non-public check above are ever dialed.
	var lastErr error
	for _, ip := range ips {
		conn, err := s.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// redactURL strips query and fragment — both can carry secrets that must
// not reach the gateway resource string or the receipt log.
func redactURL(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	c.RawFragment = ""
	c.Fragment = ""
	return c.String()
}

// hopHeaders are connection-scoped headers that must never be forwarded.
// Token names carried in the Connection value are stripped too.
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopHeaders(h http.Header) {
	for _, tok := range strings.Split(h.Get("Connection"), ",") {
		if t := strings.TrimSpace(tok); t != "" {
			h.Del(t)
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// Plain-HTTP proxy request (absolute URI). Execute directly.
	s.handleRequest(w, r)
}

// handleConnect hijacks the tunnel and MITMs the TLS inside it.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostname, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		// CONNECT authority without a port is TLS by convention.
		hostname, port = r.Host, "443"
	}
	hostname = strings.ToLower(hostname)
	// CONNECT is for HTTPS tunneling only — an arbitrary port would turn
	// this into a generic TCP relay (SSH, redis, ...) past the boundary.
	// Tunnel-layer rejects are receipted too: a probing agent must leave
	// evidence, not just an invisible 403.
	if s.connectPort443 && port != "443" {
		s.recordDenied("CONNECT", r.Host)
		http.Error(w, "CONNECT limited to port 443", http.StatusForbidden)
		return
	}
	if err := s.checkDestination(r.Context(), hostname); err != nil {
		log.Printf("connect: destination %s rejected: %v", hostname, err)
		s.recordDenied("CONNECT", r.Host)
		http.Error(w, "destination not allowed", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// Mint before answering 200: a cert failure must not leave the client
	// believing the tunnel exists.
	cert, err := s.ca.CertFor(hostname)
	if err != nil {
		log.Printf("mitm: cert for %s: %v", hostname, err)
		client.Close()
		return
	}
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		return
	}
	// Advertise http/1.1 only; h2 policy granularity is future work.
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: handshake with client for %s: %v", hostname, err)
		client.Close()
		return
	}
	// Serve HTTP inside the TLS tunnel. One CONNECT = one host; keep-alive
	// handled by the one-shot server. done fires on conn EOF/close so the
	// pending Accept (and this goroutine) exit instead of leaking.
	done := make(chan struct{})
	var doneOnce sync.Once
	listener := &oneShotListener{
		conn: &eofConn{Conn: tlsConn, done: done, once: &doneOnce},
		done: done,
		once: &doneOnce,
	}
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(hostname, port)
			s.handleRequest(w, r)
		}),
	}
	go srv.Serve(listener)
}

// recordDenied appends a deny receipt for requests rejected before the
// policy pipeline (CONNECT-layer rejects). Best-effort: a chain failure is
// logged, not retried — same posture as the deferred receipt path.
func (s *Server) recordDenied(method, target string) {
	if _, err := s.chain.Record(method, target, "deny", http.StatusForbidden, ""); err != nil {
		log.Printf("CRITICAL: receipt record failed for denied %s %s: %v", method, target, err)
	}
}

// eofConn closes done when the wrapped connection ends (EOF or Close), so
// the one-shot listener's parked Accept can return.
type eofConn struct {
	net.Conn
	done chan struct{}
	once *sync.Once // shared with oneShotListener so done closes exactly once
}

func (c *eofConn) finish() { c.once.Do(func() { close(c.done) }) }

func (c *eofConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.finish()
	}
	return n, err
}

func (c *eofConn) Close() error {
	c.finish()
	return c.Conn.Close()
}

type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	once *sync.Once // shared with the wrapped eofConn
	served bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.served {
		<-l.done
		return nil, fmt.Errorf("closed")
	}
	l.served = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.conn.Close()
}
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// handleRequest evaluates, executes, and receipts one request.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Query strings can carry secrets (tokens, SAS sigs) — the gateway and
	// the receipt log get host+path only.
	url := redactURL(r.URL)
	// Git push gating: if this is a git-receive-pack request, append the
	// target ref names to the resource string used for policy evaluation
	// and receipts. The body is buffered (bounded) and restored so upstream
	// still receives the full stream.
	url += s.gitResourceSuffix(r)
	decision := "error"
	status := 0
	approvalID := ""
	defer func() {
		if _, err := s.chain.Record(r.Method, url, decision, status, approvalID); err != nil {
			// A transit without a receipt is a boundary breach: scream to
			// stderr in fail-closed mode, not just the log stream.
			msg := fmt.Sprintf("receipt record failed for %s %s: %v", r.Method, url, err)
			log.Printf("CRITICAL: %s", msg)
			if !s.failOpen {
				fmt.Fprintf(os.Stderr, "CRITICAL: %s\n", msg)
			}
		}
	}()

	d, err := s.gw.Check(r.Context(), r.Method, url)
	if err != nil {
		log.Printf("gateway check failed for %s: %v", url, err)
		if !s.failOpen {
			decision = "deny"
			status = http.StatusBadGateway
			http.Error(w, `{"error":"gateway unreachable, fail-closed"}`, http.StatusBadGateway)
			return
		}
		d = &gateway.Decision{Decision: "allow"}
	}
	// Pivot-risk hosts always require approval, regardless of policy allow.
	if d.Decision == "allow" && matchHostGlob(s.sensitiveHosts, r.URL.Hostname()) {
		d.Decision = "escalate"
		d.ReasonCodes = append(d.ReasonCodes, "sensitive_host")
	}
	decision = d.Decision

	writeJSON := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
		status = code
	}

	switch d.Decision {
	case "allow":
		// proceed to execution below
	case "deny":
		writeJSON(http.StatusForbidden, map[string]any{"error": "action denied", "decision_id": d.DecisionID, "reasons": d.ReasonCodes})
		return
	case "escalate":
		outcome, id := s.awaitEscalation(r.Context(), d, r.Method, url)
		approvalID = id
		switch outcome {
		case "approved":
			decision = "allow"
		case "timeout":
			writeJSON(http.StatusGatewayTimeout, map[string]any{"error": "approval timeout", "decision_id": d.DecisionID, "approval_id": approvalID})
			return
		case "aborted":
			return
		default:
			writeJSON(http.StatusForbidden, map[string]any{"error": "action requires approval", "decision_id": d.DecisionID, "approval_id": approvalID, "reasons": d.ReasonCodes})
			return
		}
	default:
		// Unknown/malformed decision strings must never reach execution:
		// a truncated or confused gateway response is not an allow.
		decision = "deny"
		writeJSON(http.StatusBadGateway, map[string]any{"error": "malformed gateway decision"})
		return
	}

	// SSRF guard: the policy decision says nothing about WHERE this goes —
	// refuse loopback/private/link-local/metadata destinations outright.
	host := r.URL.Hostname()
	if err := s.checkDestination(r.Context(), host); err != nil {
		log.Printf("destination %s rejected: %v", host, err)
		decision = "deny"
		http.Error(w, "destination not allowed", http.StatusForbidden)
		status = http.StatusForbidden
		return
	}

	// Inject real credentials for this host — https only. A plaintext http
	// request to a credentialed host is still evaluated and receipted, but
	// nothing is injected: secrets must never transit in cleartext.
	var injected [][]byte
	if r.URL.Scheme == "https" {
		if headers := creds.Match(s.bindings, host); headers != nil {
			for k, v := range headers {
				r.Header.Set(k, v)
				if v != "" {
					injected = append(injected, []byte(v))
				}
			}
		}
	}
	r.RequestURI = ""
	// Reconcile the wire Host header with the enforced destination: in the
	// MITM path r.URL.Host is rewritten to the CONNECT target while r.Host
	// keeps the client's inner Host header, and net/http prefers r.Host on
	// the wire. Without this a client could CONNECT to an allowed host but
	// have upstream see a different vhost (vhost confusion / soft SSRF),
	// and creds.Match would disagree with the wire Host. Pin r.Host to the
	// checked destination in this single chokepoint covering both the
	// plain-proxy and MITM paths.
	r.Host = r.URL.Host
	// Strip hop-by-hop headers — notably Upgrade/Connection, which would
	// otherwise turn one approved GET into an uninspected byte stream.
	stripHopHeaders(r.Header)
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		decision = "error"
		log.Printf("upstream %s %s: %v", r.Method, url, err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	stripHopHeaders(resp.Header)
	// Reflector-class exfil: a bound host that echoes request data
	// (httpbin /headers, debug endpoints, request-bin services) would hand
	// the injected credentials straight back to the agent. Scrub the exact
	// injected values from response headers and body — the agent sees
	// "[REDACTED]" where its own credential was reflected.
	for k, vv := range resp.Header {
		for _, v := range vv {
			for _, secret := range injected {
				v = strings.ReplaceAll(v, string(secret), "[REDACTED]")
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	body := io.Reader(resp.Body)
	if len(injected) > 0 {
		body = newScrubReader(resp.Body, injected)
	}
	io.Copy(w, body)
	// resp.Trailer values populate after body read; forward them properly.
	for k, vv := range resp.Trailer {
		w.Header()[http.TrailerPrefix+k] = vv
	}
}

// awaitEscalation registers an approval request for an escalated decision and
// holds until it is approved, denied, the escalate window elapses, or the
// client disconnects. Returns the outcome and the approval_id ("" if the
// gateway could not register one).
func (s *Server) awaitEscalation(ctx context.Context, d *gateway.Decision, method, url string) (string, string) {
	approvalID := d.ApprovalID
	if approvalID == "" {
		id, err := s.gw.CreateApproval(ctx, d, method, url)
		if err != nil {
			log.Printf("escalate: create approval for %s failed: %v", url, err)
			return "denied", ""
		}
		approvalID = id
	}
	deadline := time.NewTimer(s.escalateTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(s.escalatePoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "aborted", approvalID
		case <-deadline.C:
			return "timeout", approvalID
		case <-ticker.C:
			status, err := s.gw.ApprovalStatus(ctx, approvalID)
			if err != nil {
				if ctx.Err() != nil {
					return "aborted", approvalID
				}
				log.Printf("escalate: poll approval %s: %v", approvalID, err)
				continue
			}
			if status != "pending" {
				return status, approvalID
			}
		}
	}
}
