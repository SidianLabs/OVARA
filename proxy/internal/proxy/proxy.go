// Package proxy is the executor chokepoint: an HTTP forward proxy with
// CONNECT + MITM support. Every request is evaluated against the gateway,
// allowed requests have real credentials injected and are executed by the
// proxy itself, and every transit is receipted.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"unicode/utf8"

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
	agentToken      string // if set, proxy clients must authenticate
	unauthLimiter   *rateLimiter
	escalateSem     chan struct{} // caps requests parked awaiting approval
	pkgGate         *packageGate  // strict installs (packages.go); nil = off
	modelGateOff    bool          // model-API body check (modelgate.go) disabled
	modelHosts      []string      // hosts the model gate applies to; nil = defaults
	modelGateNoAsk  bool          // model-gate findings are refused, not asked
	limits          limits        // body, push and read size bounds (limits.go)
	budget          *egressBudget // per-host allowance for allowed traffic; nil = off

	// per-agent state
	ids         *agentRegistry // named agents and stopped agents (agents.go)
	taint       *taintTracker  // untrusted read, then write (taint.go); nil = off
	modelBudget *modelBudget   // per-agent model use (modelbudget.go); nil = off
}

// maxPendingEscalations bounds how many requests may be held waiting for a
// human at once; beyond it new escalations are refused rather than queued.
const maxPendingEscalations = 64

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
		unauthLimiter:  newRateLimiter(20, 1),
		escalateSem:    make(chan struct{}, maxPendingEscalations),
		limits:         defaultLimits(),
		budget:         newEgressBudget(0, 0),
		ids:            newAgentRegistry(),
		taint:          newTaintTracker(),
		modelBudget:    newModelBudget(0, 0, 0),
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

// SetClientAuth requires every proxy client to present token via
// Proxy-Authorization (Basic password or Bearer — what tools send when the
// proxy URL carries credentials). Without it the proxy is an open
// credential dispenser for anyone who can reach the listener.
func (s *Server) SetClientAuth(token string) { s.agentToken = token }

func matchHostGlob(globs []string, host string) bool {
	host = normalizeHost(host)
	for _, g := range globs {
		g = normalizeHost(g)
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

// checkLiteralDestination refuses non-public IP literals without doing any
// DNS lookup. Host names pass; they are validated at dial time.
func (s *Server) checkLiteralDestination(host string) error {
	if !s.publicEgress {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip) {
		return fmt.Errorf("non-public address %s", ip)
	}
	return nil
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
	c.User = nil // userinfo can carry credentials — never into receipts/policy
	return c.String()
}

// maxResourceBytes bounds the resource string sent to the gateway and
// written to every receipt: a long path must not inflate the signed log.
const maxResourceBytes = 2048

// capResource cuts s to maxResourceBytes with a marker saying how much was
// cut, and reports whether it did.
func capResource(s string) (string, bool) {
	if len(s) <= maxResourceBytes {
		return s, false
	}
	n := maxResourceBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + fmt.Sprintf("…(+%d bytes)", len(s)-n), true
}

// allowedGitRefusal returns why a git request policy allowed must still be
// refused, or "". url is the resource policy decided on.
func (s *Server) allowedGitRefusal(r *http.Request, hb *heldBody, url string) string {
	if isUploadPackPost(r) {
		return uploadPackRefusal(r, hb, s.limits.maxUploadPack)
	}
	// An allow decided without seeing every ref being pushed is not an
	// answer about this push: ref-level rules could not have applied.
	if s.gitGate && looksLikePush(r) && (strings.HasSuffix(url, pushUnparsed) || strings.HasSuffix(url, pushTruncated)) {
		return "git_push_unparsed"
	}
	return ""
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
	// Client authentication FIRST — before CONNECT/receipt/policy anything.
	// An unauthenticated request must not even reach the policy engine.
	id, ok := s.authenticate(r)
	if !ok {
		// Rate-limited: probes leave evidence, but anyone who can reach the
		// port must not be able to grow the receipt log without bound.
		if s.unauthLimiter == nil || s.unauthLimiter.allow() {
			s.recordDenied(r.Method+" UNAUTH", r.Host)
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="ovara"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if s.refuseStopped(w, r, id) {
		return
	}
	r = withAgent(r, id)
	r.Method = strings.ToUpper(r.Method)
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// Plain proxy request (absolute URI). An https:// one is TLS to the
	// upstream just like a CONNECT tunnel, so the same port rule holds.
	if p := r.URL.Port(); s.connectPort443 && strings.EqualFold(r.URL.Scheme, "https") && p != "" && p != "443" {
		s.recordDeniedBy(id, r.Method, r.URL.Scheme+"://"+r.URL.Host)
		http.Error(w, "https requests are limited to port 443", http.StatusForbidden)
		return
	}
	s.handleRequest(w, r)
}

// handleConnect hijacks the tunnel and MITMs the TLS inside it.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	id := agentOf(r.Context())
	hostname, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		// CONNECT authority without a port is TLS by convention.
		hostname, port = r.Host, "443"
	}
	hostname = normalizeHost(hostname)
	// CONNECT is for HTTPS tunneling only — an arbitrary port would turn
	// this into a generic TCP relay (SSH, redis, ...) past the boundary.
	// Tunnel-layer rejects are receipted too: a probing agent must leave
	// evidence, not just an invisible 403.
	if s.connectPort443 && port != "443" {
		s.recordDeniedBy(id, "CONNECT", r.Host)
		http.Error(w, "CONNECT limited to port 443", http.StatusForbidden)
		return
	}
	// Only IP literals are checked here. A host NAME is deliberately not
	// resolved before policy has seen a request for it: a lookup of
	// "<stolen-data>.attacker.example" would leak the data through the
	// resolver even if policy then denies it. Names are resolved (and the
	// answers checked) at dial time, after the policy decision.
	if err := s.checkLiteralDestination(hostname); err != nil {
		log.Printf("connect: destination %s rejected: %v", hostname, err)
		s.recordDeniedBy(id, "CONNECT", r.Host)
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
	// A client that never completes the handshake must not hold the
	// connection (and a goroutine) open forever.
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: handshake with client for %s: %v", hostname, err)
		client.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
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
		// Same header bound as the outer listener: inside the tunnel the
		// default would allow 1 MiB of headers per request.
		MaxHeaderBytes: 64 << 10,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(hostname, port)
			s.handleRequest(w, withAgent(r, id))
		}),
	}
	go srv.Serve(listener)
}

// recordDenied appends a deny receipt for requests rejected before the
// policy pipeline (CONNECT-layer rejects). Best-effort: a chain failure is
// logged, not retried — same posture as the deferred receipt path.
func (s *Server) recordDenied(method, target string) {
	agent := ""
	if !strings.HasSuffix(method, " UNAUTH") {
		agent = agentLabel(s.agentToken)
	}
	s.recordDeniedAs(agent, method, target)
}

// recordDeniedBy is recordDenied for a request from a known agent.
func (s *Server) recordDeniedBy(id agentIdentity, method, target string) {
	s.recordDeniedAs(id.label, method, target)
}

func (s *Server) recordDeniedAs(agent, method, target string) {
	if _, err := s.chain.Append(receipts.Entry{Method: method, URL: target, Decision: "deny", Status: http.StatusForbidden, Agent: agent}, false); err != nil {
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
	conn   net.Conn
	done   chan struct{}
	once   *sync.Once // shared with the wrapped eofConn
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
	// One spelling of the method for every check below. The gateway matches
	// methods case-insensitively; a guard that compared against "GET" while
	// policy matched "get" would let the request through unguarded.
	r.Method = strings.ToUpper(r.Method)
	// A tunnel opened before its agent was stopped carries no more requests.
	if s.refuseStopped(w, r, agentOf(r.Context())) {
		return
	}
	// Query strings can carry secrets (tokens, SAS sigs) — the gateway and
	// the receipt log get host+path only.
	url := redactURL(r.URL)
	// The whole body is read before anyone decides anything, and exactly
	// those bytes are sent (body.go). A body too large to hold is refused,
	// not forwarded unseen.
	hb, holdErr := holdBody(r, s.bodyLimit(r))
	defer hb.close()
	// Git push gating: if this is a git-receive-pack request, append the
	// target ref names to the resource string used for policy evaluation
	// and receipts.
	url += s.gitResourceSuffix(r, hb)
	// One bound on the resource for policy and receipts alike. A cut string
	// could move the part a deny rule matches out of sight, so a request
	// whose resource needs cutting is refused, not decided on a prefix.
	url, cut := capResource(url)
	decision := "error"
	status := 0
	approvalID := ""
	facts := &receiptFacts{hb: hb, agent: agentOf(r.Context())}
	// A request that goes upstream is receipted twice: an attempt receipt,
	// synced to disk before the first byte is sent (no receipt, no send),
	// and the final receipt below, which then closes that attempt.
	attemptID := ""
	notSent := false
	var respBytes int64
	attempt := func() error {
		if decision == "allow" {
			s.lookupApprover(r.Context(), facts, approvalID)
		}
		e := s.receiptEntry(facts, r.Method, url, decision, 0, approvalID)
		e.Phase, e.Outcome = "attempt", "sent"
		rc, err := s.chain.Append(e, true)
		if rc != nil {
			attemptID = rc.ReceiptID
		}
		return err
	}
	// The final receipt is written exactly once: before the upstream
	// response headers are sent (so the agent can never hold a response
	// whose receipt is not yet on disk), or on return for every path that
	// never reaches that point.
	var recordOnce sync.Once
	record := func() {
		recordOnce.Do(func() {
			if decision == "allow" {
				s.lookupApprover(r.Context(), facts, approvalID)
			}
			e := s.receiptEntry(facts, r.Method, url, decision, status, approvalID)
			if attemptID != "" {
				e.Phase, e.AttemptID, e.RespBytes = "outcome", attemptID, respBytes
				if notSent {
					e.Outcome = "not_sent"
				}
			}
			if _, err := s.chain.Append(e, false); err != nil {
				// A transit without a receipt is a boundary breach: scream to
				// stderr in fail-closed mode, not just the log stream.
				msg := fmt.Sprintf("receipt record failed for %s %s: %v", r.Method, url, err)
				log.Printf("CRITICAL: %s", msg)
				if !s.failOpen {
					fmt.Fprintf(os.Stderr, "CRITICAL: %s\n", msg)
				}
			}
		})
	}
	defer record()

	writeJSON := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
		status = code
	}
	switch {
	case errors.Is(holdErr, errBodyTooLarge):
		decision = "deny"
		facts.reasons = []string{"body_too_large_to_review"}
		writeJSON(http.StatusRequestEntityTooLarge, map[string]any{
			"error":   fmt.Sprintf("request body is larger than the %d bytes Ovara holds for review; it was not sent", s.bodyLimit(r)),
			"reasons": []string{"body_too_large_to_review"},
		})
		return
	case holdErr != nil:
		decision = "deny"
		facts.reasons = []string{"body_unreadable"}
		writeJSON(http.StatusBadRequest, map[string]any{"error": "could not read the request body", "reasons": []string{"body_unreadable"}})
		return
	case cut:
		decision = "deny"
		facts.reasons = []string{"resource_too_long"}
		writeJSON(http.StatusForbidden, map[string]any{"error": "action denied", "reasons": []string{"resource_too_long"}})
		return
	}

	failedOpen := false
	d, err := s.gw.CheckWithContext(r.Context(), r.Method, url, withAgentPreview(r.Context(), requestContext(r, hb)))
	if err != nil {
		log.Printf("gateway check failed for %s: %v", url, err)
		if !s.failOpen {
			decision = "deny"
			status = http.StatusBadGateway
			facts.reasons = []string{"gateway_unreachable"}
			http.Error(w, `{"error":"gateway unreachable, fail-closed"}`, http.StatusBadGateway)
			return
		}
		d = &gateway.Decision{Decision: "allow"}
		failedOpen = true
		facts.reasons = []string{"gateway_unreachable_fail_open"}
	}
	facts.gw = d
	// Pivot-risk hosts are never reachable on a policy "allow" alone. This is a
	// DENY, not a pause: the gateway only opens an approval for a decision it
	// recorded as escalate (it refuses with 409 for an allowed one, on purpose),
	// so a proxy-forced "escalate" could never be approved and only ever looked
	// like a pause. To permit such a host, change the policy.
	if d.Decision == "allow" && matchHostGlob(s.sensitiveHosts, r.URL.Hostname()) {
		d.Decision = "deny"
		d.ReasonCodes = append(d.ReasonCodes, "sensitive_host")
	}
	// A "read" that carries a body or a huge query string can move data out
	// even though policy allowed the verb; the query is hidden from policy
	// (it can hold secrets), so shape is the only signal we have.
	modelFinding := ""
	if d.Decision == "allow" && !failedOpen {
		if why := s.readCarriesData(r); why != "" {
			d.Decision = "deny"
			d.ReasonCodes = append(d.ReasonCodes, why)
		} else if why := s.allowedGitRefusal(r, hb, url); why != "" {
			d.Decision = "deny"
			d.ReasonCodes = append(d.ReasonCodes, why)
		} else if why := s.modelRequestRefusal(r, hb); why != "" {
			if s.modelGateNoAsk || !modelAskable(why) {
				d.Decision = "deny"
				d.ReasonCodes = append(d.ReasonCodes, why)
			} else {
				modelFinding = why // asked below, once the URL decision is settled
			}
		}
	}
	decision = d.Decision

	// second answers the proxy's own follow-up questions (askAction). It
	// writes the refusal and returns false unless the request may go on.
	second := func(outcome, id string, about map[string]any) bool {
		if id != "" {
			approvalID = id
		}
		switch outcome {
		case pkgAllow, pkgApproved:
			return true
		case pkgTimeout:
			decision = "escalate"
			about["error"] = "approval timeout"
			about["approval_id"] = approvalID
			writeJSON(http.StatusGatewayTimeout, about)
		case pkgAborted:
			decision = "escalate"
		case pkgError:
			decision = "deny"
			about["error"] = "gateway unreachable, fail-closed"
			writeJSON(http.StatusBadGateway, about)
		default:
			decision = "deny"
			about["approval_id"] = approvalID
			writeJSON(http.StatusForbidden, about)
		}
		return false
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

	// Strict installs: downloading a package the project has not pinned is
	// a second question, about the package (packages.go). Only a download
	// the URL policy itself allowed is asked; one a person already approved
	// as a URL needs no second answer. Either way, a package whose lockfile
	// records a digest must arrive with that digest.
	var pkgDigests []string
	if !failedOpen && r.Method == http.MethodGet {
		if ref, ok := s.packageDownload(r.URL.Hostname(), r.URL.Path); ok {
			pkgDigests = s.packageDigests(ref)
		}
	}
	if d.Decision == "allow" && !failedOpen {
		if ref, ok := s.packageDownload(r.URL.Hostname(), r.URL.Path); ok {
			outcome, id := s.checkPackage(r.Context(), ref, url)
			if !second(outcome, id, map[string]any{"error": "package not allowed", "package": ref}) {
				return
			}
		}
		// A model request that makes the provider reach out on the agent's
		// behalf is a person's call, with the request in front of them.
		if modelFinding != "" {
			host := normalizeHost(r.URL.Hostname())
			preview := requestContext(r, hb)
			if preview == nil {
				preview = map[string]string{}
			}
			preview["model_feature"] = modelFinding
			outcome, id := s.askAction(r.Context(), actionModelFeature, "model:"+host+" "+modelFinding, preview, "uses a provider-side feature")
			if !second(outcome, id, map[string]any{"error": "action denied", "reasons": []string{modelFinding}}) {
				return
			}
		}
		// A write soon after the agent read untrusted content, and model use
		// past the agent's budget, are questions too (taint.go,
		// modelbudget.go).
		if !s.agentQuestions(r, hb, url, facts, second) {
			return
		}
		// Allowed traffic is metered per host; past the allowance a person
		// is asked (budget.go). Model calls resend their whole conversation
		// every turn, so only their count is metered, not their size.
		host := normalizeHost(r.URL.Hostname())
		n := int64(readRequestBytes(r))
		if hb != nil && !s.isModelHost(host) {
			n += hb.size
		}
		outcome, id := s.checkBudget(r.Context(), host, n)
		if !second(outcome, id, map[string]any{"error": "egress budget exceeded", "reasons": []string{"egress_budget_exceeded"}, "host": host}) {
			return
		}
	}

	// Reading content anyone can write marks the agent (taint.go).
	taintSrc := ""
	if !failedOpen {
		taintSrc = s.readTaintSource(r, url, d, modelFinding)
	}
	if taintSrc != "" {
		facts.reasons = append(facts.reasons, "untrusted_read")
	}

	// SSRF guard: the policy decision says nothing about WHERE this goes —
	// refuse loopback/private/link-local/metadata destinations outright.
	host := normalizeHost(r.URL.Hostname())
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
	// Fail-open lets traffic through without a policy decision; it must
	// never also hand that traffic the real credentials.
	//
	// Hop-by-hop headers go first — notably Upgrade/Connection, which would
	// otherwise turn one approved GET into an uninspected byte stream — so
	// that a Connection token cannot name, and remove, a header added here.
	stripHopHeaders(r.Header)
	var injected [][]byte
	if r.URL.Scheme == "https" && !failedOpen {
		// A binding names the port it is for (443 unless it says otherwise)
		// and may be limited to some paths and methods.
		port := r.URL.Port()
		if port == "" {
			port = "443"
		}
		if headers := creds.MatchRequest(s.bindings, creds.Request{Host: host, Port: port, Method: r.Method, Path: r.URL.Path}); headers != nil {
			// The agent's own credentials never ride along with ours.
			stripCredentialHeaders(r.Header)
			for k, v := range headers {
				r.Header.Set(k, v)
				injected = append(injected, secretTargets(k, v)...)
			}
		}
	}
	stripMethodOverride(r.Header)
	if len(pkgDigests) > 0 {
		// The digest is of the whole file as published: no fragment, no
		// encoding the client asked for (the transport still negotiates
		// gzip and decodes it).
		r.Header.Del("Range")
		r.Header.Del("If-Range")
		r.Header.Del("Accept-Encoding")
	}
	if len(injected) > 0 {
		// The response is scrubbed for reflected credentials, which only
		// works on the whole, plain body. An agent-chosen Accept-Encoding
		// would get gzip/br bytes the scrubber cannot see into, and Range
		// would return fragments of a secret that never match it whole.
		// With Accept-Encoding unset the transport still negotiates gzip
		// upstream and decompresses before we read (SEC-0001).
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Range")
		r.Header.Del("If-Range")
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
	// No receipt on disk, no request upstream: a full disk must not turn
	// into egress that leaves no trace.
	if err := attempt(); err != nil {
		msg := fmt.Sprintf("attempt receipt for %s %s could not be written: %v", r.Method, url, err)
		log.Printf("CRITICAL: %s", msg)
		if !s.failOpen {
			fmt.Fprintf(os.Stderr, "CRITICAL: %s\n", msg)
			decision = "error"
			notSent = true
			http.Error(w, "receipt could not be written; not forwarding", http.StatusBadGateway)
			status = http.StatusBadGateway
			return
		}
	}
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		decision = "error"
		log.Printf("upstream %s %s: %v", r.Method, url, err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	s.noteRead(r.Context(), taintSrc)
	status = resp.StatusCode
	respBytes = resp.ContentLength
	stripHopHeaders(resp.Header)
	if len(injected) > 0 {
		if ce := encodedValue(resp.Header.Values("Content-Encoding")); ce != "" {
			// Upstream encoded the body although we did not ask for it:
			// it cannot be scrubbed, so it is not delivered.
			decision = "deny"
			log.Printf("upstream %s sent Content-Encoding %q on a credentialed response; refusing (cannot scrub)", url, ce)
			http.Error(w, "upstream sent an encoded response that cannot be checked for leaked credentials", http.StatusBadGateway)
			status = http.StatusBadGateway
			return
		}
		// Redaction changes the body length.
		resp.Header.Del("Content-Length")
	}
	// Reflector-class exfil: a bound host that echoes request data
	// (httpbin /headers, debug endpoints, request-bin services) would hand
	// the injected credentials straight back to the agent. Scrub the
	// injected values, in their common encodings, from response header
	// names and values, body and trailers — the agent sees "[REDACTED]"
	// where its own credential was reflected. Signed URL parameters the
	// upstream minted from the credential (a Location to a presigned
	// download) are redacted too; in the body, for text types only.
	var set *secretSet
	if len(injected) > 0 {
		set = newSecretSet(injected)
	}
	copyScrubbedHeader(w.Header(), resp.Header, "", set)
	// Receipt first, then the response: status and decision are final here.
	record()
	w.WriteHeader(resp.StatusCode)
	body := io.Reader(resp.Body)
	var verify *digestReader
	if len(pkgDigests) > 0 && resp.StatusCode == http.StatusOK {
		verify = newDigestReader(resp.Body, pkgDigests)
		body = verify
	}
	if len(injected) > 0 {
		body = newScrubReader(body, injected)
		if textualType(resp.Header.Get("Content-Type")) {
			body = newSignedParamReader(body)
		}
	}
	usage := s.watchModelUsage(r, resp, &body)
	copyFlush(w, body)
	usage.finish()
	if verify != nil && errors.Is(verify.err, errDigestMismatch) {
		// The client has everything but the last bytes; abort the
		// connection so it cannot take a cut body for a whole one.
		log.Printf("CRITICAL: %s %s does not match the digest in the project's lockfile; the download was cut", r.Method, url)
		if _, err := s.chain.Record(r.Method, url, "deny", http.StatusBadGateway, ""); err != nil {
			log.Printf("CRITICAL: receipt record failed for cut download %s %s: %v", r.Method, url, err)
		}
		panic(http.ErrAbortHandler)
	}
	// resp.Trailer values populate after body read; forward them properly.
	// Scrub here too — a reflector can echo injected credentials in
	// trailers just as well as in headers or the body.
	copyScrubbedHeader(w.Header(), resp.Trailer, http.TrailerPrefix, set)
}

// encodedValue returns the first Content-Encoding value that is not identity,
// or "". Every value counts: a header list of "identity" then "gzip" is a
// gzip body.
func encodedValue(vals []string) string {
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if t := strings.TrimSpace(tok); t != "" && !strings.EqualFold(t, "identity") {
				return t
			}
		}
	}
	return ""
}

// awaitEscalation registers an approval request for an escalated decision and
// holds until it is approved, denied, the escalate window elapses, or the
// client disconnects. Returns the outcome and the approval_id ("" if the
// gateway could not register one).
func (s *Server) awaitEscalation(ctx context.Context, d *gateway.Decision, method, url string) (string, string) {
	return s.holdForApproval(ctx, url, func() (string, error) {
		if d.ApprovalID != "" {
			return d.ApprovalID, nil
		}
		return s.gw.CreateApproval(ctx, d, method, url)
	})
}

// holdForApproval opens an approval with create and waits for its answer,
// within the escalate window and the cap on parked requests.
func (s *Server) holdForApproval(ctx context.Context, what string, create func() (string, error)) (string, string) {
	// Bound the number of requests parked on a human: an agent that opens
	// hundreds of escalating requests must not exhaust goroutines, sockets
	// or the approval queue. Over the cap the request is refused.
	if s.escalateSem != nil {
		select {
		case s.escalateSem <- struct{}{}:
			defer func() { <-s.escalateSem }()
		default:
			log.Printf("escalate: %d approvals already pending; refusing %s", cap(s.escalateSem), what)
			return "denied", ""
		}
	}
	approvalID, err := create()
	if err != nil {
		log.Printf("escalate: create approval for %s failed: %v", what, err)
		return "denied", ""
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
			// One last look: an answer given inside the final poll interval
			// must not be lost, or the person approves a request that then
			// reports a timeout and comes back as a retry.
			if status, err := s.gw.ApprovalStatus(ctx, approvalID); err == nil && status != "pending" {
				return status, approvalID
			}
			return "timeout", approvalID
		case <-ticker.C:
			if s.agentStopped(ctx) {
				return "denied", approvalID
			}
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
