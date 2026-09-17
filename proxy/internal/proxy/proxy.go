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
	"path"
	"strings"
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
	escalateTimeout time.Duration
	escalatePoll    time.Duration
	gitGate         bool
	sensitiveHosts  []string
}

func New(c *ca.CA, gw *gateway.Client, bindings []creds.Binding, chain *receipts.Chain, failOpen bool) *Server {
	return &Server{
		ca: c, gw: gw, bindings: bindings, chain: chain, failOpen: failOpen,
		escalateTimeout: 60 * time.Second,
		// Git push gating is on by default: it only appends ref names to the
		// policy resource string and changes nothing for non-push requests.
		gitGate: true,
		escalatePoll:    2 * time.Second,
		transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
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
	host := r.Host
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		return
	}
	cert, err := s.ca.CertFor(host)
	if err != nil {
		log.Printf("mitm: cert for %s: %v", host, err)
		client.Close()
		return
	}
	// Advertise http/1.1 only; h2 policy granularity is future work.
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: handshake with client for %s: %v", host, err)
		client.Close()
		return
	}
	// Serve HTTP inside the TLS tunnel. One CONNECT = one host; keep-alive
	// handled by the one-shot server.
	listener := &oneShotListener{conn: tlsConn, done: make(chan struct{})}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = host
		s.handleRequest(w, r)
	})}
	go srv.Serve(listener)
}

type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.done
		return nil, fmt.Errorf("closed")
	}
	l.once = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { close(l.done); return l.conn.Close() }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// handleRequest evaluates, executes, and receipts one request.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	// Git push gating: if this is a git-receive-pack request, append the
	// target ref names to the resource string used for policy evaluation
	// and receipts. The body is buffered (bounded) and restored so upstream
	// still receives the full stream.
	url += s.gitResourceSuffix(r)
	decision := "error"
	status := 0
	defer func() {
		if _, err := s.chain.Record(r.Method, url, decision, status); err != nil {
			log.Printf("receipt: %v", err)
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
	case "deny":
		writeJSON(http.StatusForbidden, map[string]any{"error": "action denied", "decision_id": d.DecisionID, "reasons": d.ReasonCodes})
		return
	case "escalate":
		outcome, approvalID := s.awaitEscalation(r.Context(), d, r.Method, url)
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
	}

	// allow: inject real credentials for this host, execute on behalf.
	host := r.URL.Hostname()
	if headers := creds.Match(s.bindings, host); headers != nil {
		for k, v := range headers {
			r.Header.Set(k, v)
		}
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		decision = "error"
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	for k, vv := range resp.Header {
		for _, v := range vv {
			if strings.EqualFold(k, "Transfer-Encoding") {
				continue
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
