package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ovara.proxy/internal/gateway"
)

// The TCP gate. A CONNECT to a port other than 443 is not HTTPS Ovara can
// open and read: it is a connection to something else (a database, a mail
// server, SSH, gRPC, anything). Refusing it wholesale sends such agents
// around the proxy; relaying it blind would open a way past the boundary.
// The gate decides it like any other action, as tcp.connect on
// tcp:<host>:<port>, with what can be known put in front of a person (what
// the port suggests the connection is for, and that the tunnel is opaque),
// opens it only on an allow or an approval, counts the bytes each way
// against the host's egress budget, and receipts it twice: the attempt
// before the first byte, the outcome with the byte counts when it closes.
// A stopped agent's tunnel is cut within the agent watch interval.

const (
	actionTCPConnect = "tcp.connect"
	// tunnelBudgetChunk is how many bytes a tunnel moves between two
	// charges to the host's egress budget; a charge that does not fit asks
	// a person, and a refusal cuts the tunnel.
	tunnelBudgetChunk = 256 << 10
	tunnelReceiptBase = "tcp://"
)

// SetTCPGate turns the gate on or off. Off (the zero value, what a Server
// starts with), a CONNECT to a port other than 443 is refused when the 443
// restriction is on and treated as TLS to inspect when it is off.
func (s *Server) SetTCPGate(on bool) { s.tcpGate = on }

// tcpProtocols names what a port is conventionally for, so the person asked
// about a tunnel knows what kind of connection it is. A guess from the port,
// said so.
var tcpProtocols = map[string]string{
	"22": "ssh", "23": "telnet", "25": "smtp", "465": "smtps", "587": "smtp submission",
	"110": "pop3", "995": "pop3s", "143": "imap", "993": "imaps",
	"53": "dns", "80": "http", "8080": "http (alternate port)", "8443": "https (alternate port)",
	"389": "ldap", "636": "ldaps", "2049": "nfs", "445": "smb",
	"3306": "mysql", "5432": "postgres", "1433": "mssql", "1521": "oracle", "27017": "mongodb",
	"6379": "redis", "11211": "memcached", "9200": "elasticsearch", "9042": "cassandra",
	"5672": "amqp", "5671": "amqps", "9092": "kafka", "4222": "nats", "1883": "mqtt", "8883": "mqtts",
	"50051": "grpc (conventional port)",
}

func tcpProtocol(port string) string {
	if p, ok := tcpProtocols[port]; ok {
		return p + " (from the port)"
	}
	return "unknown (port " + port + ")"
}

// tcpResource is the policy resource for a tunnel: tcp:<host>:<port>, the
// host normalised like every other, an IPv6 literal in brackets.
func tcpResource(host, port string) string { return "tcp:" + net.JoinHostPort(host, port) }

// handleTunnel decides and, when allowed, relays a CONNECT to a port other
// than 443. It returns when the tunnel is closed.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request, hostname, port string) {
	ctx := r.Context()
	target := net.JoinHostPort(hostname, port)
	resource := tcpResource(hostname, port)
	facts := &receiptFacts{agent: agentOf(ctx)}
	decision, status, approvalID := gwDeny, 0, ""
	attemptID := ""
	var up, down atomic.Int64 // bytes agent -> destination, destination -> agent
	var once sync.Once
	record := func() {
		once.Do(func() {
			if decision == gwAllow {
				s.lookupApprover(ctx, facts, approvalID)
			}
			e := s.receiptEntry(facts, http.MethodConnect, tunnelReceiptBase+target, decision, status, approvalID)
			if attemptID != "" {
				e.Phase, e.AttemptID, e.ReqBytes, e.RespBytes = phaseOutcome, attemptID, up.Load(), down.Load()
			}
			if _, err := s.chain.Append(e, false); err != nil {
				msg := fmt.Sprintf("receipt record failed for CONNECT %s: %v", target, err)
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
		_ = json.NewEncoder(w).Encode(v)
		status = code
	}

	// An IP literal in private space is refused now; a name is resolved
	// only after policy has allowed the connection (never before: the
	// lookup itself would carry data out).
	if err := s.checkLiteralDestination(hostname); err != nil {
		facts.reasons = []string{"destination_not_allowed"}
		writeJSON(http.StatusForbidden, map[string]any{"error": "destination not allowed", "reasons": facts.reasons})
		return
	}
	preview := map[string]string{
		"protocol": tcpProtocol(port),
		"warning":  "opaque tunnel: Ovara cannot see what is sent inside it; the bytes each way are counted against the host's egress budget and receipted",
		"why":      "a connection to a port other than 443 is not HTTPS Ovara can inspect",
	}
	if name, out := s.outOfScope(ctx, resource); out {
		facts.reasons = []string{"agent_scope"}
		writeJSON(http.StatusForbidden, scopeRefusal(name))
		return
	}
	d, err := s.gw.CheckAction(ctx, actionTCPConnect, resource, s.withForPreview(ctx, withAgentPreview(ctx, preview)))
	if err != nil {
		log.Printf("tcp gate: gateway check for %s failed: %v", resource, err)
		if !s.failOpen {
			facts.reasons = []string{"gateway_unreachable"}
			writeJSON(http.StatusBadGateway, map[string]any{"error": "gateway unreachable, fail-closed"})
			return
		}
		d = &gateway.Decision{Decision: gwAllow}
		facts.reasons = []string{"gateway_unreachable_fail_open"}
	}
	facts.gw = d
	switch d.Decision {
	case gwAllow:
	case gwEscalate:
		log.Printf("tcp gate: %s held for approval", resource)
		outcome, id := s.holdForApproval(ctx, resource, func() (string, error) {
			if d.ApprovalID != "" {
				return d.ApprovalID, nil
			}
			return s.gw.CreateApprovalFor(ctx, d, actionTCPConnect, resource)
		})
		approvalID = id
		facts.noteApproval(id)
		switch outcome {
		case pkgApproved:
		case pkgTimeout:
			decision = gwEscalate
			code, body := s.heldAnswer(w, d.DecisionID, id, d.MatchedRule)
			writeJSON(code, body)
			return
		case pkgAborted:
			decision = gwEscalate
			return
		default:
			writeJSON(http.StatusForbidden, withRule(map[string]any{"error": errActionDenied, "decision_id": d.DecisionID, "approval_id": id, "reasons": []string{outcome}}, d.MatchedRule))
			return
		}
	default:
		writeJSON(http.StatusForbidden, withRule(map[string]any{"error": errActionDenied, "decision_id": d.DecisionID, "reasons": d.ReasonCodes}, d.MatchedRule))
		return
	}
	decision = gwAllow
	// The connection itself is one request against the host's budget; its
	// bytes are charged as they flow (relay below).
	if outcome, id := s.checkBudget(ctx, hostname, 0); outcome != pkgAllow {
		facts.noteApproval(id)
		if id != "" {
			approvalID = id
		}
		if !s.tunnelBudgetAnswer(w, writeJSON, outcome, id, &decision) {
			return
		}
	}
	upstream, err := s.dialTunnel(ctx, target)
	if err != nil {
		log.Printf("tcp gate: dial %s: %v", target, err)
		facts.reasons = append(facts.reasons, "dial_failed")
		writeJSON(http.StatusBadGateway, map[string]any{"error": "could not connect to " + target, "reasons": []string{"dial_failed"}})
		return
	}
	defer upstream.Close()
	// The attempt receipt is on disk before the first byte crosses.
	s.lookupApprover(ctx, facts, approvalID)
	e := s.receiptEntry(facts, http.MethodConnect, tunnelReceiptBase+target, decision, 0, approvalID)
	e.Phase, e.Outcome = phaseAttempt, outcomeSent
	rc, err := s.chain.Append(e, true)
	if rc != nil {
		attemptID = rc.ReceiptID
	}
	if err != nil {
		log.Printf("CRITICAL: attempt receipt for CONNECT %s: %v", target, err)
		if !s.failOpen {
			facts.reasons = append(facts.reasons, "receipt_unavailable")
			writeJSON(http.StatusServiceUnavailable, map[string]any{"error": "the receipt could not be written; the connection was not opened", "reasons": []string{"receipt_unavailable"}})
			return
		}
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeJSON(http.StatusInternalServerError, map[string]any{"error": "hijacking unsupported"})
		return
	}
	client, buffered, err := hj.Hijack()
	if err != nil {
		status = http.StatusInternalServerError
		return
	}
	defer client.Close()
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		status = http.StatusInternalServerError
		return
	}
	status = http.StatusOK

	// Relay until either side ends, the agent is stopped, or the budget is
	// refused. Closing both connections ends both copies.
	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var why atomic.Value
	cut := func(reason string) {
		why.CompareAndSwap(nil, reason)
		cancel()
	}
	stopWatch, agentCut := s.cutWhenAgentGone(tctx, cancel)
	defer stopWatch()
	go func() {
		<-tctx.Done()
		_ = client.Close()
		_ = upstream.Close()
	}()
	var fromClient io.Reader = client
	if buffered != nil && buffered.Reader.Buffered() > 0 {
		fromClient = io.MultiReader(io.LimitReader(buffered.Reader, int64(buffered.Reader.Buffered())), client)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.relay(tctx, upstream, fromClient, hostname, &up, cut)
		cancel()
	}()
	go func() {
		defer wg.Done()
		s.relay(tctx, client, upstream, hostname, &down, cut)
		cancel()
	}()
	wg.Wait()
	if agentCut() {
		facts.reasons = append(facts.reasons, "agent_stopped")
	} else if r, _ := why.Load().(string); r != "" {
		facts.reasons = append(facts.reasons, r)
	}
}

// tunnelBudgetAnswer answers a budget question that did not come back
// allowed, the way handleRequest's second questions are answered. It
// reports whether the tunnel may go on (never, here, but kept in one place).
func (s *Server) tunnelBudgetAnswer(w http.ResponseWriter, writeJSON func(int, any), outcome, id string, decision *string) bool {
	about := map[string]any{"error": "egress budget exceeded", "reasons": []string{"egress_budget_exceeded"}}
	switch outcome {
	case pkgAllow, pkgApproved:
		return true
	case pkgTimeout:
		*decision = gwEscalate
		code, body := s.heldAnswer(w, "", id, "")
		for k, v := range body {
			about[k] = v
		}
		writeJSON(code, about)
	case pkgAborted:
		*decision = gwEscalate
	case pkgError:
		*decision = gwDeny
		about["error"] = "gateway unreachable, fail-closed"
		writeJSON(http.StatusBadGateway, about)
	default:
		*decision = gwDeny
		about["approval_id"] = id
		writeJSON(http.StatusForbidden, about)
	}
	return false
}

// relay copies src to dst, counting into n and charging the host's egress
// budget every tunnelBudgetChunk bytes; a charge that is refused cuts the
// tunnel with cut("egress_budget").
func (s *Server) relay(ctx context.Context, dst io.Writer, src io.Reader, host string, n *atomic.Int64, cut func(string)) {
	buf := make([]byte, 32<<10)
	var unbilled int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if _, ew := dst.Write(buf[:nr]); ew != nil {
				return
			}
			n.Add(int64(nr))
			unbilled += int64(nr)
			if unbilled >= tunnelBudgetChunk {
				if outcome, _ := s.checkBudget(ctx, host, unbilled); outcome != pkgAllow {
					cut("egress_budget")
					return
				}
				unbilled = 0
			}
		}
		if er != nil {
			return
		}
	}
}

// dialTunnel opens the raw connection for a tunnel: through the upstream
// proxy with a CONNECT of its own when one is configured (the upstream
// resolves the name), else resolved and checked here (dialChecked).
func (s *Server) dialTunnel(ctx context.Context, target string) (net.Conn, error) {
	if s.upstreamHost == "" || s.transport.Proxy == nil {
		return s.dialChecked(ctx, "tcp", target)
	}
	u, err := s.transport.Proxy(&http.Request{URL: &url.URL{Scheme: schemeHTTPS, Host: target}})
	if err != nil {
		return nil, err
	}
	if u == nil { // the transport has no proxy for this destination
		return s.dialChecked(ctx, "tcp", target)
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := s.dialer.DialContext(dctx, "tcp", s.upstreamHost)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	if u.Scheme == schemeHTTPS {
		cfg := s.transport.TLSClientConfig.Clone()
		cfg.ServerName = u.Hostname()
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream proxy tls: %w", err)
		}
		conn = tc
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u.User != nil {
		pw, _ := u.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)) + "\r\n"
	}
	req += "\r\n"
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	// The status line and headers only: a 200 to a CONNECT has no body,
	// what follows is the tunnel (net/http would read it as a body until
	// EOF).
	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	if parts := strings.SplitN(line, " ", 3); len(parts) < 2 || parts[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy refused the tunnel: %s", line)
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		// bytes the destination sent before we started relaying (a banner)
		return &bufferedConn{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), conn)}, nil
	}
	return conn, nil
}

// bufferedConn is a connection whose first reads come from what a reader
// already buffered.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
