package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ovara.proxy/internal/receipts"
)

// The TCP gate: a CONNECT to a port other than 443 is decided as
// tcp.connect, opened only on an allow or an approval, counted, receipted
// and cut when the agent is stopped or the budget is refused.

// echoServer accepts raw TCP connections and echoes what it reads; accepts
// counts them.
func echoServer(t *testing.T) (addr string, accepts *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), &n
}

const firstApproval = "apr_1" // the scripted gateway's first approval id

func tcpGateServer(t *testing.T, tcpDecision string) (*Server, *actionGateway, string, string) {
	t.Helper()
	srv, ag, chainFile := newActionServer(t, "allow")
	ag.setDecision(actionTCPConnect, tcpDecision)
	srv.SetTCPGate(true)
	srv.SetConnectPort443Only(true) // the gate, not the MITM path, takes the other ports
	ps := httptest.NewServer(srv)
	t.Cleanup(ps.Close)
	return srv, ag, chainFile, strings.TrimPrefix(ps.URL, "http://")
}

// connectThrough sends a CONNECT for target to the proxy at proxyAddr and
// returns the connection, a reader over it, the status line and, for a
// refusal, the body.
func connectThrough(t *testing.T, proxyAddr, target string, hdr map[string]string) (net.Conn, *bufio.Reader, string, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	for k, v := range hdr {
		req += k + ": " + v + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	status := resp.Status
	var body []byte
	if resp.StatusCode != http.StatusOK {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	_ = c.SetReadDeadline(time.Time{})
	return c, br, status, body
}

func allReceiptsOf(t *testing.T, chainFile string) []receipts.Receipt {
	t.Helper()
	data, err := os.ReadFile(chainFile)
	if err != nil {
		t.Fatal(err)
	}
	var out []receipts.Receipt
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r receipts.Receipt
		if json.Unmarshal(line, &r) == nil && r.ReceiptID != "" {
			out = append(out, r)
		}
	}
	return out
}

// tunnelReceipts waits for the outcome receipt of a closed tunnel and
// returns (attempt, outcome).
func tunnelReceipts(t *testing.T, chainFile, target string) (receipts.Receipt, receipts.Receipt) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var attempt, outcome receipts.Receipt
		for _, r := range allReceiptsOf(t, chainFile) {
			if r.Method != http.MethodConnect || r.URL != tunnelReceiptBase+target {
				continue
			}
			switch r.Phase {
			case phaseAttempt:
				attempt = r
			case phaseOutcome:
				outcome = r
			}
		}
		if outcome.ReceiptID != "" {
			return attempt, outcome
		}
		if time.Now().After(deadline) {
			t.Fatalf("no outcome receipt for %s: %+v", target, allReceiptsOf(t, chainFile))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func roundTrip(t *testing.T, c net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo %q, want %q", buf, msg)
	}
}

func TestTCPGate_AllowedTunnelRelaysAndReceiptsBytes(t *testing.T) {
	_, ag, chainFile, proxyAddr := tcpGateServer(t, "allow")
	echo, accepts := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)

	c, br, status, _ := connectThrough(t, proxyAddr, echo, nil)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("CONNECT: %s", status)
	}
	roundTrip(t, c, br, "hello over tcp")
	c.Close()

	checks := ag.of(actionTCPConnect)
	if len(checks) != 1 || checks[0].Resource != "tcp:"+echo {
		t.Fatalf("decision asked for %+v, want tcp:%s", checks, echo)
	}
	if ctx := checks[0].Context; ctx["protocol"] != "unknown (port "+port+")" || !strings.Contains(ctx["warning"], "opaque tunnel") {
		t.Fatalf("approval context: %v", ctx)
	}
	attempt, outcome := tunnelReceipts(t, chainFile, echo)
	if attempt.ReceiptID == "" || attempt.Decision != gwAllow || attempt.Outcome != "sent" {
		t.Fatalf("attempt receipt: %+v", attempt)
	}
	if outcome.AttemptID != attempt.ReceiptID || outcome.Decision != gwAllow || outcome.Status != 200 {
		t.Fatalf("outcome receipt: %+v", outcome)
	}
	if outcome.ReqBytes != int64(len("hello over tcp")) || outcome.RespBytes != int64(len("hello over tcp")) {
		t.Fatalf("bytes each way: req %d resp %d", outcome.ReqBytes, outcome.RespBytes)
	}
	if accepts.Load() != 1 {
		t.Fatalf("destination accepted %d connections, want 1", accepts.Load())
	}
}

func TestTCPGate_DeniedTunnelNeverDials(t *testing.T) {
	_, ag, chainFile, proxyAddr := tcpGateServer(t, "deny")
	echo, accepts := echoServer(t)
	c, _, status, raw := connectThrough(t, proxyAddr, echo, nil)
	defer c.Close()
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("CONNECT to a denied destination: %s", status)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if body["error"] != "action denied" {
		t.Fatalf("refusal body: %v (%s)", body, raw)
	}
	time.Sleep(50 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatalf("a denied tunnel reached the destination")
	}
	if len(ag.of(actionTCPConnect)) != 1 {
		t.Fatalf("decision asked %d times", len(ag.of(actionTCPConnect)))
	}
	r := lastReceiptOf(t, chainFile)
	if r.Method != http.MethodConnect || r.URL != tunnelReceiptBase+echo || r.Decision != gwDeny || r.Status != 403 || r.Phase != "" {
		t.Fatalf("deny receipt: %+v", r)
	}
}

func TestTCPGate_HeldTunnelOpensOnlyAfterApproval(t *testing.T) {
	_, ag, chainFile, proxyAddr := tcpGateServer(t, "escalate")
	echo, accepts := echoServer(t)
	go func() {
		time.Sleep(200 * time.Millisecond)
		if accepts.Load() != 0 {
			t.Errorf("destination reached BEFORE approval")
		}
		ag.status.Store("approved")
	}()
	c, br, status, _ := connectThrough(t, proxyAddr, echo, nil)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("approved CONNECT: %s", status)
	}
	roundTrip(t, c, br, "after approval")
	c.Close()
	if ag.creates.Load() != 1 {
		t.Fatalf("%d approvals opened, want 1", ag.creates.Load())
	}
	attempt, outcome := tunnelReceipts(t, chainFile, echo)
	if attempt.ApprovalID != firstApproval || attempt.Decision != gwAllow || outcome.ApprovalID != firstApproval {
		t.Fatalf("receipts do not name the approval: %+v / %+v", attempt, outcome)
	}
}

func TestTCPGate_PersonsDenialNeverDials(t *testing.T) {
	_, ag, chainFile, proxyAddr := tcpGateServer(t, "escalate")
	ag.status.Store("denied")
	echo, accepts := echoServer(t)
	c, _, status, _ := connectThrough(t, proxyAddr, echo, nil)
	defer c.Close()
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("CONNECT a person denied: %s", status)
	}
	if accepts.Load() != 0 {
		t.Fatalf("a denied tunnel reached the destination")
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || r.ApprovalID != firstApproval {
		t.Fatalf("deny receipt: %+v", r)
	}
}

func TestTCPGate_UnansweredHoldGetsTheRetryAnswer(t *testing.T) {
	srv, _, chainFile, proxyAddr := tcpGateServer(t, "escalate")
	srv.SetEscalateWindow(150*time.Millisecond, 10*time.Millisecond)
	srv.SetEscalateAnswer(true)
	echo, accepts := echoServer(t)
	c, _, status, raw := connectThrough(t, proxyAddr, echo, nil)
	defer c.Close()
	if !strings.HasPrefix(status, "503") {
		t.Fatalf("an unanswered hold: %s, want 503", status)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if body["error"] != "held for approval" || body["approval_id"] != firstApproval {
		t.Fatalf("held answer: %v", body)
	}
	if accepts.Load() != 0 {
		t.Fatalf("a held tunnel reached the destination")
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwEscalate || r.Status != 503 {
		t.Fatalf("held receipt: %+v", r)
	}
}

func TestTCPGate_OverBudgetIsCut(t *testing.T) {
	srv, ag, chainFile, proxyAddr := tcpGateServer(t, "allow")
	srv.SetEgressBudget(true, 1000, 1024)
	ag.setDecision(actionEgressBudget, "deny")
	echo, _ := echoServer(t)
	c, br, status, _ := connectThrough(t, proxyAddr, echo, nil)
	defer c.Close()
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("CONNECT: %s", status)
	}
	// Drain what comes back so the echo never blocks, and push more than
	// one budget chunk through.
	go func() { _, _ = io.Copy(io.Discard, br) }()
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	var sent int64
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	for sent < 2<<20 {
		n, err := c.Write(chunk)
		sent += int64(n)
		if err != nil {
			break
		}
	}
	if sent >= 2<<20 {
		t.Fatalf("the tunnel took %d bytes without being cut", sent)
	}
	_, outcome := tunnelReceipts(t, chainFile, echo)
	if !containsString(outcome.Reasons, "egress_budget") {
		t.Fatalf("outcome reasons %v, want egress_budget", outcome.Reasons)
	}
	if len(ag.of(actionEgressBudget)) == 0 {
		t.Fatalf("the budget question was never asked")
	}
}

func TestTCPGate_StoppedAgentIsCut(t *testing.T) {
	srv, _, chainFile, proxyAddr := tcpGateServer(t, "allow")
	srv.SetAgents(map[string]string{agentAlpha: tokAlpha})
	echo, _ := echoServer(t)
	c, br, status, _ := connectThrough(t, proxyAddr, echo, asAgent(tokAlpha))
	defer c.Close()
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("CONNECT: %s", status)
	}
	roundTrip(t, c, br, "before the kill")
	srv.SetStoppedAgents([]string{agentAlpha})
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatalf("the tunnel stayed open after the agent was stopped")
	}
	_, outcome := tunnelReceipts(t, chainFile, echo)
	if !containsString(outcome.Reasons, "agent_stopped") || outcome.Agent != agentAlpha {
		t.Fatalf("outcome receipt: %+v", outcome)
	}
}

// fakeConnectProxy is an upstream CONNECT proxy: it records the targets it
// is asked for and relays to them.
func fakeConnectProxy(t *testing.T) (addr string, targets *[]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var seen []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				seen = append(seen, req.Host)
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), &seen
}

func TestTCPGate_ThroughUpstreamProxy(t *testing.T) {
	srv, _, chainFile, proxyAddr := tcpGateServer(t, "allow")
	upAddr, targets := fakeConnectProxy(t)
	if err := srv.SetUpstream("http://"+upAddr, nil); err != nil {
		t.Fatal(err)
	}
	echo, accepts := echoServer(t)
	c, br, status, _ := connectThrough(t, proxyAddr, echo, nil)
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("CONNECT via upstream: %s", status)
	}
	roundTrip(t, c, br, "through the corporate proxy")
	c.Close()
	if len(*targets) != 1 || (*targets)[0] != echo {
		t.Fatalf("upstream proxy saw %v, want CONNECT %s", *targets, echo)
	}
	if accepts.Load() != 1 {
		t.Fatalf("destination accepted %d, want 1", accepts.Load())
	}
	_, outcome := tunnelReceipts(t, chainFile, echo)
	if outcome.ReqBytes == 0 || outcome.RespBytes == 0 {
		t.Fatalf("bytes not counted through the upstream path: %+v", outcome)
	}
}

func TestTCPGate_OffKeepsTheRefusal(t *testing.T) {
	srv, ag, _, proxyAddr := tcpGateServer(t, "allow")
	srv.SetTCPGate(false)
	echo, accepts := echoServer(t)
	c, _, status, _ := connectThrough(t, proxyAddr, echo, nil)
	defer c.Close()
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("gate off: %s, want 403", status)
	}
	if len(ag.of(actionTCPConnect)) != 0 || accepts.Load() != 0 {
		t.Fatalf("gate off must neither ask nor dial")
	}
}

func TestTCPGate_PrivateLiteralRefusedWithoutAsking(t *testing.T) {
	srv, ag, chainFile, proxyAddr := tcpGateServer(t, "allow")
	srv.SetPublicEgressOnly(true)
	c, _, status, _ := connectThrough(t, proxyAddr, "10.0.0.5:5432", nil)
	defer c.Close()
	if !strings.HasPrefix(status, "403") {
		t.Fatalf("private literal: %s, want 403", status)
	}
	if len(ag.of(actionTCPConnect)) != 0 {
		t.Fatalf("a private literal must be refused before the gateway is asked")
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwDeny || !containsString(r.Reasons, "destination_not_allowed") {
		t.Fatalf("receipt: %+v", r)
	}
}

func TestTCPGate_ProtocolFromPort(t *testing.T) {
	for port, want := range map[string]string{"5432": "postgres (from the port)", "22": "ssh (from the port)", "4711": "unknown (port 4711)"} {
		if got := tcpProtocol(port); got != want {
			t.Errorf("tcpProtocol(%s) = %q, want %q", port, got, want)
		}
	}
	if got := tcpResource("db.internal", "5432"); got != "tcp:db.internal:5432" {
		t.Errorf("tcpResource = %q", got)
	}
	if got := tcpResource("::1", "6379"); got != "tcp:[::1]:6379" {
		t.Errorf("tcpResource v6 = %q", got)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
