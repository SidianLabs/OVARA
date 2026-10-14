package main

// `ovara mcp wrap`: the MCP gate for a server that speaks over stdio. The
// proxy sees MCP only when it travels over HTTP; a stdio server is a child
// process of the agent's MCP client and never touches the network path.
// Wrapping it puts Ovara between the two: the client starts
// `ovara mcp wrap -dir D -name NAME -- <server command>` instead of the
// server, and every message passes through here, one JSON-RPC message per
// line. Tool lists the server sends are checked against their pins and
// tool calls the client sends are decided by the gateway, exactly as the
// proxy does for HTTP (proxy/internal/mcp).
//
// It means something only when it runs as a user the agent cannot act as:
// an agent that can edit the pin file, read the gateway token or start the
// server without the wrapper has nothing in its way.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"ovara.proxy/internal/canonjson"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/mcp"
	"ovara.proxy/internal/proxy"
)

func cmdMCP(args []string) error {
	if len(args) == 0 || args[0] != "wrap" {
		fmt.Fprintln(os.Stderr, `usage: ovara mcp wrap -dir D -name NAME -- <server command> [args...]

  Runs an MCP server that speaks over stdio, with Ovara in between: tool
  definitions are pinned (new or changed ones pause for a person) and every
  tool call is decided by policy (action types mcp.tools and mcp.tool_call,
  resources "mcp:stdio:NAME ..." and "mcp:stdio:NAME/<tool>").

  Point the agent's MCP configuration at this command instead of the server,
  and run it as a user the agent cannot act as.`)
		return errors.New("usage: ovara mcp wrap -dir D -name NAME -- <server command>")
	}
	return cmdMCPWrap(args[1:], os.Stdin, os.Stdout)
}

var serverNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func cmdMCPWrap(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("mcp wrap", flag.ContinueOnError)
	dir := fs.String("dir", ".", "deployment directory from ovara init")
	name := fs.String("name", "", "a name for the server: its pins and policy resources are mcp:stdio:NAME")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if !serverNameRE.MatchString(*name) {
		return errors.New("-name is required: letters, digits, '_', '-' and '.' (up to 64)")
	}
	if len(argv) == 0 {
		return errors.New("no server command: ovara mcp wrap -dir D -name NAME -- <server command> [args...]")
	}
	cfg, err := config.Load(filepath.Join(*dir, "proxy.json"))
	if err != nil {
		return fmt.Errorf("proxy.json: %w (run `ovara init` first)", err)
	}
	if b, err := os.ReadFile(filepath.Join(*dir, "policy.json")); err == nil && !strings.Contains(string(b), `"mcp.tool_call"`) {
		fmt.Fprintln(os.Stderr, `[ovara] warning: policy.json has no mcp.tools or mcp.tool_call rule; add {"action_type": "mcp.tools", "resource": "*", "escalate": true} and the same for mcp.tool_call (ovara init writes them)`)
	}
	pins := cfg.MCPPinsFile
	if !filepath.IsAbs(pins) {
		pins = filepath.Join(*dir, pins)
	}
	store, err := mcp.OpenStore(pins)
	if err != nil {
		return fmt.Errorf("mcp pins: %w", err)
	}
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	ask := &gatewayAsker{gw: gw, timeout: time.Duration(cfg.EscalateTimeoutSec) * time.Second, poll: time.Duration(cfg.EscalatePollSec) * time.Second}
	w := newWrapper(store, ask, "stdio:"+*name)

	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // the server command is what the person configured
	cmd.Stderr = os.Stderr
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", termSafe(argv[0]), err)
	}
	relayErr := w.relay(context.Background(), stdin, stdout, serverIn, serverOut)
	if relayErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if relayErr != nil {
		return relayErr
	}
	if waitErr != nil {
		return fmt.Errorf("mcp server: %w", waitErr)
	}
	return nil
}

// gatewayAsker asks the gateway and, on escalate, opens an approval and
// waits for its answer (the same calls the box's command gate makes).
type gatewayAsker struct {
	gw            *gateway.Client
	timeout, poll time.Duration
}

func (a *gatewayAsker) Ask(ctx context.Context, actionType, resource string, preview map[string]string) (string, string) {
	d, err := a.gw.CheckAction(ctx, actionType, resource, preview)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] gateway unreachable, refusing %s: %v\n", termSafe(resource), err)
		return mcp.OutcomeError, ""
	}
	switch d.Decision {
	case decisionAllow:
		return mcp.OutcomeAllow, ""
	case decisionEscalate:
	default:
		return mcp.OutcomeDeny, ""
	}
	id := d.ApprovalID
	if id == "" {
		if id, err = a.gw.CreateApprovalFor(ctx, d, actionType, resource); err != nil {
			fmt.Fprintf(os.Stderr, "[ovara] could not open an approval, refusing %s: %v\n", termSafe(resource), err)
			return mcp.OutcomeDeny, ""
		}
	}
	fmt.Fprintf(os.Stderr, "[ovara] %s paused for your approval (%s): %s\n", actionType, id, termSafe(resource))
	poll := a.poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.NewTimer(a.timeout)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return mcp.OutcomeAborted, id
		case <-deadline.C:
			if st, err := a.gw.ApprovalStatus(ctx, id); err == nil && st != "pending" {
				return approvalOutcome(settleApproval(ctx, a.gw, id, st)), id
			}
			return mcp.OutcomeTimeout, id
		case <-tick.C:
			st, err := a.gw.ApprovalStatus(ctx, id)
			if err != nil || st == "pending" {
				continue
			}
			return approvalOutcome(settleApproval(ctx, a.gw, id, st)), id
		}
	}
}

func approvalOutcome(status string) string {
	if status == approvalApprovedStatus {
		return mcp.OutcomeApproved
	}
	return mcp.OutcomeDeny
}

const approvalApprovedStatus = "approved"

// maxPendingCalls bounds the tool calls waiting for an answer at once.
const maxPendingCalls = 64

// wrapper relays one stdio MCP session.
type wrapper struct {
	gate   *mcp.Gate
	server string

	outMu sync.Mutex // the client's stdin: one whole line at a time
	inMu  sync.Mutex // the server's stdin
	slots chan struct{}
}

func newWrapper(store *mcp.Store, ask mcp.Asker, server string) *wrapper {
	g := mcp.NewGate(store, ask, proxy.RedactPreviewCount)
	g.Logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[ovara] "+format+"\n", args...) }
	return &wrapper{gate: g, server: server, slots: make(chan struct{}, maxPendingCalls)}
}

func writeLine(mu *sync.Mutex, w io.Writer, line []byte) error {
	mu.Lock()
	defer mu.Unlock()
	if _, err := w.Write(line); err != nil {
		return err
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		_, err := w.Write([]byte{'\n'})
		return err
	}
	return nil
}

// errLineTooLong: a message too long to check.
var errLineTooLong = errors.New("message longer than the bound Ovara checks")

// readLine returns the next line (with its newline, if any), at most max
// bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max {
			return nil, errLineTooLong
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

// relay runs the session until the server's output ends. Lines from the
// client go to the server once their tool calls are decided; lines from
// the server go to the client once their tool lists are checked.
func (w *wrapper) relay(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var calls sync.WaitGroup
	clientDone := make(chan error, 1)
	go func() {
		err := w.fromClient(ctx, bufio.NewReaderSize(clientIn, 64<<10), clientOut, serverIn, &calls)
		calls.Wait() // decided calls still go out before the server's input closes
		_ = serverIn.Close()
		clientDone <- err
	}()
	err := w.fromServer(ctx, bufio.NewReaderSize(serverOut, 64<<10), clientOut)
	cancel()
	if err != nil {
		return err
	}
	select {
	case cerr := <-clientDone:
		return cerr
	default:
		return nil // the server ended first; the client side ends with it
	}
}

func (w *wrapper) fromServer(ctx context.Context, r *bufio.Reader, clientOut io.Writer) error {
	for {
		line, err := readLine(r, mcp.MaxMessageBytes)
		if errors.Is(err, errLineTooLong) {
			fmt.Fprintf(os.Stderr, "[ovara] %s sent a message over %d bytes; it cannot be checked, stopping\n", w.server, mcp.MaxMessageBytes)
			return fmt.Errorf("mcp server %s: %w", w.server, err)
		}
		if len(line) > 0 {
			out := line
			// Every line goes through the check: one that does not start
			// like JSON may still read as JSON-RPC to a lenient client.
			// What the client reads is what was checked: the canonical
			// encoding of the line (mcp.CheckServerBody). A line readers
			// could disagree on is refused.
			if t := bytes.TrimSpace(line); len(t) > 0 {
				res, canonical := w.gate.CheckServerBody(ctx, w.server, t, true)
				switch {
				case res.Verdict.Outcome == mcp.OutcomeAborted:
					return nil
				case !res.Verdict.Allowed():
					out = mcp.Refusal(res.IDs, res.Batch, res.Verdict, w.server)
				case canonical != nil:
					out = canonical
				}
			}
			if werr := writeLine(&w.outMu, clientOut, out); werr != nil {
				return nil // the client is gone
			}
		}
		if err != nil {
			return nil // io.EOF: the server ended
		}
	}
}

func (w *wrapper) fromClient(ctx context.Context, r *bufio.Reader, clientOut io.Writer, serverIn io.Writer, calls *sync.WaitGroup) error { //nolint:unparam // the error result mirrors fromServer; both run under one errgroup-style wait
	for {
		line, err := readLine(r, mcp.MaxMessageBytes)
		if errors.Is(err, errLineTooLong) {
			fmt.Fprintf(os.Stderr, "[ovara] the client sent a message over %d bytes; it cannot be checked and was not passed on\n", mcp.MaxMessageBytes)
			_ = writeLine(&w.outMu, clientOut, mcp.ErrorResponse(nil, "message too large to check", nil))
			// skip the rest of that line
			for {
				_, err := r.ReadSlice('\n')
				if err != bufio.ErrBufferFull {
					break
				}
			}
			continue
		}
		if len(line) > 0 {
			w.fromClientLine(ctx, line, clientOut, serverIn, calls)
		}
		if err != nil {
			return nil
		}
	}
}

func (w *wrapper) fromClientLine(ctx context.Context, line []byte, clientOut, serverIn io.Writer, calls *sync.WaitGroup) {
	if len(bytes.TrimSpace(line)) == 0 {
		_ = writeLine(&w.inMu, serverIn, line)
		return
	}
	// The server gets the canonical encoding of the line, which is what is
	// checked below; never the client's bytes, which a server's JSON reader
	// could read differently (see mcp.Canonical).
	canonical, cerr := mcp.Canonical(bytes.TrimSpace(line))
	if canonjson.Ambiguous(cerr) {
		// JSON to a lenient reader, but readers disagree on it: which of
		// two members named alike wins, what invalid UTF-8 reads as.
		fmt.Fprintf(os.Stderr, "[ovara] the client sent a line that can be read in more than one way; it was not passed on\n")
		v := mcp.RefusedAmbiguous()
		out := mcp.ErrorResponse(nil, v.Detail, v.ErrorData(w.server))
		if body, err := mcp.Parse(line); err == nil {
			out = refuseClientBody(body, nil, v, w.server)
		}
		if out != nil {
			_ = writeLine(&w.outMu, clientOut, out)
		}
		return
	}
	if cerr != nil {
		// A line Ovara cannot read strictly is never passed on: a lenient
		// server (NaN, UTF-16, a second value) could still read a tool call
		// in it that nobody decided.
		fmt.Fprintf(os.Stderr, "[ovara] the client sent a line that is not valid JSON; it was not passed on\n")
		_ = writeLine(&w.outMu, clientOut, mcp.ParseErrorResponse(w.server))
		return
	}
	line = canonical
	body, err := mcp.Parse(line)
	hasCall := false
	if err == nil {
		for _, m := range body.Messages {
			if m.IsToolCall() {
				hasCall = true
			}
		}
	}
	if !hasCall {
		_ = writeLine(&w.inMu, serverIn, line)
		return
	}
	select {
	case w.slots <- struct{}{}:
	default:
		v := mcp.Refused("too many tool calls waiting for an answer", "mcp_too_many_pending")
		if out := refuseClientBody(body, nil, v, w.server); out != nil {
			_ = writeLine(&w.outMu, clientOut, out)
		}
		return
	}
	calls.Add(1)
	// Decided on its own: a call waiting for a person does not hold up the
	// rest of the session.
	go func() {
		defer calls.Done()
		defer func() { <-w.slots }()
		checks := w.gate.ClientBody(ctx, w.server, body)
		refused := map[int]mcp.Verdict{}
		var first *mcp.Verdict
		for i := range checks {
			c := checks[i]
			if c.Verdict.Outcome == mcp.OutcomeAborted {
				return
			}
			if !c.Verdict.Allowed() {
				refused[c.Index] = c.Verdict
				if first == nil {
					first = &c.Verdict
				}
			}
		}
		if first == nil {
			_ = writeLine(&w.inMu, serverIn, line)
			return
		}
		if out := refuseClientBody(body, refused, *first, w.server); out != nil {
			_ = writeLine(&w.outMu, clientOut, out)
		}
	}()
}

// refuseClientBody answers every request in a refused client body with an
// error: the refused calls with their own reason, the rest because they
// came in the same batch.
func refuseClientBody(body *mcp.Body, refused map[int]mcp.Verdict, def mcp.Verdict, server string) []byte {
	notSent := mcp.Verdict{Outcome: mcp.OutcomeDeny, Reasons: []string{"mcp_batch_refused"}, Detail: "not sent: another call in the same batch was refused"}
	parts := make([][]byte, 0, len(body.Messages))
	for i, m := range body.Messages {
		if m.ID == nil || m.Method == "" {
			continue
		}
		v, ok := refused[i]
		if !ok {
			v = notSent
			if refused == nil {
				v = def
			}
		}
		parts = append(parts, mcp.ErrorResponse(m.ID, v.Detail, v.ErrorData(server)))
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 && !body.Batch {
		return parts[0]
	}
	return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
}
