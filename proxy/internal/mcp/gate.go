package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"ovara.proxy/internal/textsafe"
)

// Action types asked of the gateway.
const (
	// ActionTools is asked when a server lists tools that are not pinned
	// or whose definition changed. Resource "mcp:<server> tools <n> new"
	// (plus " <m> changed").
	ActionTools = "mcp.tools"
	// ActionToolCall is asked for every call of a pinned tool. Resource
	// "mcp:<server>/<tool>".
	ActionToolCall = "mcp.tool_call"
)

// Outcomes of a question (the proxy's askAction uses the same words).
const (
	OutcomeAllow    = "allow"    // policy allowed it
	OutcomeApproved = "approved" // a person approved it
	OutcomeDeny     = "deny"
	OutcomeTimeout  = "timeout"
	OutcomeAborted  = "aborted" // the client went away while waiting
	OutcomeError    = "error"   // the gateway could not be asked
)

// Asker puts one question to the gateway and, when policy says escalate,
// waits for a person. It returns one of the Outcome values and the approval
// id if a person was asked.
type Asker interface {
	Ask(ctx context.Context, actionType, resource string, preview map[string]string) (outcome, approvalID string)
}

// AskFunc adapts a function to Asker.
type AskFunc func(ctx context.Context, actionType, resource string, preview map[string]string) (string, string)

// Ask calls f.
func (f AskFunc) Ask(ctx context.Context, actionType, resource string, preview map[string]string) (string, string) {
	return f(ctx, actionType, resource, preview)
}

// Verdict is the answer about one tool list or one tool call.
type Verdict struct {
	Outcome    string
	ApprovalID string
	Reasons    []string
	// Detail says in words why a refusal happened.
	Detail string
}

// Allowed reports whether the message may go on.
func (v Verdict) Allowed() bool { return v.Outcome == OutcomeAllow || v.Outcome == OutcomeApproved }

// Gate pins tool definitions and decides tool calls.
type Gate struct {
	Store *Store
	Ask   Asker
	// Redact masks credential-shaped values in an argument preview and
	// counts them. Nil shows arguments as they are.
	Redact func(string) (string, int)
	// Logf, if set, receives one line per question and refusal.
	Logf func(format string, args ...any)

	mu      sync.Mutex
	pending map[string]*pendingList
}

type pendingList struct {
	done chan struct{}
	v    Verdict
}

// NewGate returns a gate over store that asks through ask.
func NewGate(store *Store, ask Asker, redact func(string) (string, int)) *Gate {
	return &Gate{Store: store, Ask: ask, Redact: redact, pending: map[string]*pendingList{}}
}

func (g *Gate) logf(format string, args ...any) {
	if g.Logf != nil {
		g.Logf(format, args...)
	}
}

// Refused is a verdict that refuses without asking anyone.
func Refused(detail string, reasons ...string) Verdict {
	return Verdict{Outcome: OutcomeDeny, Reasons: reasons, Detail: detail}
}

// ToolList decides a tool list from server: tools whose definitions are
// pinned pass; new or changed ones are put to the gateway (ActionTools) with
// the definitions, what changed and any warnings in front of the person.
// An approval pins them; a refusal records the refused changes, so calls to
// those tools are refused until a definition is approved.
func (g *Gate) ToolList(ctx context.Context, server string, tools []Tool) Verdict {
	d := g.Store.Drift(server, tools)
	if len(d.Restored) > 0 {
		if err := g.Store.Restore(server, d.Restored); err != nil {
			g.logf("mcp: saving pins: %v", err)
		}
	}
	if d.Empty() {
		return Verdict{Outcome: OutcomeAllow}
	}
	key := server + "\x00" + driftKey(d)
	g.mu.Lock()
	if p, ok := g.pending[key]; ok {
		g.mu.Unlock()
		select {
		case <-p.done:
			return p.v
		case <-ctx.Done():
			return Verdict{Outcome: OutcomeAborted}
		}
	}
	p := &pendingList{done: make(chan struct{})}
	g.pending[key] = p
	g.mu.Unlock()

	p.v = g.askToolList(ctx, server, d)
	g.mu.Lock()
	delete(g.pending, key)
	g.mu.Unlock()
	close(p.done)
	return p.v
}

func driftKey(d Drift) string {
	parts := make([]string, 0, len(d.New)+len(d.Changed))
	for _, t := range d.New {
		parts = append(parts, t.Name+"="+t.Hash)
	}
	for _, c := range d.Changed {
		parts = append(parts, c.New.Name+"="+c.New.Hash)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (g *Gate) askToolList(ctx context.Context, server string, d Drift) Verdict {
	resource := fmt.Sprintf("mcp:%s tools %d new", server, len(d.New))
	if len(d.Changed) > 0 {
		resource += fmt.Sprintf(" %d changed", len(d.Changed))
	}
	others := g.Store.OtherTools(server)
	lines := make([]string, 0, len(d.New)+len(d.Changed))
	var flags []string
	for _, t := range d.New {
		lines = append(lines, fmt.Sprintf("+ new tool %s (sha256 %s): %s", textsafe.Escape(t.Name), t.Hash[:12], describe(t.Description, 600)))
		flags = append(flags, Flags(t, others)...)
	}
	for _, c := range d.Changed {
		lines = append(lines, fmt.Sprintf("~ changed tool %s (sha256 %s → %s)", textsafe.Escape(c.New.Name), short(c.Old.SHA256), c.New.Hash[:12]))
		if c.Old.Description == cut(c.New.Description, maxPinnedDescription) {
			lines = append(lines, "    description unchanged; its input schema, title or annotations changed")
		} else {
			lines = append(lines, "    was: "+describe(c.Old.Description, 1500), "    now: "+describe(c.New.Description, 1500))
		}
		flags = append(flags, Flags(c.New, others)...)
	}
	for _, f := range flags {
		lines = append(lines, "⚠ "+f)
	}
	why := "the first time this server's tools are seen: the definitions below are what the model will read"
	switch {
	case len(d.Changed) > 0:
		why = "tool definitions changed since they were approved (a server can change what a tool says or does after it was trusted)"
	case !d.First:
		why = "the server lists tools that were not approved before"
	}
	preview := map[string]string{
		"mcp_server": server,
		"why":        why,
		"mcp_tools":  strings.Join(lines, "\n"),
	}
	if len(flags) > 0 {
		preview["warning"] = fmt.Sprintf("%d sign(s) of instructions aimed at the model: %s", len(flags), strings.Join(flags, "; "))
	}
	g.logf("mcp: %s: asking about %d new and %d changed tool definition(s)", server, len(d.New), len(d.Changed))
	outcome, id := g.Ask.Ask(ctx, ActionTools, resource, preview)
	v := Verdict{Outcome: outcome, ApprovalID: id}
	switch outcome {
	case OutcomeAllow, OutcomeApproved:
		var approved []Tool
		approved = append(approved, d.New...)
		for _, c := range d.Changed {
			approved = append(approved, c.New)
		}
		if err := g.Store.Approve(server, approved, id); err != nil {
			g.logf("mcp: saving pins: %v", err)
		}
		return v
	case OutcomeAborted:
		return v
	}
	// Anything but an answer of yes: the definitions do not reach the
	// agent, and the old pins of changed tools no longer stand for what
	// the server runs.
	if err := g.Store.Refuse(server, d.Changed); err != nil {
		g.logf("mcp: saving pins: %v", err)
	}
	v.Reasons = []string{"mcp_tools_not_approved"}
	v.Detail = "tool definitions not approved"
	switch outcome {
	case OutcomeTimeout:
		v.Reasons = append(v.Reasons, "approval_timeout")
		v.Detail += " (no answer in time)"
	case OutcomeError:
		v.Reasons = append(v.Reasons, "gateway_unreachable")
		v.Detail += " (gateway unreachable)"
	}
	g.logf("mcp: %s: tool definitions refused (%s)", server, outcome)
	return v
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// describe makes a description safe and short enough to show.
func describe(s string, n int) string {
	if s == "" {
		return "(no description)"
	}
	return textsafe.Escape(cut(s, n))
}

// maxArgsPreview bounds the arguments shown with a tool call.
const maxArgsPreview = 400

// ToolCall decides one call of tool name on server. A tool that is not
// pinned, or whose new definition was refused, is refused without asking;
// any other call is put to the gateway (ActionToolCall) with its arguments
// and their hash (arguments_sha256), so that an approval, and the
// gateway's merging of identical pending questions, stand for these exact
// arguments and never for another call that only starts the same way.
func (g *Gate) ToolCall(ctx context.Context, server, name string, args json.RawMessage) Verdict {
	return g.toolCall(ctx, server, name, args, "")
}

// toolCall is ToolCall for a call that came in a body whose hash is
// bodySHA ("" when there is none); the hash goes with the question too.
func (g *Gate) toolCall(ctx context.Context, server, name string, args json.RawMessage, bodySHA string) Verdict {
	pin, ok := g.Store.Lookup(server, name)
	if !ok {
		g.logf("mcp: %s: call of tool %s refused: not an approved tool of this server", server, textsafe.Escape(name))
		return Refused("tool "+name+" is not an approved tool of this server (its definition has not been seen and approved through Ovara)", "mcp_tool_not_approved")
	}
	if pin.Refused != "" {
		g.logf("mcp: %s: call of tool %s refused: its changed definition was refused", server, textsafe.Escape(name))
		return Refused("the definition of tool "+name+" changed and the change was refused", "mcp_tool_definition_refused")
	}
	preview := map[string]string{
		"mcp_server":  server,
		"tool":        textsafe.Escape(name),
		"tool_sha256": pin.SHA256,
		// What the approval stands for: the exact arguments, whatever part
		// of them the preview below can show.
		"arguments_sha256": ArgumentsSHA256(args),
	}
	if bodySHA != "" {
		preview["body_sha256"] = bodySHA
	}
	if len(args) > 0 && string(args) != "null" {
		a := string(args)
		masked := 0
		if g.Redact != nil {
			a, masked = g.Redact(a)
		}
		preview["arguments_bytes"] = strconv.Itoa(len(args))
		preview["arguments"] = textsafe.Escape(cut(a, maxArgsPreview))
		if masked > 0 {
			preview["warning"] = fmt.Sprintf("the arguments carry %d credential-shaped or encoded value(s), masked: data in this form may be leaving", masked)
		}
	}
	outcome, id := g.Ask.Ask(ctx, ActionToolCall, "mcp:"+server+"/"+EscapeName(name), preview)
	v := Verdict{Outcome: outcome, ApprovalID: id}
	switch outcome {
	case OutcomeAllow, OutcomeApproved, OutcomeAborted:
	case OutcomeTimeout:
		v.Reasons, v.Detail = []string{"approval_timeout"}, "the call of tool "+name+" was not approved in time"
	case OutcomeError:
		v.Reasons, v.Detail = []string{"gateway_unreachable"}, "the gateway could not be asked about tool "+name
	default:
		v.Outcome = OutcomeDeny
		v.Reasons, v.Detail = []string{"mcp_tool_call_denied"}, "the call of tool "+name+" was refused"
	}
	if !v.Allowed() && v.Outcome != OutcomeAborted {
		g.logf("mcp: %s: call of tool %s refused (%s)", server, textsafe.Escape(name), outcome)
	}
	return v
}

// ErrorData is the error data attached to a refusal sent back to the
// client.
func (v Verdict) ErrorData(server string) map[string]any {
	d := map[string]any{"reasons": v.Reasons, "mcp_server": server}
	if v.ApprovalID != "" {
		d["approval_id"] = v.ApprovalID
	}
	return d
}
