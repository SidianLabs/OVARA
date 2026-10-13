package mcp

import (
	"context"
	"encoding/json"
)

// CallCheck is the verdict on one message of a client body.
type CallCheck struct {
	Index   int // position in Body.Messages
	ID      json.RawMessage
	Tool    string
	Verdict Verdict
}

// ClientBody decides every tools/call in a body the client sends to server,
// in order. A body that can be read two ways is refused whole when it holds
// a tools/call. Messages that are not tool calls are not listed.
func (g *Gate) ClientBody(ctx context.Context, server string, b *Body) []CallCheck {
	out := make([]CallCheck, 0, len(b.Messages))
	for i, m := range b.Messages {
		if m.Method != "tools/call" {
			continue
		}
		c := CallCheck{Index: i, ID: m.ID}
		name, args, err := ToolCall(m.Params)
		switch {
		case b.Ambiguous || err == ErrAmbiguous:
			c.Verdict = Refused("the request can be read in more than one way (duplicate or case-variant keys, or invalid UTF-8)", "mcp_message_ambiguous")
		case err != nil:
			c.Verdict = Refused("a tools/call without a tool name", "mcp_message_malformed")
		default:
			c.Tool = name
			c.Verdict = g.ToolCall(ctx, server, name, args)
		}
		out = append(out, c)
		if c.Verdict.Outcome == OutcomeAborted {
			break
		}
	}
	return out
}

// ServerResult is the verdict on one body the server sends to the client.
type ServerResult struct {
	// HasTools is set when the body holds a tool list.
	HasTools bool
	Verdict  Verdict
	// IDs are the ids of the responses in the body, for the errors sent in
	// its place when it is refused.
	IDs []json.RawMessage
	// Batch is set when the body was a batch.
	Batch bool
	// IsMCP is set when the body is MCP traffic.
	IsMCP bool
}

// ServerBody checks a body (one message or a batch) a server sends to the
// client: every tool list in it goes through ToolList. A tool list that
// cannot be read, or can be read two ways, is refused. Bodies that are not
// JSON-RPC pass.
func (g *Gate) ServerBody(ctx context.Context, server string, data []byte) ServerResult {
	b, err := Parse(data)
	if err != nil {
		return ServerResult{Verdict: Verdict{Outcome: OutcomeAllow}}
	}
	res := ServerResult{Verdict: Verdict{Outcome: OutcomeAllow}, Batch: b.Batch, IsMCP: b.IsMCP()}
	var lists [][]Tool
	bad, reason := "", "mcp_tools_unreadable"
	for _, m := range b.Messages {
		if !m.IsResponse() {
			continue
		}
		res.IDs = append(res.IDs, m.ID)
		if m.Result == nil {
			continue
		}
		tools, isList, err := ToolList(m.Result)
		if !isList {
			continue
		}
		res.HasTools = true
		switch {
		case err == ErrAmbiguous:
			bad, reason = "the tool list can be read in more than one way (duplicate or case-variant keys)", "mcp_message_ambiguous"
		case err != nil:
			bad = "the tool list is malformed: " + err.Error()
		default:
			lists = append(lists, tools)
		}
	}
	if b.Ambiguous && res.IsMCP {
		res.HasTools = res.HasTools || len(res.IDs) > 0
		bad, reason = "the message can be read in more than one way (duplicate or case-variant keys, or invalid UTF-8)", "mcp_message_ambiguous"
	}
	if bad != "" {
		res.Verdict = Refused(bad, reason)
		return res
	}
	for _, tools := range lists {
		if v := g.ToolList(ctx, server, tools); !v.Allowed() {
			res.Verdict = v
			return res
		}
	}
	return res
}

// Refusal is the body sent in place of a refused one: one JSON-RPC error
// per id, as a batch when the original was one or there are several.
func Refusal(ids []json.RawMessage, batch bool, v Verdict, server string) []byte {
	if len(ids) == 0 {
		ids = []json.RawMessage{nil}
	}
	if len(ids) == 1 && !batch {
		return ErrorResponse(ids[0], v.Detail, v.ErrorData(server))
	}
	out := []byte{'['}
	for i, id := range ids {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, ErrorResponse(id, v.Detail, v.ErrorData(server))...)
	}
	return append(out, ']')
}
