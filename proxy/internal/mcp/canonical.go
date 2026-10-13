package mcp

import (
	"context"

	"ovara.proxy/internal/canonjson"
)

// What the other side receives is exactly what was checked. A message is
// read strictly (canonjson), and the canonical encoding of what was read is
// relayed in place of the bytes that arrived: a server or client whose
// JSON reader differs from this package's (which duplicate key wins, how
// invalid UTF-8 or a lone surrogate is read, a second value after the
// first) then has nothing to read differently. Without this, every parser
// differential is a way past the gate.

// strictOptions is the strict reading of MCP traffic: member names that
// differ only in case count as duplicates (case-insensitive readers would
// see one member twice), and a leading byte order mark is dropped.
var strictOptions = canonjson.Options{FoldCase: true, AllowBOM: true}

// Canonical reads data strictly as MCP traffic is read and returns its
// canonical encoding (one line). See canonjson for the errors.
func Canonical(data []byte) ([]byte, error) {
	return canonjson.Canonical(data, strictOptions)
}

// RefusedAmbiguous is the verdict on a message that can be read in more
// than one way.
func RefusedAmbiguous() Verdict {
	return Refused("the message can be read in more than one way (duplicate or case-variant keys, or invalid UTF-8)", "mcp_message_ambiguous")
}

// CheckServerBody is ServerBody over the canonical form of data. It
// returns the verdict and what is relayed when the verdict allows: the
// canonical bytes, or nil when data is not JSON at all (then data itself,
// which no JSON reader takes for a message, is relayed as it came). A body
// that is JSON to a lenient reader but ambiguous (duplicate or case-variant
// keys, invalid UTF-8) is refused when it could be JSON-RPC, and always
// when mcpContext says the channel carries MCP.
func (g *Gate) CheckServerBody(ctx context.Context, server string, data []byte, mcpContext bool) (ServerResult, []byte) {
	canon, err := Canonical(data)
	if err == nil {
		return g.ServerBody(ctx, server, canon), canon
	}
	res := g.ServerBody(ctx, server, data)
	if canonjson.Ambiguous(err) && res.Verdict.Allowed() && (mcpContext || res.IsMCP || LooksLikeJSONRPC(data)) {
		res.IsMCP = true
		res.HasTools = true
		res.Verdict = RefusedAmbiguous()
	}
	return res, nil
}
