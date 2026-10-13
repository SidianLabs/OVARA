package proxy

import "net/http"

// What the upstream receives is exactly what was checked.
//
// The model gate and the MCP gate decide on what a body means. If they
// decided on their own reading and then forwarded the agent's bytes, the
// upstream would read those bytes with a different parser, and any
// disagreement between the two (which of two duplicate keys wins, whether
// NaN is a number, what follows the first value, how invalid UTF-8 or a
// lone surrogate reads, a case-insensitive member lookup) would let the
// upstream act on something the gate never saw. So a body a gate reads as
// JSON is read strictly (canonjson: UTF-8, one value, no NaN, no duplicate
// member names, numbers as written) and replaced, before anyone is asked
// about the request, by the canonical encoding of the value read. That
// encoding is what the approval context's body_sha256, the receipts and
// the upstream all get. A body that cannot be read strictly is refused or
// asked about as before; it is never forwarded on the strength of a check
// that read it differently.

// bodyRead is what was read of a request body before anything was decided.
type bodyRead struct {
	// modelWhy is the model gate's finding, "" for none.
	modelWhy string
	// mcp is what the MCP gate read, nil when the body is not MCP.
	mcp *mcpPrep
}

// readBody reads the held body of r as the gates will, and replaces it
// with its canonical form where a gate reads it as JSON. It runs before
// the request is put to policy, so that the hash in the approval context
// is the hash of the bytes that will be sent.
func (s *Server) readBody(r *http.Request, hb *heldBody) *bodyRead {
	br := &bodyRead{}
	why, canonical := s.modelRequestRefusal(r, hb)
	br.modelWhy = why
	if canonical != nil {
		hb.replace(r, canonical)
	}
	br.mcp = s.mcpPrepare(r, hb)
	return br
}
