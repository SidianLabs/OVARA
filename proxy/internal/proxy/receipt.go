package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"

	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

// What a receipt says about a request beyond method, URL and decision.
//
// A request that goes upstream gets two receipts: an "attempt", written and
// synced to disk before the first byte is sent (the request is refused if
// that write fails), and an "outcome" naming the attempt, written once the
// upstream has answered and before the answer reaches the agent. A request
// that never goes upstream gets one receipt with no phase.

// agentLabel identifies the client in receipts: a stable hash of the proxy
// credential it presented, never the credential itself.
func agentLabel(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return "pt_" + hex.EncodeToString(sum[:])[:16]
}

// receiptFacts gathers the request facts every receipt for one request
// shares. The zero value describes a request nothing is known about yet.
type receiptFacts struct {
	gw       *gateway.Decision // the URL decision, once the gateway answered
	reasons  []string          // proxy-side reasons when there is no decision
	agent    agentIdentity     // who sent the request
	hb       *heldBody
	approver string
	looked   bool // approver lookup done
}

// entry builds the receipt entry for the request in its current state.
func (s *Server) receiptEntry(f *receiptFacts, method, url, decision string, status int, approvalID string) receipts.Entry {
	e := receipts.Entry{
		Method:     method,
		URL:        url,
		Decision:   decision,
		Status:     status,
		ApprovalID: approvalID,
		Agent:      f.agentLabel(s),
		Approver:   f.approver,
	}
	if f.gw != nil {
		e.Rule = f.gw.MatchedRule
		e.PolicyHash = f.gw.ReceiptStub.PolicyHash
		e.Reasons = append(e.Reasons, f.gw.ReasonCodes...)
	}
	e.Reasons = append(e.Reasons, f.reasons...)
	if f.hb != nil {
		e.ReqBytes = f.hb.size
		e.BodySHA256 = f.hb.sha256Hex()
	}
	return e
}

// lookupApprover asks the gateway who approved approvalID, once. A failure
// leaves the field empty; the approval id in the receipt still names it.
func (s *Server) lookupApprover(ctx context.Context, f *receiptFacts, approvalID string) {
	if f.looked || approvalID == "" {
		return
	}
	f.looked = true
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	who, err := s.gw.ApprovalResolvedBy(ctx, approvalID)
	if err != nil {
		log.Printf("receipt: approver of %s: %v", approvalID, err)
		return
	}
	f.approver = who
}

// agentLabel is what the receipt says about the client: the agent's name,
// or for agent_token the hash of the token.
func (f *receiptFacts) agentLabel(s *Server) string {
	if f.agent.label != "" {
		return f.agent.label
	}
	return agentLabel(s.agentToken)
}
