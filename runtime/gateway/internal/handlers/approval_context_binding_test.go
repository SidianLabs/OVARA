package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
)

// Two requests whose context values differ only past the cut are two
// different approvals: what the person is shown, and what Open merges
// identical pending requests on, covers the whole values.
func TestApprovalContext_ValuesDifferingPastTheCutStayDifferent(t *testing.T) {
	pad := strings.Repeat("x", maxContextValueLen+50)
	ctxOf := func(to string) map[string]string {
		meta, _ := json.Marshal(map[string]any{"proxy_context": map[string]any{
			"tool":      "send_email",
			"arguments": `{"body":"` + pad + `","to":"` + to + `"}`,
		}})
		return approvalContextFromMetadata(meta)
	}
	a, b := ctxOf("boss@corp.examp"), ctxOf("evil@atk.exampl")
	if a["arguments"] == b["arguments"] {
		t.Fatalf("values differing past the cut look the same: %q", a["arguments"][maxContextValueLen-10:])
	}
	svc := approval.NewService(approval.NewInMemoryStore())
	open := func(id string, ctx map[string]string) *approval.ApprovalRequest {
		r, _, err := svc.Open(&approval.CreateRequest{DecisionID: id, ActionType: models.ActionType("mcp.tool_call"), Resource: "mcp:h/mcp/send_email", Environment: models.EnvironmentDev, AgentID: "a", Context: ctx})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if open("d1", a).ApprovalID == open("d2", b).ApprovalID {
		t.Fatal("two different tool calls were merged into one approval")
	}
}

// The hashes that bind an approval to its request survive the entry cap.
func TestApprovalContext_HashesSurviveTheCap(t *testing.T) {
	m := map[string]any{"arguments_sha256": "aa", "body_sha256": "bb"}
	for i := 0; i < 40; i++ {
		m[fmt.Sprintf("a%02d", i)] = "v"
	}
	meta, _ := json.Marshal(map[string]any{"proxy_context": m})
	got := approvalContextFromMetadata(meta)
	if got["arguments_sha256"] != "aa" || got["body_sha256"] != "bb" {
		t.Fatalf("a binding hash was dropped: %v", got)
	}
}
