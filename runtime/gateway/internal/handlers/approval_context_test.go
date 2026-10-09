package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApprovalContext_ExtractsOnlyBoundedStrings(t *testing.T) {
	if got := approvalContextFromMetadata(nil); got != nil {
		t.Fatalf("no metadata -> nil, got %v", got)
	}
	if got := approvalContextFromMetadata(json.RawMessage(`{"other":1}`)); got != nil {
		t.Fatalf("metadata without proxy_context -> nil, got %v", got)
	}
	if got := approvalContextFromMetadata(json.RawMessage(`not json`)); got != nil {
		t.Fatalf("garbage -> nil, got %v", got)
	}

	long := strings.Repeat("A", 5000)
	meta, _ := json.Marshal(map[string]any{"proxy_context": map[string]any{
		"query":      "a=1&b=2",
		"body_bytes": "42",
		"not_string": 7,           // dropped: only strings are shown
		"nested":     map[string]any{"x": "y"}, // dropped
		"long":       long,        // truncated
		strings.Repeat("k", 200): "long key",
	}})
	got := approvalContextFromMetadata(meta)
	if got["query"] != "a=1&b=2" || got["body_bytes"] != "42" {
		t.Fatalf("expected values missing: %v", got)
	}
	if _, ok := got["not_string"]; ok {
		t.Error("a non-string value reached the approver")
	}
	if _, ok := got["nested"]; ok {
		t.Error("a nested value reached the approver")
	}
	if len(got["long"]) > maxContextValueLen+4 {
		t.Errorf("value not truncated: %d bytes", len(got["long"]))
	}
	for k := range got {
		if len(k) > maxContextKeyLen {
			t.Errorf("key not truncated: %d bytes", len(k))
		}
	}
}

func TestApprovalContext_CapsTheNumberOfEntries(t *testing.T) {
	m := map[string]any{}
	for i := 0; i < 100; i++ {
		m[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
	}
	meta, _ := json.Marshal(map[string]any{"proxy_context": m})
	if n := len(approvalContextFromMetadata(meta)); n > maxContextEntries {
		t.Fatalf("%d entries; the cap is %d", n, maxContextEntries)
	}
}
