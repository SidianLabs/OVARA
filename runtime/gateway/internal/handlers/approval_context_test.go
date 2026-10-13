package handlers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
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
		"query":                  "a=1&b=2",
		"body_bytes":             "42",
		"not_string":             7,                        // dropped: only strings are shown
		"nested":                 map[string]any{"x": "y"}, // dropped
		"long":                   long,                     // truncated
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
	want := strings.Repeat("A", maxContextValueLen) + "… [truncated: 4400 more bytes not shown]"
	if got["long"] != want {
		t.Errorf("long value: got %d bytes ending %q", len(got["long"]), got["long"][len(got["long"])-45:])
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
	if n := len(approvalContextFromMetadata(meta)); n != maxContextEntries {
		t.Fatalf("%d entries; the cap is %d", n, maxContextEntries)
	}
}

// The commit-back diff is what a person reads before letting changes into
// the real repository: it gets a much larger budget than other values,
// and a cut is always labelled.
func TestApprovalContext_DiffKeepsItsLength(t *testing.T) {
	diff := strings.Repeat("+ line of a diff\n", 3000) // 51000 bytes
	meta, _ := json.Marshal(map[string]any{"proxy_context": map[string]any{"diff": diff, "files": strings.Repeat("f", maxContextListLen+100), "branch": strings.Repeat("b", 700)}})
	got := approvalContextFromMetadata(meta)
	if got["diff"] != diff {
		t.Fatalf("a %d-byte diff was cut to %d bytes", len(diff), len(got["diff"]))
	}
	// File lists get the list budget; other values the ordinary one.
	if !strings.HasSuffix(got["files"], "… [truncated: 100 more bytes not shown]") {
		t.Errorf("files: %q", got["files"][maxContextListLen-5:])
	}
	if !strings.HasSuffix(got["branch"], "… [truncated: 100 more bytes not shown]") {
		t.Errorf("branch: %q", got["branch"][maxContextValueLen-5:])
	}

	big := strings.Repeat("x", maxContextDiffLen+1234)
	meta, _ = json.Marshal(map[string]any{"proxy_context": map[string]any{"diff": big}})
	got = approvalContextFromMetadata(meta)
	if want := big[:maxContextDiffLen] + "… [truncated: 1234 more bytes not shown]"; got["diff"] != want {
		t.Fatalf("big diff: %d bytes, suffix %q", len(got["diff"]), got["diff"][len(got["diff"])-45:])
	}
}

// A cut never splits a UTF-8 sequence.
func TestApprovalContext_CutsOnRuneBoundary(t *testing.T) {
	v := strings.Repeat("a", maxContextValueLen-1) + strings.Repeat("é", 10) // é is 2 bytes
	meta, _ := json.Marshal(map[string]any{"proxy_context": map[string]any{"note": v}})
	got := approvalContextFromMetadata(meta)["note"]
	if !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8 after cut: %q", got[maxContextValueLen-4:])
	}
	if want := strings.Repeat("a", maxContextValueLen-1) + "… [truncated: 20 more bytes not shown]"; got != want {
		t.Fatalf("got %q", got[maxContextValueLen-4:])
	}
}

// Over the entry cap, which keys survive must not depend on map order,
// and the safety notes the proxy adds are always kept.
func TestApprovalContext_KeySelectionIsDeterministic(t *testing.T) {
	m := map[string]any{"warning": "w", "body_note": "n", "body_sha256": "s", "zz_last": "z"}
	for i := 0; i < 40; i++ {
		m[fmt.Sprintf("k%02d", i)] = "v"
	}
	meta, _ := json.Marshal(map[string]any{"proxy_context": m})
	first := approvalContextFromMetadata(meta)
	if len(first) != maxContextEntries {
		t.Fatalf("%d entries", len(first))
	}
	for _, k := range []string{"warning", "body_note", "body_sha256"} {
		if _, ok := first[k]; !ok {
			t.Errorf("%s was dropped", k)
		}
	}
	for i := 0; i < maxContextEntries-3; i++ {
		if _, ok := first[fmt.Sprintf("k%02d", i)]; !ok {
			t.Errorf("k%02d missing: keys are not taken in sorted order", i)
		}
	}
	for i := 0; i < 50; i++ {
		if again := approvalContextFromMetadata(meta); !reflect.DeepEqual(again, first) {
			t.Fatalf("selection changed between calls: %v vs %v", again, first)
		}
	}
}
