package handlers

import (
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"
)

// Limits on what a request may place in front of a human approver. The
// context is display-only, so it is bounded hard: a request cannot use it to
// flood the approval screen or the journal.
const (
	maxContextEntries  = 16
	maxContextKeyLen   = 40
	maxContextValueLen = 600
	// The commit-back diff is what a person reads before changes reach the
	// real repository; it gets the same budget the proxy uses to build it.
	maxContextDiffLen = 64 << 10
	// Lists a person must see in full (what policy kept out, which
	// sensitive files changed, what a cut diff leaves out, the MCP tool
	// definitions being approved).
	maxContextListLen = 8 << 10
)

// contextListKeys get the larger list budget.
var contextListKeys = map[string]bool{"diff_not_shown": true, "kept_out": true, "sensitive": true, "files": true, "mcp_tools": true}

// contextPriorityKeys are always kept first when a request carries more
// entries than the cap: the proxy's own safety notes about the request
// body, which agent is asking, and the untrusted read that made a write a
// question.
var contextPriorityKeys = []string{"warning", "body_note", "body_sha256", "agent", "taint", "sensitive", "diff_not_shown", "kept_out", "tree"}

// approvalContextFromMetadata extracts {"proxy_context": {"k": "v", ...}} from
// the metadata of the request the gateway evaluated. Anything that is not a
// flat object of short strings is dropped. Over the entry cap, keys are
// taken in a fixed order (the priority keys, then the rest sorted), so what
// the approver sees never depends on map iteration order.
func approvalContextFromMetadata(meta json.RawMessage) map[string]string {
	if len(meta) == 0 {
		return nil
	}
	var outer struct {
		ProxyContext map[string]any `json:"proxy_context"`
	}
	if json.Unmarshal(meta, &outer) != nil || len(outer.ProxyContext) == 0 {
		return nil
	}
	keys := make([]string, 0, len(outer.ProxyContext))
	for k := range outer.ProxyContext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make([]string, 0, len(keys))
	for _, p := range contextPriorityKeys {
		if _, ok := outer.ProxyContext[p]; ok {
			ordered = append(ordered, p)
		}
	}
	for _, k := range keys {
		if !isPriorityKey(k) {
			ordered = append(ordered, k)
		}
	}

	out := make(map[string]string, maxContextEntries)
	for _, k := range ordered {
		if len(out) >= maxContextEntries {
			break
		}
		s, ok := outer.ProxyContext[k].(string)
		if !ok || k == "" {
			continue
		}
		limit := maxContextValueLen
		if k == "diff" {
			limit = maxContextDiffLen
		} else if contextListKeys[k] {
			limit = maxContextListLen
		}
		if len(k) > maxContextKeyLen {
			k = k[:maxContextKeyLen]
		}
		if _, dup := out[k]; dup {
			continue // two long keys cut to the same prefix: the first wins
		}
		out[k] = truncateContextValue(s, limit)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isPriorityKey(k string) bool {
	for _, p := range contextPriorityKeys {
		if k == p {
			return true
		}
	}
	return false
}

// truncateContextValue cuts s to at most limit bytes on a UTF-8 boundary
// and says how much was left out, so a cut is never mistaken for the whole
// value.
func truncateContextValue(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("… [truncated: %d more bytes not shown]", len(s)-cut)
}
